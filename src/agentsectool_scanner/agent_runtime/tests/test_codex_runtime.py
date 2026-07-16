from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from openai_codex import CodexConfig

from agentsectool_scanner.agent_runtime.codex_runtime import build_codex_config, run_codex
from agentsectool_scanner.agent_runtime.config import Config
from agentsectool_scanner.agent_runtime.core import ApprovalDecision, ApprovalRequest
from agentsectool_scanner.agent_runtime.trace import TraceSink, read_trace


class FakeCodexClient:
    def __init__(
        self,
        config: CodexConfig,
        approval_handler: Callable[[str, dict[str, Any] | None], dict[str, Any]],
        *,
        invoke_approval: bool = True,
    ) -> None:
        self.config = config
        self.approval_handler = approval_handler
        self.invoke_approval = invoke_approval
        self.thread_params: dict[str, Any] | None = None
        self.resume_id: str | None = None
        self.turn_params: dict[str, Any] | None = None
        self.approval_result: dict[str, Any] | None = None
        self._index = 0
        self._notifications = [
            _notification(
                "item/started",
                {
                    "item": {
                        "id": "item-1",
                        "type": "commandExecution",
                        "command": "printf hello",
                        "cwd": "/workspace",
                        "status": "inProgress",
                    }
                },
            ),
            _notification(
                "item/completed",
                {
                    "item": {
                        "id": "item-1",
                        "type": "commandExecution",
                        "command": "printf hello",
                        "cwd": "/workspace",
                        "status": "completed",
                        "exitCode": 0,
                        "aggregatedOutput": "hello",
                    }
                },
            ),
            _notification("item/agentMessage/delta", {"delta": "done"}),
            _notification(
                "turn/completed",
                {"turn": {"id": "turn-1", "status": "completed", "items": []}},
            ),
        ]

    def __enter__(self) -> "FakeCodexClient":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        return None

    def initialize(self) -> dict[str, str]:
        return {"userAgent": "codex-cli/0.137.0"}

    def thread_start(self, params: dict[str, Any] | None = None) -> object:
        self.thread_params = params
        return SimpleNamespace(thread=SimpleNamespace(id="thread-1"))

    def thread_resume(self, thread_id: str, params: dict[str, Any] | None = None) -> object:
        self.resume_id = thread_id
        self.thread_params = params
        return SimpleNamespace(thread=SimpleNamespace(id=thread_id))

    def turn_start(
        self,
        thread_id: str,
        input_items: str,
        params: dict[str, Any] | None = None,
    ) -> object:
        assert thread_id
        assert input_items == "inspect target"
        self.turn_params = params
        return SimpleNamespace(turn=SimpleNamespace(id="turn-1"))

    def next_turn_notification(self, turn_id: str) -> object:
        notification = self._notifications[self._index]
        self._index += 1
        if self._index == 2 and self.invoke_approval:
            self.approval_result = self.approval_handler(
                "item/commandExecution/requestApproval",
                {
                    "threadId": "thread-1",
                    "turnId": turn_id,
                    "itemId": "item-1",
                    "command": "printf hello",
                    "cwd": "/workspace",
                    "reason": "run validation",
                },
            )
        return notification

    def unregister_turn_notifications(self, turn_id: str) -> None:
        assert turn_id == "turn-1"


def _notification(method: str, payload: dict[str, Any]) -> object:
    return SimpleNamespace(method=method, payload=payload)


def _config(tmp_path: Path) -> Config:
    return Config(
        active_model="openai",
        models={
            "openai": {
                "provider": "openai",
                "model": "gpt-test",
                "base_url": "https://api.example.test/v1",
                "api_key": "test-key",
            }
        },
        run_id="run-1",
        trace_dir=str(tmp_path),
        workspace=str(tmp_path),
        trace={"capture_llm_io": False},
    )


def test_codex_runtime_maps_native_tool_and_thread_events(tmp_path: Path) -> None:
    config = _config(tmp_path)
    sink = TraceSink(run_id="run-1", task_id="task", trace_dir=tmp_path)
    holder: dict[str, FakeCodexClient] = {}

    def factory(config: CodexConfig, handler: Callable[..., dict[str, Any]]) -> FakeCodexClient:
        client = FakeCodexClient(config, handler)
        holder["client"] = client
        return client

    result = run_codex(config, "inspect target", sink=sink, client_factory=factory)

    events = read_trace(run_id="run-1", trace_dir=tmp_path)
    assert result.outcome == "ok"
    assert result.steps == 1
    assert holder["client"].approval_result == {"decision": "decline"}
    assert holder["client"].thread_params["approvalPolicy"] == "on-request"
    assert holder["client"].thread_params["sandbox"] == "workspace-write"
    assert any(event.type == "runtime_metadata" for event in events)
    assert any(event.type == "tool_call_start" for event in events)
    assert any(event.type == "approval_event" for event in events)
    assert any(event.type == "tool_result" for event in events)
    exit_event = next(event for event in events if event.type == "run_exit")
    assert exit_event.payload["thread_id"] == "thread-1"
    assert exit_event.payload["turn_id"] == "turn-1"
    assert exit_event.payload["text"] == "done"


def test_codex_runtime_resumes_thread_and_uses_user_approval(tmp_path: Path) -> None:
    config = _config(tmp_path)
    sink = TraceSink(run_id="run-1", task_id="task", trace_dir=tmp_path)
    holder: dict[str, FakeCodexClient] = {}

    def approve(request: ApprovalRequest) -> ApprovalDecision:
        assert request.kind == "command"
        return ApprovalDecision(decision="acceptForSession", reason="test")

    def factory(config: CodexConfig, handler: Callable[..., dict[str, Any]]) -> FakeCodexClient:
        client = FakeCodexClient(config, handler)
        holder["client"] = client
        return client

    result = run_codex(
        config,
        "inspect target",
        sink=sink,
        approval_callback=approve,
        thread_id="thread-existing",
        client_factory=factory,
    )

    assert result.outcome == "ok"
    assert holder["client"].resume_id == "thread-existing"
    assert holder["client"].approval_result == {"decision": "acceptForSession"}


def test_dangerously_bypass_changes_only_inner_codex_policy(tmp_path: Path) -> None:
    config = _config(tmp_path)
    sink = TraceSink(run_id="run-1", task_id="task", trace_dir=tmp_path)
    holder: dict[str, FakeCodexClient] = {}

    def factory(config: CodexConfig, handler: Callable[..., dict[str, Any]]) -> FakeCodexClient:
        client = FakeCodexClient(config, handler)
        holder["client"] = client
        return client

    result = run_codex(
        config,
        "inspect target",
        sink=sink,
        dangerously_bypass=True,
        client_factory=factory,
    )

    assert result.outcome == "ok"
    assert holder["client"].thread_params["approvalPolicy"] == "never"
    assert holder["client"].thread_params["sandbox"] == "danger-full-access"
    assert holder["client"].approval_result == {"decision": "accept"}


def test_codex_config_disables_unsupported_namespace_tools(tmp_path: Path) -> None:
    codex_config = build_codex_config(
        _config(tmp_path),
        provider_base_url="https://api.example.test/v1",
        api_key="test-key",
    )

    assert "features.multi_agent=false" in codex_config.config_overrides
