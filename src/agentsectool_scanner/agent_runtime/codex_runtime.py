from __future__ import annotations

import json
import os
from collections.abc import Callable
from contextlib import nullcontext
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Protocol

from openai_codex import CodexConfig
from openai_codex.client import CodexClient

from agentsectool_scanner.agent_runtime.config import Config, resolve_api_key
from agentsectool_scanner.agent_runtime.core import ApprovalCallback, ApprovalDecision, ApprovalRequest
from agentsectool_scanner.agent_runtime.core.events import LoopProgressEvent, RunResult
from agentsectool_scanner.agent_runtime.trace import TraceEvent, TraceSink
from agentsectool_scanner.agent_runtime.trace.http_relay import TraceHttpRelay
from agentsectool_scanner.agent_runtime.trace.payloads import TracePayloadRecorder, to_jsonable

_CODEX_PROVIDER_ID = "scanner_agent_provider"


class CodexClientLike(Protocol):
    def __enter__(self) -> "CodexClientLike": ...

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None: ...

    def initialize(self) -> object: ...

    def thread_start(self, params: dict[str, Any] | None = None) -> object: ...

    def thread_resume(
        self, thread_id: str, params: dict[str, Any] | None = None
    ) -> object: ...

    def turn_start(
        self,
        thread_id: str,
        input_items: str,
        params: dict[str, Any] | None = None,
    ) -> object: ...

    def next_turn_notification(self, turn_id: str) -> object: ...

    def unregister_turn_notifications(self, turn_id: str) -> None: ...


ApprovalHandler = Callable[[str, dict[str, Any] | None], dict[str, Any]]
ClientFactory = Callable[[CodexConfig, ApprovalHandler], CodexClientLike]


def run_codex(
    config: Config,
    raw_text: str,
    *,
    sink: TraceSink,
    progress_callback: Callable[[LoopProgressEvent], None] | None = None,
    approval_callback: ApprovalCallback | None = None,
    thread_id: str | None = None,
    dangerously_bypass: bool = False,
    client_factory: ClientFactory | None = None,
) -> RunResult:
    """Run one Codex turn and translate app-server events into project trace events."""

    normalized_task = raw_text.strip()
    if not normalized_task:
        raise ValueError("task must not be empty")

    profile = config.active_profile
    api_key = resolve_api_key(profile)
    task_event = sink.emit(
        stage="P0",
        type="task_input",
        payload={
            "raw_text": raw_text,
            "normalized_text": normalized_task,
            "resume_thread_id": thread_id,
            "model_profile": config.active_model,
        },
    )
    artifact_dir = Path(config.trace_dir) / "artifacts" / sink.run_id
    recorder = TracePayloadRecorder(
        sink=sink,
        artifact_dir=artifact_dir / "llm",
        capture_enabled=config.trace.capture_llm_io,
        raw_payloads=config.trace.raw_payloads,
        preview_chars=config.trace.preview_chars,
    )

    relay_required = recorder.capture_enabled or profile.provider == "litellm"
    relay_context = (
        TraceHttpRelay(
            host="127.0.0.1",
            port=0,
            target_base_url=profile.base_url,
            recorder=recorder,
            model=profile.model,
            parents=[task_event.id],
            layer="codex_to_provider",
            normalize_tool_sequence=profile.provider == "litellm",
        )
        if relay_required
        else nullcontext(None)
    )

    try:
        with relay_context as relay:
            provider_base_url = relay.base_url if relay is not None else profile.base_url
            codex_config = build_codex_config(
                config,
                provider_base_url=provider_base_url,
                api_key=api_key,
            )
            bridge = _CodexTraceBridge(
                sink=sink,
                anchor=task_event,
                progress_callback=progress_callback,
                approval_callback=approval_callback,
                dangerously_bypass=dangerously_bypass,
            )
            factory = client_factory or _default_client_factory
            with factory(codex_config, bridge.handle_approval) as client:
                initialize_response = client.initialize()
                thread_response = start_or_resume_thread(
                    client,
                    config=config,
                    thread_id=thread_id,
                    dangerously_bypass=dangerously_bypass,
                )
                active_thread_id = _nested_text(thread_response, "thread", "id")
                if active_thread_id is None:
                    raise RuntimeError("Codex thread response did not contain a thread id")

                runtime_event = sink.emit(
                    stage="core",
                    type="runtime_metadata",
                    parents=[task_event.id],
                    payload={
                        "agent_runtime": "codex",
                        "sdk_package": "openai-codex",
                        "sdk_version": _package_version("openai-codex"),
                        "initialize": to_jsonable(initialize_response),
                        "thread_id": active_thread_id,
                        "model_profile": config.active_model,
                        "requested_model": profile.model,
                        "provider_kind": profile.provider,
                        "provider_base_url": profile.base_url,
                    },
                )
                bridge.set_runtime_anchor(runtime_event)

                turn_params: dict[str, Any] = {"effort": profile.reasoning_effort}
                if profile.service_tier is not None:
                    turn_params["serviceTier"] = profile.service_tier
                turn_response = client.turn_start(
                    active_thread_id,
                    normalized_task,
                    params=turn_params,
                )
                active_turn_id = _nested_text(turn_response, "turn", "id")
                if active_turn_id is None:
                    raise RuntimeError("Codex turn response did not contain a turn id")
                bridge.set_turn(active_thread_id, active_turn_id)

                try:
                    while True:
                        notification = client.next_turn_notification(active_turn_id)
                        if bridge.handle_notification(notification):
                            break
                finally:
                    client.unregister_turn_notifications(active_turn_id)

                return bridge.finish()
    except Exception as exc:
        sink.emit(
            stage="core",
            type="run_exit",
            parents=[task_event.id],
            outcome="error",
            payload={
                "reason": "codex_runtime_error",
                "error_type": type(exc).__name__,
                "message": str(exc),
                "thread_id": thread_id,
                "model_profile": config.active_model,
            },
        )
        _emit_progress(
            progress_callback,
            LoopProgressEvent(
                type="run_exit",
                outcome="error",
                reason="codex_runtime_error",
                text=str(exc),
            ),
        )
        return RunResult(outcome="error", steps=0)


def _default_client_factory(
    config: CodexConfig,
    approval_handler: Callable[[str, dict[str, Any] | None], dict[str, Any]],
) -> CodexClient:
    return CodexClient(config=config, approval_handler=approval_handler)


def build_codex_config(
    config: Config, *, provider_base_url: str, api_key: str
) -> CodexConfig:
    """Build the pinned Codex app-server configuration for one model profile."""

    overrides = (
        _override("model_provider", _CODEX_PROVIDER_ID),
        _override(f"model_providers.{_CODEX_PROVIDER_ID}.name", "Scanner model provider"),
        _override(f"model_providers.{_CODEX_PROVIDER_ID}.base_url", provider_base_url),
        _override(f"model_providers.{_CODEX_PROVIDER_ID}.env_key", "AGENTSECTOOL_MODEL_API_KEY"),
        _override(f"model_providers.{_CODEX_PROVIDER_ID}.wire_api", "responses"),
        f"model_providers.{_CODEX_PROVIDER_ID}.requires_openai_auth=false",
        "features.multi_agent=false",
        'web_search="disabled"',
    )
    env = {
        "AGENTSECTOOL_MODEL_API_KEY": api_key,
        "CODEX_HOME": os.environ.get("CODEX_HOME", "/home/scanner/.codex"),
    }
    return CodexConfig(
        config_overrides=overrides,
        cwd=config.workspace,
        env=env,
        client_name="agentsectool_scanner_agent",
        client_title="AgentSecTool Scanner Agent",
    )


def start_or_resume_thread(
    client: CodexClientLike,
    *,
    config: Config,
    thread_id: str | None,
    dangerously_bypass: bool,
) -> object:
    """Create or resume a thread with the project's approval and sandbox policy."""

    profile = config.active_profile
    params: dict[str, Any] = {
        "approvalPolicy": "never" if dangerously_bypass else "on-request",
        "approvalsReviewer": "user",
        "cwd": config.workspace,
        "developerInstructions": config.system_prompt,
        "model": profile.model,
        "modelProvider": _CODEX_PROVIDER_ID,
        "sandbox": "danger-full-access" if dangerously_bypass else "workspace-write",
    }
    if profile.service_tier is not None:
        params["serviceTier"] = profile.service_tier
    if thread_id:
        return client.thread_resume(thread_id, params=params)
    return client.thread_start(params=params)


class _CodexTraceBridge:
    def __init__(
        self,
        *,
        sink: TraceSink,
        anchor: TraceEvent,
        progress_callback: Callable[[LoopProgressEvent], None] | None,
        approval_callback: ApprovalCallback | None,
        dangerously_bypass: bool,
    ) -> None:
        self._sink = sink
        self._anchor = anchor
        self._progress_callback = progress_callback
        self._approval_callback = approval_callback
        self._dangerously_bypass = dangerously_bypass
        self._runtime_anchor = anchor
        self._thread_id: str | None = None
        self._turn_id: str | None = None
        self._item_events: dict[str, TraceEvent] = {}
        self._approval_events: dict[str, TraceEvent] = {}
        self._terminal_events: list[str] = []
        self._final_text_parts: list[str] = []
        self._completed_items = 0
        self._turn_status = "failed"
        self._turn_error: object = None

    def set_runtime_anchor(self, event: TraceEvent) -> None:
        self._runtime_anchor = event

    def set_turn(self, thread_id: str, turn_id: str) -> None:
        self._thread_id = thread_id
        self._turn_id = turn_id

    def handle_approval(self, method: str, params: dict[str, Any] | None) -> dict[str, Any]:
        request = _approval_request(method, params or {})
        if self._dangerously_bypass:
            decision = ApprovalDecision(decision="accept", reason="dangerously_bypassed")
        elif self._approval_callback is None:
            decision = ApprovalDecision(decision="decline", reason="approval_unavailable")
        else:
            decision = self._approval_callback(request)

        parent = self._item_events.get(request.item_id or "", self._runtime_anchor)
        event = self._sink.emit(
            stage="core",
            type="approval_event",
            parents=[parent.id],
            payload={
                "request": request.model_dump(mode="json"),
                "decision": decision.model_dump(mode="json"),
            },
        )
        if request.item_id:
            self._approval_events[request.item_id] = event
        return {"decision": decision.decision}

    def handle_notification(self, notification: object) -> bool:
        method = getattr(notification, "method", "unknown")
        payload = to_jsonable(getattr(notification, "payload", {}))
        if not isinstance(payload, dict):
            payload = {"value": payload}
        stream_event = self._sink.emit(
            stage="core",
            type="llm_stream_event",
            parents=[self._runtime_anchor.id],
            payload={"method": method, "data": payload},
        )

        if method == "item/agentMessage/delta":
            delta = payload.get("delta")
            if isinstance(delta, str):
                self._final_text_parts.append(delta)
                _emit_progress(
                    self._progress_callback,
                    LoopProgressEvent(type="model_text_delta", text=delta),
                )
            self._terminal_events.append(stream_event.id)
            return False

        if method == "item/started":
            self._handle_item_started(payload, stream_event)
            return False

        if method == "item/completed":
            self._handle_item_completed(payload, stream_event)
            return False

        if method == "turn/completed":
            turn = payload.get("turn")
            if isinstance(turn, dict):
                self._turn_status = str(turn.get("status") or "failed")
                self._turn_error = turn.get("error")
            self._terminal_events.append(stream_event.id)
            return True

        return False

    def _handle_item_started(self, payload: dict[str, Any], parent: TraceEvent) -> None:
        item = payload.get("item")
        if not isinstance(item, dict):
            return
        item_id = item.get("id")
        item_type = item.get("type")
        if not isinstance(item_id, str) or not isinstance(item_type, str):
            return
        tool_name = _tool_name(item)
        if tool_name is None:
            return
        arguments = _tool_arguments(item)
        parsed_event = self._sink.emit(
            stage="core",
            type="parsed_tool_call",
            parents=[parent.id],
            payload={
                "call_id": item_id,
                "tool_name": tool_name,
                "arguments": arguments,
                "source": "codex_app_server",
            },
        )
        start_event = self._sink.emit(
            stage="core",
            type="tool_call_start",
            parents=[parsed_event.id],
            payload={"call_id": item_id, "tool_name": tool_name, "arguments": arguments},
        )
        self._item_events[item_id] = start_event
        _emit_progress(
            self._progress_callback,
            LoopProgressEvent(
                type="tool_call_start",
                tool_name=tool_name,
                call_id=item_id,
                arguments=arguments,
                display=_tool_display(item),
            ),
        )

    def _handle_item_completed(self, payload: dict[str, Any], parent: TraceEvent) -> None:
        item = payload.get("item")
        if not isinstance(item, dict):
            return
        item_id = item.get("id")
        item_type = item.get("type")
        if item_type == "agentMessage" and not self._final_text_parts:
            text = item.get("text")
            if isinstance(text, str):
                self._final_text_parts.append(text)
        if not isinstance(item_id, str):
            return
        tool_name = _tool_name(item)
        if tool_name is None:
            return
        event_parent = (
            self._approval_events.get(item_id) or self._item_events.get(item_id) or parent
        )
        result_event = self._sink.emit(
            stage="core",
            type="tool_result",
            parents=[event_parent.id],
            payload={
                "call_id": item_id,
                "tool_name": tool_name,
                "result": item,
                "tainted": True,
            },
        )
        self._completed_items += 1
        self._terminal_events.append(result_event.id)
        _emit_progress(
            self._progress_callback,
            LoopProgressEvent(
                type="tool_call_finish",
                tool_name=tool_name,
                call_id=item_id,
                result={"result": item},
            ),
        )

    def finish(self) -> RunResult:
        outcome = "ok" if self._turn_status == "completed" else "error"
        reason = "codex_finished" if outcome == "ok" else "codex_turn_failed"
        parents = list(dict.fromkeys(self._terminal_events[-8:])) or [self._runtime_anchor.id]
        text = "".join(self._final_text_parts).strip()
        payload: dict[str, Any] = {
            "reason": reason,
            "text": text,
            "thread_id": self._thread_id,
            "turn_id": self._turn_id,
            "turn_status": self._turn_status,
        }
        if self._turn_error is not None:
            payload["error"] = self._turn_error
        self._sink.emit(
            stage="core",
            type="run_exit",
            parents=parents,
            outcome=outcome,
            payload=payload,
        )
        _emit_progress(
            self._progress_callback,
            LoopProgressEvent(
                type="run_exit",
                step=self._completed_items,
                outcome=outcome,
                reason=reason,
            ),
        )
        return RunResult(outcome=outcome, steps=self._completed_items)


def _approval_request(method: str, params: dict[str, Any]) -> ApprovalRequest:
    network = params.get("networkApprovalContext")
    if method == "item/fileChange/requestApproval":
        kind = "file_change"
    elif isinstance(network, dict):
        kind = "network"
    elif method == "item/commandExecution/requestApproval":
        kind = "command"
    else:
        kind = "unknown"
    available = params.get("availableDecisions")
    return ApprovalRequest(
        method=method,
        kind=kind,
        thread_id=_text(params.get("threadId")),
        turn_id=_text(params.get("turnId")),
        item_id=_text(params.get("itemId")),
        reason=_text(params.get("reason")),
        command=_text(params.get("command")),
        cwd=_text(params.get("cwd")),
        grant_root=_text(params.get("grantRoot")),
        network_context=network if isinstance(network, dict) else None,
        available_decisions=[str(value) for value in available]
        if isinstance(available, list)
        else [],
    )


def _tool_name(item: dict[str, Any]) -> str | None:
    item_type = item.get("type")
    if item_type == "commandExecution":
        return "shell"
    if item_type == "fileChange":
        return "apply_patch"
    if item_type == "mcpToolCall":
        return f"mcp:{item.get('server', 'unknown')}/{item.get('tool', 'unknown')}"
    if item_type == "dynamicToolCall":
        namespace = item.get("namespace")
        tool = item.get("tool", "unknown")
        return f"{namespace}:{tool}" if namespace else str(tool)
    if item_type == "webSearch":
        return "web_search"
    return None


def _tool_arguments(item: dict[str, Any]) -> dict[str, Any]:
    item_type = item.get("type")
    if item_type == "commandExecution":
        return {"command": item.get("command"), "cwd": item.get("cwd")}
    if item_type == "fileChange":
        return {"changes": item.get("changes")}
    arguments = item.get("arguments")
    return arguments if isinstance(arguments, dict) else {"value": arguments}


def _tool_display(item: dict[str, Any]) -> str | None:
    command = item.get("command")
    if isinstance(command, str):
        return f"command: {command}"
    return None


def _override(key: str, value: str) -> str:
    return f"{key}={json.dumps(value, ensure_ascii=False)}"


def _nested_text(value: object, *fields: str) -> str | None:
    current = value
    for field in fields:
        if isinstance(current, dict):
            current = current.get(field)
        else:
            current = getattr(current, field, None)
    return _text(current)


def _text(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _package_version(name: str) -> str:
    try:
        return version(name)
    except PackageNotFoundError:
        return "unknown"


def _emit_progress(
    callback: Callable[[LoopProgressEvent], None] | None,
    event: LoopProgressEvent,
) -> None:
    if callback is not None:
        callback(event)
