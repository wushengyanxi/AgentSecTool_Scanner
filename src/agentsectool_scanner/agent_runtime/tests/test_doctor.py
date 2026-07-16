from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from agentsectool_scanner.agent_runtime.config import Config
from agentsectool_scanner.agent_runtime.doctor import evaluate_live_trace, run_static_checks
from agentsectool_scanner.agent_runtime.trace import TraceSink


class FakeClient:
    def __init__(self, **_kwargs) -> None:
        self.thread_params = None

    def __enter__(self) -> "FakeClient":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def initialize(self) -> dict[str, str]:
        return {"userAgent": "codex-cli/0.137.0"}

    def thread_start(self, params=None):
        self.thread_params = params
        return SimpleNamespace(thread=SimpleNamespace(id="doctor-thread"))


def test_static_doctor_reports_runtime_and_credentials(
    tmp_path: Path, monkeypatch
) -> None:
    codex_home = tmp_path / "codex-home"
    workspace = tmp_path / "workspace"
    codex_home.mkdir()
    workspace.mkdir()
    config = Config(
        active_model="openai",
        models={
            "openai": {
                "provider": "openai",
                "model": "gpt-test",
                "base_url": "https://api.example.test/v1",
                "api_key": "test-key",
            }
        },
        workspace=str(workspace),
    )
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    monkeypatch.setattr("agentsectool_scanner.agent_runtime.doctor.CodexClient", FakeClient)

    result = run_static_checks(config)

    assert result["ok"] is True
    assert result["checks"]["codex_sdk"]["version"] == "0.1.0b3"
    assert result["checks"]["codex_app_server"]["metadata"]["userAgent"]


def test_live_doctor_requires_failure_recovery_and_thread_resume(tmp_path: Path) -> None:
    config = Config(
        active_model="openai",
        models={
            "openai": {
                "provider": "openai",
                "model": "gpt-test",
                "base_url": "https://api.example.test/v1",
                "api_key": "test-key",
            }
        },
        run_id="doctor-live",
        trace_dir=str(tmp_path),
        workspace=str(tmp_path),
    )
    sink = TraceSink(run_id="doctor-live", task_id="doctor", trace_dir=tmp_path)
    sink.emit(stage="core", type="llm_stream_event", payload={"method": "item/agentMessage/delta"})
    for exit_code, output in [
        (0, "protocol-check-a"),
        (7, "expected-failure"),
        (0, ""),
    ]:
        sink.emit(
            stage="core",
            type="tool_result",
            payload={
                "result": {
                    "type": "commandExecution",
                    "exitCode": exit_code,
                    "aggregatedOutput": output,
                }
            },
        )
    sink.emit(
        stage="core",
        type="run_exit",
        outcome="ok",
        payload={"thread_id": "thread-1", "turn_id": "turn-1"},
    )
    sink.emit(stage="core", type="llm_stream_event", payload={"method": "item/agentMessage/delta"})
    sink.emit(
        stage="core",
        type="tool_result",
        payload={
            "result": {
                "type": "commandExecution",
                "exitCode": 0,
                "aggregatedOutput": "protocol-check-marker",
            }
        },
    )
    sink.emit(
        stage="core",
        type="run_exit",
        outcome="ok",
        payload={"thread_id": "thread-1", "turn_id": "turn-2"},
    )

    result = evaluate_live_trace(config)

    assert result["ok"] is True
    assert result["checks"]["failure_recovery"]["ok"] is True
    assert result["checks"]["thread_resume"]["ok"] is True
