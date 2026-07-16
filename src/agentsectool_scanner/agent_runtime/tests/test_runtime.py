from __future__ import annotations

from io import StringIO
from pathlib import Path

from agentsectool_scanner.agent_runtime import runtime
from agentsectool_scanner.agent_runtime.config import Config
from agentsectool_scanner.agent_runtime.core import RunResult
from agentsectool_scanner.agent_runtime.trace import TraceSink


def test_repl_uses_a_distinct_run_id_for_each_task(
    tmp_path: Path, monkeypatch
) -> None:
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
        run_id="stale-run-id",
        trace_dir=str(tmp_path),
        workspace=str(tmp_path),
    )
    observed_run_ids: list[str] = []

    def fake_run(active_config: Config, _text: str, **_kwargs: object) -> RunResult:
        assert active_config.run_id is not None
        observed_run_ids.append(active_config.run_id)
        TraceSink(
            run_id=active_config.run_id,
            task_id=active_config.task_id,
            trace_dir=active_config.trace_dir,
        ).emit(
            stage="core",
            type="run_exit",
            outcome="ok",
            payload={
                "text": "done",
                "thread_id": "thread-1",
                "turn_id": f"turn-{len(observed_run_ids)}",
            },
        )
        return RunResult(outcome="ok", steps=0)

    monkeypatch.setattr(runtime, "run", fake_run)
    input_stream = StringIO()
    output_stream = StringIO()

    runtime.execute_repl_task(config, "first", input_stream, output_stream)
    runtime.execute_repl_task(config, "second", input_stream, output_stream)

    assert len(set(observed_run_ids)) == 2
    assert "stale-run-id" not in observed_run_ids


def test_repl_failure_summary_uses_codex_command_result(tmp_path: Path) -> None:
    sink = TraceSink(run_id="failed-run", task_id="task", trace_dir=tmp_path)
    sink.emit(
        stage="core",
        type="tool_result",
        payload={
            "call_id": "call-1",
            "tool_name": "shell",
            "result": {
                "type": "commandExecution",
                "status": "failed",
                "exitCode": 7,
                "aggregatedOutput": "expected failure",
            },
        },
    )

    summary = runtime._repl_fallback_summary(
        run_id="failed-run",
        trace_dir=tmp_path,
        result=RunResult(outcome="error", steps=1),
    )

    assert "shell call-1" in summary
    assert "exit_code=7" in summary
    assert "expected failure" in summary
