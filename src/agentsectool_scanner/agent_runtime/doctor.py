from __future__ import annotations

import os
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from openai_codex.client import CodexClient

from agentsectool_scanner.agent_runtime.codex_runtime import build_codex_config, start_or_resume_thread
from agentsectool_scanner.agent_runtime.config import Config, resolve_api_key
from agentsectool_scanner.agent_runtime.trace import read_trace
from agentsectool_scanner.agent_runtime.trace.payloads import to_jsonable


def run_static_checks(config: Config) -> dict[str, Any]:
    """Check the pinned SDK, runtime process, writable state, and active credentials."""

    checks: dict[str, dict[str, Any]] = {}
    sdk_version = _package_version("openai-codex")
    checks["codex_sdk"] = {
        "ok": sdk_version == "0.1.0b3",
        "version": sdk_version,
        "expected": "0.1.0b3",
    }
    workspace = Path(config.workspace)
    checks["workspace"] = {
        "ok": workspace.is_dir() and os.access(workspace, os.W_OK),
        "path": str(workspace),
    }
    codex_home = Path(os.environ.get("CODEX_HOME", "/home/scanner/.codex"))
    checks["codex_home"] = {
        "ok": codex_home.is_dir() and os.access(codex_home, os.W_OK),
        "path": str(codex_home),
    }
    api_key = ""
    try:
        api_key = resolve_api_key(config.active_profile)
    except RuntimeError as exc:
        checks["model_credentials"] = {"ok": False, "message": str(exc)}
    else:
        checks["model_credentials"] = {"ok": True}

    try:
        client_config = build_codex_config(
            config,
            provider_base_url=config.active_profile.base_url,
            api_key=api_key or "doctor-placeholder",
        )
        with CodexClient(
            config=client_config,
            approval_handler=lambda _method, _params: {"decision": "decline"},
        ) as client:
            metadata = client.initialize()
            thread = start_or_resume_thread(
                client,
                config=config,
                thread_id=None,
                dangerously_bypass=False,
            )
        checks["codex_app_server"] = {
            "ok": True,
            "metadata": to_jsonable(metadata),
            "thread": to_jsonable(thread),
        }
    except Exception as exc:
        checks["codex_app_server"] = {
            "ok": False,
            "error_type": type(exc).__name__,
            "message": str(exc),
        }

    return {
        "ok": all(bool(check.get("ok")) for check in checks.values()),
        "mode": "static",
        "model_profile": config.active_model,
        "provider": config.active_profile.provider,
        "model": config.active_profile.model,
        "checks": checks,
    }


def evaluate_live_trace(config: Config) -> dict[str, Any]:
    """Evaluate the protocol properties produced by a live doctor turn."""

    if config.run_id is None:
        raise RuntimeError("doctor live run requires run_id")
    events = read_trace(run_id=config.run_id, trace_dir=config.trace_dir)
    tool_results = [
        event
        for event in events
        if event.type == "tool_result"
        and _tool_item(event.payload).get("type") == "commandExecution"
    ]
    stream_events = [
        event
        for event in events
        if event.type == "llm_stream_event"
        and event.payload.get("method") == "item/agentMessage/delta"
    ]
    exit_events = [event for event in events if event.type == "run_exit"]
    recent_exits = exit_events[-2:]
    failed_commands = [
        event
        for event in tool_results
        if isinstance(_tool_item(event.payload).get("exitCode"), int)
        and _tool_item(event.payload)["exitCode"] != 0
    ]
    recovered_after_failure = bool(
        failed_commands
        and any(
            event.seq > failed_commands[0].seq
            and _tool_item(event.payload).get("exitCode") == 0
            for event in tool_results
        )
    )
    marker_observed = any(
        "protocol-check-marker" in str(_tool_item(event.payload).get("aggregatedOutput", ""))
        for event in tool_results
    )
    thread_ids = [event.payload.get("thread_id") for event in recent_exits]
    turn_ids = [event.payload.get("turn_id") for event in recent_exits]
    checks = {
        "responses_stream": {"ok": bool(stream_events)},
        "multiple_tool_calls": {"ok": len(tool_results) >= 4, "count": len(tool_results)},
        "failure_recovery": {
            "ok": recovered_after_failure,
            "failed_command_count": len(failed_commands),
        },
        "workspace_write": {"ok": marker_observed},
        "turn_completion": {
            "ok": len(recent_exits) == 2 and all(event.outcome == "ok" for event in recent_exits),
            "outcomes": [event.outcome for event in recent_exits],
        },
        "thread_resume": {
            "ok": (
                len(thread_ids) == 2
                and isinstance(thread_ids[0], str)
                and thread_ids[0] == thread_ids[1]
                and len(set(turn_ids)) == 2
            ),
            "thread_ids": thread_ids,
            "turn_ids": turn_ids,
        },
    }
    return {
        "ok": all(bool(check.get("ok")) for check in checks.values()),
        "mode": "live",
        "run_id": config.run_id,
        "checks": checks,
    }


def _package_version(name: str) -> str:
    try:
        return version(name)
    except PackageNotFoundError:
        return "missing"


def _tool_item(payload: dict[str, Any]) -> dict[str, Any]:
    result = payload.get("result")
    return result if isinstance(result, dict) else {}
