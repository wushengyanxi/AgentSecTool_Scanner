from __future__ import annotations

import threading
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx

from agentsectool_scanner.agent_runtime.trace import TraceSink, read_trace
from agentsectool_scanner.agent_runtime.trace.http_relay import TraceHttpRelay
from agentsectool_scanner.agent_runtime.trace.payloads import TracePayloadRecorder


def test_relay_forwards_sse_and_records_actual_model(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("content-length", "0"))
            self.rfile.read(length)
            body = (
                b'data: {"type":"response.created","response":{"model":"actual-model"}}\n\n'
                b'data: [DONE]\n\n'
            )
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return None

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    sink = TraceSink(run_id="relay-run", task_id="task", trace_dir=tmp_path)
    recorder = TracePayloadRecorder(
        sink=sink,
        artifact_dir=tmp_path / "artifacts",
        capture_enabled=True,
        raw_payloads=False,
        preview_chars=1000,
    )

    try:
        with TraceHttpRelay(
            host="127.0.0.1",
            port=0,
            target_base_url=f"http://127.0.0.1:{upstream.server_port}",
            recorder=recorder,
            model="requested-model",
            parents=[],
            layer="codex_to_provider",
        ) as relay:
            with httpx.Client(trust_env=False) as client:
                response = client.post(
                    relay.base_url + "/v1/responses",
                    headers={"authorization": "Bearer secret-token"},
                    json={"model": "requested-model", "input": "hello"},
                )
    finally:
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=2)

    assert response.status_code == 200
    assert "response.created" in response.text
    events = read_trace(run_id="relay-run", trace_dir=tmp_path)
    response_event = [event for event in events if event.type == "llm_response"][-1]
    assert response_event.payload["metadata"]["response_model"] == "actual-model"
    request_event = [event for event in events if event.type == "llm_request"][-1]
    assert request_event.payload["metadata"]["headers"]["authorization"] == "***"


def test_relay_normalizes_litellm_tool_result_order(tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("content-length", "0"))
            captured["body"] = httpx.Response(
                200, content=self.rfile.read(length)
            ).json()
            body = b'data: {"type":"response.completed","response":{}}\n\n'
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return None

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    sink = TraceSink(run_id="relay-order", task_id="task", trace_dir=tmp_path)
    recorder = TracePayloadRecorder(
        sink=sink,
        artifact_dir=tmp_path / "artifacts-order",
        capture_enabled=False,
        raw_payloads=False,
        preview_chars=1000,
    )
    input_items = [
        {"type": "function_call", "call_id": "call-1", "name": "exec_command"},
        {
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "checking"}],
        },
        {"type": "function_call_output", "call_id": "call-1", "output": "ok"},
    ]

    try:
        with TraceHttpRelay(
            host="127.0.0.1",
            port=0,
            target_base_url=f"http://127.0.0.1:{upstream.server_port}",
            recorder=recorder,
            model="requested-model",
            parents=[],
            normalize_tool_sequence=True,
        ) as relay:
            with httpx.Client(trust_env=False) as client:
                response = client.post(
                    relay.base_url + "/v1/responses",
                    json={"model": "requested-model", "input": deepcopy(input_items)},
                )
    finally:
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=2)

    assert response.status_code == 200
    assert [item["type"] for item in captured["body"]["input"]] == [
        "message",
        "function_call",
        "function_call_output",
    ]
