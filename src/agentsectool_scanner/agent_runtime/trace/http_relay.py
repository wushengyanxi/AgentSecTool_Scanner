from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Sequence
from contextlib import AbstractContextManager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urljoin

import httpx

from agentsectool_scanner.agent_runtime.trace.payloads import TracePayloadRecorder, redact_headers

_HOP_BY_HOP_HEADERS = {
    "connection",
    "content-encoding",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


class TraceHttpRelay(AbstractContextManager["TraceHttpRelay"]):
    """Small local HTTP relay that records request and response bodies."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        target_base_url: str,
        recorder: TracePayloadRecorder,
        model: str,
        parents: Sequence[str],
        layer: str = "sdk_to_provider",
        normalize_tool_sequence: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self._target_base_url = target_base_url.rstrip("/") + "/"
        self._recorder = recorder
        self._model = model
        self._parents = list(parents)
        self._layer = layer
        self._normalize_tool_sequence = normalize_tool_sequence
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "TraceHttpRelay":
        relay = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # noqa: N802
                self._handle()

            def do_POST(self) -> None:  # noqa: N802
                self._handle()

            def do_PUT(self) -> None:  # noqa: N802
                self._handle()

            def do_PATCH(self) -> None:  # noqa: N802
                self._handle()

            def do_DELETE(self) -> None:  # noqa: N802
                self._handle()

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _handle(self) -> None:
                relay._handle_request(self)

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self.port = int(self._server.server_address[1])
        self.base_url = f"http://{self.host}:{self.port}"
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name=f"trace-http-relay-{self.port}",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> bool:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        return False

    def _handle_request(self, handler: BaseHTTPRequestHandler) -> None:
        request_id = uuid.uuid4().hex[:12]
        request_body = _read_request_body(handler)
        if self._normalize_tool_sequence:
            request_body = _normalize_responses_tool_sequence(request_body)
        request_event = self._recorder.record_llm_payload(
            layer=self._layer,
            direction="request",
            request_id=request_id,
            model=self._model,
            body=request_body,
            metadata={
                "method": handler.command,
                "path": handler.path,
                "headers": redact_headers(dict(handler.headers.items())),
            },
            parents=self._parents,
        )

        target_url = urljoin(self._target_base_url, handler.path.lstrip("/"))
        headers = _forward_headers(dict(handler.headers.items()))
        response_started = False
        try:
            with httpx.Client(timeout=None) as client:
                with client.stream(
                    handler.command,
                    target_url,
                    headers=headers,
                    content=request_body,
                ) as response:
                    _start_streaming_response(handler, response.status_code, response.headers)
                    response_started = True
                    chunks: list[bytes] = []
                    for chunk in response.iter_bytes():
                        if not chunk:
                            continue
                        chunks.append(chunk)
                        handler.wfile.write(chunk)
                        handler.wfile.flush()
                    response_body = b"".join(chunks)
                    response_headers = dict(response.headers.items())
                    response_status = response.status_code
            parent_ids = [request_event.id] if request_event is not None else self._parents
            self._recorder.record_llm_payload(
                layer=self._layer,
                direction="response",
                request_id=request_id,
                model=self._model,
                body=response_body,
                metadata={
                    "status_code": response_status,
                    "headers": redact_headers(response_headers),
                    "response_model": _response_model(response_body),
                },
                parents=parent_ids,
            )
        except Exception as exc:
            parent_ids = [request_event.id] if request_event is not None else self._parents
            error_body = {
                "error": str(exc) or type(exc).__name__,
                "error_type": type(exc).__name__,
            }
            self._recorder.record_llm_payload(
                layer=self._layer,
                direction="response",
                request_id=request_id,
                model=self._model,
                body=error_body,
                metadata={"status_code": 502},
                parents=parent_ids,
            )
            if response_started:
                handler.close_connection = True
            else:
                _write_response(
                    handler,
                    502,
                    {"content-type": "application/json"},
                    b'{"error":"trace relay upstream request failed"}',
                )


def _read_request_body(handler: BaseHTTPRequestHandler) -> bytes:
    length_text = handler.headers.get("content-length")
    if not length_text:
        return b""
    try:
        length = int(length_text)
    except ValueError:
        return b""
    if length <= 0:
        return b""
    return handler.rfile.read(length)


def _normalize_responses_tool_sequence(body: bytes) -> bytes:
    """Keep assistant text outside function-call/result pairs for Chat API gateways."""

    try:
        payload = json.loads(body)
    except (TypeError, ValueError):
        return body
    if not isinstance(payload, dict) or not isinstance(payload.get("input"), list):
        return body

    items = list(payload["input"])
    changed = False
    while True:
        pending_start: int | None = None
        pending_ids: set[str] = set()
        relocated = False
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            item_type = item.get("type")
            call_id = item.get("call_id")
            if item_type == "function_call" and isinstance(call_id, str):
                if pending_start is None:
                    pending_start = index
                pending_ids.add(call_id)
                continue
            if item_type == "function_call_output" and isinstance(call_id, str):
                pending_ids.discard(call_id)
                if not pending_ids:
                    pending_start = None
                continue
            if (
                pending_start is not None
                and item_type == "message"
                and item.get("role") == "assistant"
                and _has_pending_output(items[index + 1 :], pending_ids)
            ):
                message = items.pop(index)
                items.insert(pending_start, message)
                changed = True
                relocated = True
                break
        if not relocated:
            break

    if not changed:
        return body
    payload["input"] = items
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _has_pending_output(items: list[object], pending_ids: set[str]) -> bool:
    return any(
        isinstance(item, dict)
        and item.get("type") == "function_call_output"
        and item.get("call_id") in pending_ids
        for item in items
    )


def _forward_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in _HOP_BY_HOP_HEADERS and key.lower() != "host"
    }


def _write_response(
    handler: BaseHTTPRequestHandler,
    status_code: int,
    headers: httpx.Headers | dict[str, str],
    body: bytes,
) -> None:
    handler.send_response(status_code)
    for key, value in headers.items():
        if key.lower() in _HOP_BY_HOP_HEADERS:
            continue
        handler.send_header(key, value)
    handler.send_header("content-length", str(len(body)))
    handler.send_header("connection", "close")
    handler.end_headers()
    handler.wfile.write(body)
    handler.wfile.flush()


def _start_streaming_response(
    handler: BaseHTTPRequestHandler,
    status_code: int,
    headers: httpx.Headers,
) -> None:
    handler.send_response(status_code)
    for key, value in headers.items():
        if key.lower() in _HOP_BY_HOP_HEADERS or key.lower() == "content-length":
            continue
        handler.send_header(key, value)
    handler.send_header("connection", "close")
    handler.end_headers()


def _response_model(body: bytes) -> str | None:
    text = body.decode("utf-8", errors="replace")
    candidates = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
    if not candidates:
        candidates = [text]
    for candidate in candidates:
        try:
            payload = json.loads(candidate)
        except (ValueError, TypeError):
            continue
        if isinstance(payload, dict):
            model = payload.get("model")
            if isinstance(model, str) and model:
                return model
            response = payload.get("response")
            if isinstance(response, dict) and isinstance(response.get("model"), str):
                return response["model"]
    return None
