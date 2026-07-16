from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections.abc import Sequence
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from agentsectool_scanner.agent_runtime.trace.events import TraceEvent
from agentsectool_scanner.agent_runtime.trace.sink import TraceSink

_SENSITIVE_KEY_PARTS = (
    "authorization",
    "api_key",
    "apikey",
    "auth_token",
    "password",
    "secret",
    "token",
)
_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
_ASSIGNMENT_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|auth[_-]?token|password|secret|token)\s*[:=]\s*['\"]?[^'\"\s,;]+"
)
_SK_RE = re.compile(r"\b(?:sk|sk-ant|sk-proj|dsk)-[A-Za-z0-9._-]{8,}")


class TracePayloadRecorder:
    """Persist large LLM payloads as artifacts and write compact trace events."""

    def __init__(
        self,
        *,
        sink: TraceSink,
        artifact_dir: Path,
        capture_enabled: bool,
        raw_payloads: bool,
        preview_chars: int,
    ) -> None:
        self._sink = sink
        self._artifact_dir = artifact_dir
        self._capture_enabled = capture_enabled
        self._raw_payloads = raw_payloads
        self._preview_chars = preview_chars

    @property
    def capture_enabled(self) -> bool:
        return self._capture_enabled

    def record_llm_payload(
        self,
        *,
        layer: str,
        direction: str,
        request_id: str,
        body: Any,
        model: str | None = None,
        metadata: dict[str, Any] | None = None,
        parents: Sequence[str] | None = None,
    ) -> TraceEvent | None:
        """Write one request or response payload event and its body artifact."""

        if not self._capture_enabled:
            return None

        original = _body_to_jsonable(body)
        original_bytes = _canonical_bytes(original)
        stored = original if self._raw_payloads else redact_payload(original)
        artifact_text = _to_pretty_json(stored)
        artifact_path = self._write_artifact(
            layer=layer,
            direction=direction,
            request_id=request_id,
            text=artifact_text,
        )
        payload: dict[str, Any] = {
            "layer": layer,
            "direction": direction,
            "request_id": request_id,
            "body_sha256": hashlib.sha256(original_bytes).hexdigest(),
            "body_artifact": str(artifact_path),
            "redacted": not self._raw_payloads,
            "preview": _preview(artifact_text, self._preview_chars),
        }
        if model:
            payload["model"] = model
        if metadata:
            payload["metadata"] = redact_payload(to_jsonable(metadata))

        event_type = "llm_request" if direction == "request" else "llm_response"
        return self._sink.emit(
            stage="core",
            type=event_type,
            parents=parents,
            payload=payload,
        )

    def _write_artifact(
        self,
        *,
        layer: str,
        direction: str,
        request_id: str,
        text: str,
    ) -> Path:
        self._artifact_dir.mkdir(parents=True, exist_ok=True)
        token = secrets.token_hex(4)
        safe_request_id = _safe_name(request_id)
        path = self._artifact_dir / f"{layer}-{direction}-{safe_request_id}-{token}.json"
        path.write_text(text, encoding="utf-8")
        return path


def redact_payload(value: Any) -> Any:
    """Redact common credential-bearing fields and string patterns."""

    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if _is_sensitive_key(key_text):
                redacted[key_text] = "***"
            else:
                redacted[key_text] = redact_payload(item)
        return redacted
    if isinstance(value, list):
        return [redact_payload(item) for item in value]
    if isinstance(value, tuple):
        return [redact_payload(item) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def redact_headers(headers: dict[str, Any]) -> dict[str, Any]:
    """Redact HTTP headers; authorization-like headers are always removed."""

    return {
        str(key): ("***" if _is_sensitive_key(str(key)) else _redact_text(str(value)))
        for key, value in headers.items()
    }


def to_jsonable(value: Any) -> Any:
    """Convert common Python objects to JSON-safe structures for artifacts."""

    if isinstance(value, BaseModel):
        return to_jsonable(value.model_dump(mode="json"))
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        try:
            return to_jsonable(model_dump())
        except Exception:
            pass
    dict_method = getattr(value, "dict", None)
    if callable(dict_method):
        try:
            return to_jsonable(dict_method())
        except Exception:
            pass
    if is_dataclass(value):
        return to_jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [to_jsonable(item) for item in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return repr(value)


def _body_to_jsonable(body: Any) -> Any:
    if isinstance(body, bytes):
        text = body.decode("utf-8", errors="replace")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text
    if isinstance(body, str):
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return body
    return to_jsonable(body)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(to_jsonable(value), ensure_ascii=False, sort_keys=True).encode("utf-8")


def _to_pretty_json(value: Any) -> str:
    return json.dumps(to_jsonable(value), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _preview(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip())
    return (cleaned or "payload")[:80]


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _redact_text(value: str) -> str:
    text = _BEARER_RE.sub(r"\1***", value)
    text = _ASSIGNMENT_SECRET_RE.sub(lambda match: f"{match.group(1)}=***", text)
    return _SK_RE.sub("***", text)
