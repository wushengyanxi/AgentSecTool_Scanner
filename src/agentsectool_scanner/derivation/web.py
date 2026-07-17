"""HTTP routing adapter for the standard-library dashboard server."""

from __future__ import annotations

from urllib.parse import unquote

from .repository import DerivationConflictError, DerivationNotFoundError
from .service import DerivationService


class DerivationAPI:
    def __init__(self, service: DerivationService | None = None):
        self.service = service or DerivationService()

    def handle(self, method: str, path: str, query: dict, body: dict | None) -> tuple[int, dict] | None:
        prefix = "/api/derivation"
        if not path.startswith(prefix):
            return None
        relative = path[len(prefix):].strip("/")
        parts = [unquote(part) for part in relative.split("/") if part]
        try:
            if method == "GET" and not parts:
                return 200, {"service": "derivation", "config": self.service.status()}
            if method == "GET" and parts == ["config"]:
                return 200, self.service.status()
            if method == "POST" and parts == ["imports", "preview"]:
                return 200, self.service.preview_import(self._required(body, "package_path"))
            if method == "POST" and parts == ["imports"]:
                return 201, self.service.import_package(
                    self._required(body, "package_path"), (body or {}).get("expected_hash")
                )
            if method == "GET" and parts == ["tasks"]:
                return 200, {"tasks": self.service.list_tasks(
                    status=self._query(query, "status"), query=self._query(query, "q")
                )}
            if len(parts) >= 2 and parts[0] == "tasks":
                task_id = parts[1]
                if method == "GET" and len(parts) == 2:
                    return 200, self.service.task_detail(task_id)
                if method == "GET" and parts[2:] == ["events"]:
                    after = int(self._query(query, "after") or 0)
                    return 200, {"events": self.service.repository.list_events(task_id, after=after)}
                if method == "POST" and parts[2:] == ["messages"]:
                    payload = body or {}
                    return 202, self.service.send_message(
                        task_id,
                        str(payload.get("content") or ""),
                        payload.get("attachments") or [],
                    )
                if method == "POST" and parts[2:] == ["acceptance-tests"]:
                    payload = body or {}
                    return 201, self.service.save_acceptance_test(
                        task_id, payload.get("definition") or {}, payload.get("reason")
                    )
                if (
                    method == "POST"
                    and len(parts) == 5
                    and parts[2] == "acceptance-tests"
                    and parts[4] == "confirm"
                ):
                    return 200, self.service.confirm_acceptance_test(task_id, parts[3])
            if method == "GET" and len(parts) == 2 and parts[0] == "harness-runs":
                return 200, self.service.repository.get_harness_run(parts[1])
            if len(parts) == 3 and parts[0] == "capabilities" and method == "POST":
                if parts[2] == "approve":
                    return 200, self.service.approve_capability(
                        parts[1], (body or {}).get("note")
                    )
                if parts[2] == "reject":
                    return 200, self.service.reject_capability(
                        parts[1], str((body or {}).get("note") or "")
                    )
            return 404, {"error": "not found"}
        except DerivationNotFoundError as exc:
            return 404, {"error": str(exc)}
        except DerivationConflictError as exc:
            return 409, {"error": str(exc)}
        except (ValueError, TypeError) as exc:
            return 400, {"error": str(exc)}

    @staticmethod
    def _required(body: dict | None, key: str):
        value = (body or {}).get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"缺少字段：{key}")
        return value.strip()

    @staticmethod
    def _query(query: dict, key: str) -> str | None:
        values = query.get(key)
        return values[0] if values else None
