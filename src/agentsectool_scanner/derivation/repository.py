"""SQLite persistence for the derivation workflow."""

from __future__ import annotations

import json
import hashlib
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from agentsectool_scanner.paths import DERIVATION_DB


ACCEPTANCE_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class DerivationConflictError(RuntimeError):
    """Raised when an immutable workflow object conflicts with existing state."""


class DerivationNotFoundError(LookupError):
    """Raised when a requested workflow object does not exist."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _row(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


class DerivationRepository:
    def __init__(self, db_path: str | Path = DERIVATION_DB):
        self.db_path = Path(db_path)

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
        with self.connection() as conn:
            conn.executescript(schema)
            columns = {row[1] for row in conn.execute("PRAGMA table_info(harness_runs)")}
            if "image_reference" not in columns:
                conn.execute("ALTER TABLE harness_runs ADD COLUMN image_reference TEXT")
            capability_columns = {
                row[1] for row in conn.execute("PRAGMA table_info(capability_packages)")
            }
            if capability_columns and "capability_key" not in capability_columns:
                conn.execute("ALTER TABLE capability_packages ADD COLUMN capability_key TEXT")
                rows = conn.execute(
                    "SELECT id, manifest_json FROM capability_packages"
                ).fetchall()
                for row in rows:
                    manifest = json.loads(row["manifest_json"])
                    conn.execute(
                        "UPDATE capability_packages SET capability_key=? WHERE id=?",
                        (manifest.get("capability_id") or row["id"], row["id"]),
                    )
            conn.commit()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 15000")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def source_for_request(self, request_id: str) -> dict | None:
        self.initialize()
        with self.connection() as conn:
            return _row(conn.execute(
                """SELECT p.*, t.id AS task_id, t.status AS task_status
                   FROM package_snapshots p
                   LEFT JOIN derivation_tasks t ON t.source_package_id = p.id
                   WHERE p.package_kind='source' AND p.request_id=?""",
                (request_id,),
            ).fetchone())

    def create_source_task(
        self,
        *,
        request_id: str,
        package_hash: str,
        manifest: dict,
        source_path: str,
        storage_path: str,
        artifacts: Iterable[dict],
    ) -> dict:
        self.initialize()
        artifact_list = list(artifacts)
        task_id = new_id("task")
        package_id = new_id("pkg")
        thread_id = new_id("thread")
        now = utc_now()
        with self.transaction() as conn:
            existing = conn.execute(
                """SELECT p.package_hash, t.id AS task_id
                   FROM package_snapshots p
                   JOIN derivation_tasks t ON t.source_package_id=p.id
                   WHERE p.package_kind='source' AND p.request_id=?""",
                (request_id,),
            ).fetchone()
            if existing:
                if existing["package_hash"] != package_hash:
                    raise DerivationConflictError(
                        f"request_id {request_id!r} 已存在，但需求包内容不同"
                    )
                return self._get_task(conn, existing["task_id"])

            conn.execute(
                """INSERT INTO package_snapshots
                   (id, package_kind, request_id, task_id, source_path, package_hash,
                    manifest_json, storage_path, created_at)
                   VALUES (?, 'source', ?, ?, ?, ?, ?, ?, ?)""",
                (package_id, request_id, task_id, source_path, package_hash,
                 canonical_json(manifest), storage_path, now),
            )
            conn.execute(
                """INSERT INTO derivation_tasks
                   (id, request_id, source_package_id, status, created_at, updated_at)
                   VALUES (?, ?, ?, 'ready', ?, ?)""",
                (task_id, request_id, package_id, now, now),
            )
            conn.execute(
                "INSERT INTO agent_threads (id, task_id, created_at) VALUES (?, ?, ?)",
                (thread_id, task_id, now),
            )
            for artifact in artifact_list:
                conn.execute(
                    """INSERT INTO artifacts
                       (id, package_id, role, relative_path, kind, sha256, size_bytes,
                        media_type, storage_path, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (new_id("artifact"), package_id, artifact["role"],
                     artifact["relative_path"], artifact.get("kind"), artifact["sha256"],
                     artifact["size_bytes"], artifact["media_type"],
                     artifact["storage_path"], now),
                )
            self._insert_event(conn, task_id, None, "package_imported", {
                "request_id": request_id,
                "package_hash": package_hash,
                "artifact_count": len(artifact_list),
            }, now)
            return self._get_task(conn, task_id)

    def create_supplement(
        self,
        *,
        task_id: str,
        package_hash: str,
        manifest: dict,
        storage_path: str,
        artifacts: Iterable[dict],
    ) -> dict:
        self.initialize()
        package_id = new_id("supplement")
        now = utc_now()
        artifact_list = list(artifacts)
        with self.transaction() as conn:
            self._require_task(conn, task_id)
            conn.execute(
                """INSERT INTO package_snapshots
                   (id, package_kind, task_id, package_hash, manifest_json, storage_path, created_at)
                   VALUES (?, 'supplement', ?, ?, ?, ?, ?)""",
                (package_id, task_id, package_hash, canonical_json(manifest), storage_path, now),
            )
            for artifact in artifact_list:
                conn.execute(
                    """INSERT INTO artifacts
                       (id, package_id, role, relative_path, kind, sha256, size_bytes,
                        media_type, storage_path, created_at)
                       VALUES (?, ?, 'attachment', ?, ?, ?, ?, ?, ?, ?)""",
                    (new_id("artifact"), package_id, artifact["relative_path"],
                     artifact.get("kind"), artifact["sha256"], artifact["size_bytes"],
                     artifact["media_type"], artifact["storage_path"], now),
                )
            return {
                "id": package_id,
                "task_id": task_id,
                "package_hash": package_hash,
                "manifest": manifest,
                "storage_path": storage_path,
                "artifact_count": len(artifact_list),
                "created_at": now,
            }

    def list_tasks(self, status: str | None = None, query: str | None = None) -> list[dict]:
        self.initialize()
        where: list[str] = []
        args: list[object] = []
        if status:
            where.append("t.status=?")
            args.append(status)
        if query:
            where.append("(t.request_id LIKE ? OR t.project_name LIKE ? OR t.vulnerability_id LIKE ?)")
            token = f"%{query}%"
            args.extend((token, token, token))
        clause = "WHERE " + " AND ".join(where) if where else ""
        with self.connection() as conn:
            rows = conn.execute(
                f"""SELECT t.*,
                           COUNT(DISTINCT a.id) AS acceptance_count,
                           COUNT(DISTINCT CASE WHEN av.user_confirmed=1 THEN a.id END) AS confirmed_count
                    FROM derivation_tasks t
                    LEFT JOIN acceptance_tests a ON a.task_id=t.id
                    LEFT JOIN acceptance_test_versions av
                      ON av.acceptance_test_id=a.id AND av.version=a.current_version
                    {clause}
                    GROUP BY t.id
                    ORDER BY t.updated_at DESC""",
                args,
            ).fetchall()
            return [dict(row) for row in rows]

    def get_task(self, task_id: str) -> dict:
        self.initialize()
        with self.connection() as conn:
            return self._get_task(conn, task_id)

    def _get_task(self, conn: sqlite3.Connection, task_id: str) -> dict:
        task = _row(conn.execute(
            """SELECT t.*, p.package_hash AS source_package_hash,
                      p.source_path, p.storage_path AS source_storage_path,
                      p.manifest_json AS source_manifest_json
               FROM derivation_tasks t
               JOIN package_snapshots p ON p.id=t.source_package_id
               WHERE t.id=?""",
            (task_id,),
        ).fetchone())
        if not task:
            raise DerivationNotFoundError(f"派生任务不存在：{task_id}")
        task["source_manifest"] = json.loads(task.pop("source_manifest_json"))
        task["artifacts"] = [dict(row) for row in conn.execute(
            "SELECT * FROM artifacts WHERE package_id=? ORDER BY role, relative_path",
            (task["source_package_id"],),
        )]
        return task

    def update_task_identity(
        self, task_id: str, *, project_name: str | None, vulnerability_id: str | None
    ) -> None:
        self.initialize()
        with self.transaction() as conn:
            self._require_task(conn, task_id)
            conn.execute(
                """UPDATE derivation_tasks
                   SET project_name=COALESCE(?, project_name),
                       vulnerability_id=COALESCE(?, vulnerability_id), updated_at=?
                   WHERE id=?""",
                (project_name, vulnerability_id, utc_now(), task_id),
            )

    def set_task_status(self, task_id: str, status: str) -> None:
        self.initialize()
        with self.transaction() as conn:
            self._require_task(conn, task_id)
            conn.execute(
                "UPDATE derivation_tasks SET status=?, updated_at=? WHERE id=?",
                (status, utc_now(), task_id),
            )

    def list_artifacts(self, task_id: str, include_supplements: bool = True) -> list[dict]:
        self.initialize()
        with self.connection() as conn:
            self._require_task(conn, task_id)
            kinds = "('source','supplement')" if include_supplements else "('source')"
            rows = conn.execute(
                f"""SELECT a.*, p.package_kind, p.created_at AS package_created_at
                    FROM artifacts a
                    JOIN package_snapshots p ON p.id=a.package_id
                    WHERE p.task_id=? AND p.package_kind IN {kinds}
                    ORDER BY p.created_at, a.relative_path""",
                (task_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def get_artifact(self, task_id: str, artifact_id: str) -> dict:
        self.initialize()
        with self.connection() as conn:
            row = conn.execute(
                """SELECT a.*, p.package_kind, p.task_id
                   FROM artifacts a
                   JOIN package_snapshots p ON p.id=a.package_id
                   WHERE a.id=? AND p.task_id=?""",
                (artifact_id, task_id),
            ).fetchone()
            if not row:
                raise DerivationNotFoundError(f"材料不存在或不属于当前任务：{artifact_id}")
            return dict(row)

    def append_message(
        self,
        task_id: str,
        *,
        role: str,
        content: str,
        supplement_package_id: str | None = None,
    ) -> dict:
        if role not in {"user", "assistant"}:
            raise ValueError("消息角色必须为 user 或 assistant")
        if not content.strip() and not supplement_package_id:
            raise ValueError("消息内容和附件不能同时为空")
        self.initialize()
        message_id = new_id("message")
        now = utc_now()
        with self.transaction() as conn:
            thread = conn.execute("SELECT id FROM agent_threads WHERE task_id=?", (task_id,)).fetchone()
            if not thread:
                raise DerivationNotFoundError(f"派生任务不存在：{task_id}")
            if supplement_package_id:
                supplement = conn.execute(
                    "SELECT task_id FROM package_snapshots WHERE id=? AND package_kind='supplement'",
                    (supplement_package_id,),
                ).fetchone()
                if not supplement or supplement["task_id"] != task_id:
                    raise DerivationConflictError("补充包不属于当前任务")
            sequence = conn.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 FROM agent_messages WHERE thread_id=?",
                (thread["id"],),
            ).fetchone()[0]
            conn.execute(
                """INSERT INTO agent_messages
                   (id, thread_id, sequence, role, content, supplement_package_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (message_id, thread["id"], sequence, role, content.strip(),
                 supplement_package_id, now),
            )
            return {
                "id": message_id,
                "task_id": task_id,
                "sequence": sequence,
                "role": role,
                "content": content.strip(),
                "supplement_package_id": supplement_package_id,
                "created_at": now,
            }

    def list_messages(self, task_id: str) -> list[dict]:
        self.initialize()
        with self.connection() as conn:
            thread = conn.execute("SELECT id FROM agent_threads WHERE task_id=?", (task_id,)).fetchone()
            if not thread:
                raise DerivationNotFoundError(f"派生任务不存在：{task_id}")
            rows = conn.execute(
                "SELECT * FROM agent_messages WHERE thread_id=? ORDER BY sequence",
                (thread["id"],),
            ).fetchall()
            return [dict(row) for row in rows]

    def add_event(
        self, task_id: str, event_kind: str, payload: object, message_id: str | None = None
    ) -> int:
        self.initialize()
        with self.transaction() as conn:
            self._require_task(conn, task_id)
            return self._insert_event(conn, task_id, message_id, event_kind, payload, utc_now())

    def _insert_event(
        self,
        conn: sqlite3.Connection,
        task_id: str,
        message_id: str | None,
        event_kind: str,
        payload: object,
        now: str,
    ) -> int:
        cur = conn.execute(
            """INSERT INTO agent_events (task_id, message_id, event_kind, payload_json, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (task_id, message_id, event_kind, canonical_json(payload), now),
        )
        return int(cur.lastrowid)

    def list_events(self, task_id: str, after: int = 0, limit: int = 500) -> list[dict]:
        self.initialize()
        with self.connection() as conn:
            self._require_task(conn, task_id)
            rows = conn.execute(
                """SELECT * FROM agent_events
                   WHERE task_id=? AND id>? ORDER BY id LIMIT ?""",
                (task_id, max(0, int(after)), min(max(int(limit), 1), 1000)),
            ).fetchall()
            events = []
            for row in rows:
                item = dict(row)
                item["payload"] = json.loads(item.pop("payload_json"))
                events.append(item)
            return events

    def upsert_acceptance_test(
        self,
        task_id: str,
        definition: dict,
        *,
        actor: str,
        change_reason: str | None = None,
    ) -> dict:
        if actor not in {"agent", "user", "system"}:
            raise ValueError("无效的验收项修改主体")
        stable_key = str(definition.get("stable_key", "")).strip()
        name = str(definition.get("name", "")).strip()
        purpose = str(definition.get("purpose", "")).strip()
        assertion = definition.get("assertion")
        if not stable_key or not name or not purpose or not isinstance(assertion, dict):
            raise ValueError("验收项必须包含 stable_key、name、purpose 和 assertion")
        if not ACCEPTANCE_KEY_RE.fullmatch(stable_key):
            raise ValueError("stable_key 只能包含字母、数字、点、下划线、冒号和连字符")
        now = utc_now()
        with self.transaction() as conn:
            self._require_task(conn, task_id)
            current = conn.execute(
                """SELECT a.id, a.current_version, v.*
                   FROM acceptance_tests a
                   JOIN acceptance_test_versions v
                     ON v.acceptance_test_id=a.id AND v.version=a.current_version
                   WHERE a.task_id=? AND a.stable_key=?""",
                (task_id, stable_key),
            ).fetchone()
            enabled = bool(definition.get("enabled", True))
            blocking = bool(definition.get("blocking", True))
            confirmed = bool(definition.get("user_confirmed", actor == "user"))
            script_artifact_id = definition.get("script_artifact_id")
            if current and actor == "agent" and current["user_confirmed"]:
                raise DerivationConflictError("智能体不能修改已由用户确认的验收项")
            if actor == "user" and not enabled and not (change_reason or "").strip():
                raise ValueError("停用验收项必须填写原因")
            if current:
                acceptance_id = current["id"]
                version = int(current["current_version"]) + 1
            else:
                acceptance_id = new_id("acceptance")
                version = 1
                conn.execute(
                    """INSERT INTO acceptance_tests
                       (id, task_id, stable_key, current_version, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (acceptance_id, task_id, stable_key, version, now),
                )
            version_id = new_id("acceptance_version")
            conn.execute(
                """INSERT INTO acceptance_test_versions
                   (id, acceptance_test_id, version, name, purpose, enabled, blocking,
                    assertion_json, script_artifact_id, user_confirmed, actor,
                    change_reason, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (version_id, acceptance_id, version, name, purpose, int(enabled), int(blocking),
                 canonical_json(assertion), script_artifact_id, int(confirmed), actor,
                 change_reason, now),
            )
            conn.execute(
                "UPDATE acceptance_tests SET current_version=? WHERE id=?",
                (version, acceptance_id),
            )
            conn.execute(
                "UPDATE derivation_tasks SET updated_at=? WHERE id=?",
                (now, task_id),
            )
            result = dict(definition)
            result.update({
                "id": acceptance_id,
                "version_id": version_id,
                "version": version,
                "enabled": enabled,
                "blocking": blocking,
                "user_confirmed": confirmed,
                "actor": actor,
                "created_at": now,
            })
            self._insert_event(conn, task_id, None, "acceptance_test_versioned", result, now)
            return result

    def list_acceptance_tests(self, task_id: str) -> list[dict]:
        self.initialize()
        with self.connection() as conn:
            self._require_task(conn, task_id)
            rows = conn.execute(
                """SELECT a.id, a.stable_key, a.current_version, v.*
                   FROM acceptance_tests a
                   JOIN acceptance_test_versions v
                     ON v.acceptance_test_id=a.id AND v.version=a.current_version
                   WHERE a.task_id=? ORDER BY a.created_at, a.stable_key""",
                (task_id,),
            ).fetchall()
            output = []
            for row in rows:
                item = dict(row)
                item["assertion"] = json.loads(item.pop("assertion_json"))
                item["enabled"] = bool(item["enabled"])
                item["blocking"] = bool(item["blocking"])
                item["user_confirmed"] = bool(item["user_confirmed"])
                output.append(item)
            return output

    def acceptance_history(self, acceptance_id: str) -> list[dict]:
        self.initialize()
        with self.connection() as conn:
            rows = conn.execute(
                """SELECT * FROM acceptance_test_versions
                   WHERE acceptance_test_id=? ORDER BY version""",
                (acceptance_id,),
            ).fetchall()
            if not rows:
                raise DerivationNotFoundError(f"验收项不存在：{acceptance_id}")
            output = []
            for row in rows:
                item = dict(row)
                item["assertion"] = json.loads(item.pop("assertion_json"))
                output.append(item)
            return output

    def create_agent_run(self, task_id: str, message_id: str, model: str) -> dict:
        self.initialize()
        run_id = new_id("agent_run")
        now = utc_now()
        with self.transaction() as conn:
            self._require_task(conn, task_id)
            message = conn.execute(
                """SELECT m.id FROM agent_messages m
                   JOIN agent_threads t ON t.id=m.thread_id
                   WHERE m.id=? AND t.task_id=?""",
                (message_id, task_id),
            ).fetchone()
            if not message:
                raise DerivationConflictError("触发消息不属于当前任务")
            active = conn.execute(
                "SELECT id FROM agent_runs WHERE task_id=? AND status='running'",
                (task_id,),
            ).fetchone()
            if active:
                raise DerivationConflictError("当前任务已有智能体运行")
            conn.execute(
                """INSERT INTO agent_runs
                   (id, task_id, triggering_message_id, status, model, started_at)
                   VALUES (?, ?, ?, 'running', ?, ?)""",
                (run_id, task_id, message_id, model, now),
            )
            conn.execute(
                "UPDATE derivation_tasks SET status='running', updated_at=? WHERE id=?",
                (now, task_id),
            )
            self._insert_event(conn, task_id, message_id, "agent_run_started", {
                "run_id": run_id,
                "model": model,
            }, now)
            return {
                "id": run_id,
                "task_id": task_id,
                "triggering_message_id": message_id,
                "status": "running",
                "model": model,
                "started_at": now,
            }

    def finish_agent_run(
        self,
        run_id: str,
        *,
        status: str,
        response_id: str | None = None,
        error: str | None = None,
        task_status: str | None = None,
    ) -> None:
        if status not in {"completed", "waiting_user", "failed", "cancelled"}:
            raise ValueError("无效的智能体结束状态")
        task_status = task_status or {
            "completed": "ready",
            "waiting_user": "waiting_user",
            "failed": "infra_failed",
            "cancelled": "ready",
        }[status]
        now = utc_now()
        with self.transaction() as conn:
            run = conn.execute("SELECT task_id FROM agent_runs WHERE id=?", (run_id,)).fetchone()
            if not run:
                raise DerivationNotFoundError(f"智能体运行不存在：{run_id}")
            conn.execute(
                """UPDATE agent_runs
                   SET status=?, response_id=?, error=?, finished_at=? WHERE id=?""",
                (status, response_id, error, now, run_id),
            )
            conn.execute(
                "UPDATE derivation_tasks SET status=?, updated_at=? WHERE id=?",
                (task_status, now, run["task_id"]),
            )
            self._insert_event(conn, run["task_id"], None, "agent_run_finished", {
                "run_id": run_id,
                "status": status,
                "error": error,
            }, now)

    def input_hash(self, task_id: str) -> str:
        context = {
            "artifacts": [
                {"id": item["id"], "sha256": item["sha256"], "package_kind": item["package_kind"]}
                for item in self.list_artifacts(task_id)
            ],
            "acceptance_tests": [
                {
                    "id": item["id"],
                    "version": item["current_version"],
                    "assertion": item["assertion"],
                    "enabled": item["enabled"],
                    "blocking": item["blocking"],
                }
                for item in self.list_acceptance_tests(task_id)
            ],
            "messages": [
                {"id": item["id"], "sequence": item["sequence"], "content": item["content"]}
                for item in self.list_messages(task_id)
            ],
        }
        return hashlib.sha256(canonical_json(context).encode("utf-8")).hexdigest()

    def create_attempt(
        self, task_id: str, *, agent_run_id: str | None, input_hash: str, workspace_path: str
    ) -> dict:
        self.initialize()
        attempt_id = new_id("attempt")
        now = utc_now()
        with self.transaction() as conn:
            self._require_task(conn, task_id)
            if agent_run_id:
                owner = conn.execute(
                    "SELECT task_id FROM agent_runs WHERE id=?", (agent_run_id,)
                ).fetchone()
                if not owner or owner["task_id"] != task_id:
                    raise DerivationConflictError("智能体运行不属于当前任务")
            ordinal = conn.execute(
                "SELECT COALESCE(MAX(ordinal), 0) + 1 FROM derivation_attempts WHERE task_id=?",
                (task_id,),
            ).fetchone()[0]
            conn.execute(
                """INSERT INTO derivation_attempts
                   (id, task_id, agent_run_id, ordinal, input_hash, workspace_path,
                    status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, 'draft', ?)""",
                (attempt_id, task_id, agent_run_id, ordinal, input_hash, workspace_path, now),
            )
            conn.execute(
                "UPDATE derivation_tasks SET current_attempt_id=?, updated_at=? WHERE id=?",
                (attempt_id, now, task_id),
            )
            self._insert_event(conn, task_id, None, "attempt_created", {
                "attempt_id": attempt_id,
                "ordinal": ordinal,
                "input_hash": input_hash,
            }, now)
            return {
                "id": attempt_id,
                "task_id": task_id,
                "agent_run_id": agent_run_id,
                "ordinal": ordinal,
                "input_hash": input_hash,
                "workspace_path": workspace_path,
                "status": "draft",
                "created_at": now,
            }

    def get_attempt(self, attempt_id: str) -> dict:
        self.initialize()
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM derivation_attempts WHERE id=?", (attempt_id,)).fetchone()
            if not row:
                raise DerivationNotFoundError(f"派生 attempt 不存在：{attempt_id}")
            return dict(row)

    def list_attempts(self, task_id: str) -> list[dict]:
        self.initialize()
        with self.connection() as conn:
            self._require_task(conn, task_id)
            return [dict(row) for row in conn.execute(
                "SELECT * FROM derivation_attempts WHERE task_id=? ORDER BY ordinal DESC",
                (task_id,),
            )]

    def set_attempt_status(self, attempt_id: str, status: str, summary: str | None = None) -> None:
        if status not in {"draft", "validating", "failed", "candidate"}:
            raise ValueError("无效的 attempt 状态")
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT task_id FROM derivation_attempts WHERE id=?", (attempt_id,)
            ).fetchone()
            if not row:
                raise DerivationNotFoundError(f"派生 attempt 不存在：{attempt_id}")
            conn.execute(
                "UPDATE derivation_attempts SET status=?, summary=COALESCE(?, summary) WHERE id=?",
                (status, summary, attempt_id),
            )
            conn.execute(
                "UPDATE derivation_tasks SET updated_at=? WHERE id=?",
                (utc_now(), row["task_id"]),
            )

    def start_harness_run(self, task_id: str, attempt_id: str, workdir: str) -> dict:
        run_id = new_id("harness")
        now = utc_now()
        with self.transaction() as conn:
            attempt = conn.execute(
                "SELECT task_id FROM derivation_attempts WHERE id=?", (attempt_id,)
            ).fetchone()
            if not attempt or attempt["task_id"] != task_id:
                raise DerivationConflictError("attempt 不属于当前任务")
            conn.execute(
                """INSERT INTO harness_runs
                   (id, task_id, attempt_id, provider, status, workdir, started_at)
                   VALUES (?, ?, ?, 'local_docker', 'running', ?, ?)""",
                (run_id, task_id, attempt_id, workdir, now),
            )
            conn.execute(
                "UPDATE derivation_attempts SET status='validating' WHERE id=?", (attempt_id,)
            )
            self._insert_event(conn, task_id, None, "harness_started", {
                "run_id": run_id,
                "attempt_id": attempt_id,
                "provider": "local_docker",
            }, now)
            return {"id": run_id, "status": "running", "started_at": now}

    def finish_harness_run(
        self,
        run_id: str,
        *,
        status: str,
        results: Iterable[dict],
        image_reference: str | None = None,
        image_digest: str | None = None,
        error: str | None = None,
    ) -> dict:
        if status not in {"passed", "failed", "blocked", "cancelled"}:
            raise ValueError("无效的 Harness 状态")
        now = utc_now()
        result_list = list(results)
        with self.transaction() as conn:
            run = conn.execute(
                "SELECT task_id, attempt_id FROM harness_runs WHERE id=?", (run_id,)
            ).fetchone()
            if not run:
                raise DerivationNotFoundError(f"Harness 运行不存在：{run_id}")
            for result in result_list:
                conn.execute(
                    """INSERT INTO acceptance_results
                       (id, harness_run_id, acceptance_test_id, acceptance_test_version,
                        status, actual_json, evidence_json, failure_kind, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (new_id("acceptance_result"), run_id, result["acceptance_test_id"],
                     result["acceptance_test_version"], result["status"],
                     canonical_json(result.get("actual", {})),
                     canonical_json(result.get("evidence", [])),
                     result.get("failure_kind"), now),
                )
            conn.execute(
                """UPDATE harness_runs
                   SET status=?, image_reference=?, image_digest=?, error=?, finished_at=? WHERE id=?""",
                (status, image_reference, image_digest, error, now, run_id),
            )
            attempt_status = "candidate" if status == "passed" else "failed"
            conn.execute(
                "UPDATE derivation_attempts SET status=? WHERE id=?",
                (attempt_status, run["attempt_id"]),
            )
            unconfirmed = conn.execute(
                """SELECT COUNT(*) FROM acceptance_tests a
                   JOIN acceptance_test_versions v
                     ON v.acceptance_test_id=a.id AND v.version=a.current_version
                   WHERE a.task_id=? AND v.enabled=1 AND v.user_confirmed=0""",
                (run["task_id"],),
            ).fetchone()[0]
            task_status = (
                "waiting_user" if status == "passed" and unconfirmed else
                "candidate_review" if status == "passed" else
                "infra_failed" if status == "blocked" else "validation_failed"
            )
            conn.execute(
                "UPDATE derivation_tasks SET status=?, updated_at=? WHERE id=?",
                (task_status, now, run["task_id"]),
            )
            self._insert_event(conn, run["task_id"], None, "harness_finished", {
                "run_id": run_id,
                "status": status,
                "result_count": len(result_list),
                "unconfirmed_acceptance_count": unconfirmed,
                "error": error,
            }, now)
            return self._get_harness_run(conn, run_id)

    def get_harness_run(self, run_id: str) -> dict:
        self.initialize()
        with self.connection() as conn:
            return self._get_harness_run(conn, run_id)

    def _get_harness_run(self, conn: sqlite3.Connection, run_id: str) -> dict:
        row = conn.execute("SELECT * FROM harness_runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            raise DerivationNotFoundError(f"Harness 运行不存在：{run_id}")
        result = dict(row)
        result["results"] = []
        for value in conn.execute(
            "SELECT * FROM acceptance_results WHERE harness_run_id=? ORDER BY created_at, id",
            (run_id,),
        ):
            item = dict(value)
            item["actual"] = json.loads(item.pop("actual_json"))
            item["evidence"] = json.loads(item.pop("evidence_json"))
            result["results"].append(item)
        return result

    def list_harness_runs(self, task_id: str) -> list[dict]:
        self.initialize()
        with self.connection() as conn:
            self._require_task(conn, task_id)
            return [dict(row) for row in conn.execute(
                "SELECT * FROM harness_runs WHERE task_id=? ORDER BY started_at DESC",
                (task_id,),
            )]

    def create_capability_package(
        self,
        *,
        task_id: str,
        attempt_id: str,
        asset_type: str,
        package_path: str,
        image_reference: str,
        image_digest: str,
        manifest: dict,
    ) -> dict:
        capability_id = new_id("capability")
        capability_key = str(manifest.get("capability_id", "")).strip()
        if not capability_key:
            raise ValueError("能力包缺少 capability_id")
        now = utc_now()
        with self.transaction() as conn:
            attempt = conn.execute(
                "SELECT task_id, status FROM derivation_attempts WHERE id=?", (attempt_id,)
            ).fetchone()
            if not attempt or attempt["task_id"] != task_id:
                raise DerivationConflictError("attempt 不属于当前任务")
            if attempt["status"] != "candidate":
                raise DerivationConflictError("只有通过 Harness 的 attempt 可以形成候选能力包")
            harness = conn.execute(
                """SELECT id FROM harness_runs
                   WHERE attempt_id=? AND status='passed'
                   ORDER BY finished_at DESC LIMIT 1""",
                (attempt_id,),
            ).fetchone()
            if not harness:
                raise DerivationConflictError("候选能力包缺少通过的 Harness 运行")
            unconfirmed = conn.execute(
                """SELECT COUNT(*) FROM acceptance_tests a
                   JOIN acceptance_test_versions v
                     ON v.acceptance_test_id=a.id AND v.version=a.current_version
                   WHERE a.task_id=? AND v.enabled=1 AND v.user_confirmed=0""",
                (task_id,),
            ).fetchone()[0]
            if unconfirmed:
                raise DerivationConflictError("所有启用的验收项经用户确认后才能提交候选审核")
            capability_version = conn.execute(
                """SELECT COALESCE(MAX(version), 0) + 1 FROM capability_packages
                   WHERE asset_type=? AND capability_key=?""",
                (asset_type, capability_key),
            ).fetchone()[0]
            task_version = conn.execute(
                "SELECT COALESCE(MAX(version), 0) + 1 FROM capability_packages WHERE task_id=?",
                (task_id,),
            ).fetchone()[0]
            version = max(capability_version, task_version)
            conn.execute(
                """INSERT INTO capability_packages
                   (id, task_id, attempt_id, version, asset_type, capability_key,
                    status, package_path,
                    image_reference, image_digest, manifest_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, 'candidate', ?, ?, ?, ?, ?)""",
                (capability_id, task_id, attempt_id, version, asset_type, capability_key,
                 package_path,
                 image_reference, image_digest, canonical_json(manifest), now),
            )
            for test in manifest.get("project_tests", []):
                conn.execute(
                    """INSERT INTO project_tests
                       (id, capability_package_id, stable_key, name, description,
                        version, definition_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (new_id("project_test"), capability_id, test["test_id"], test["name"],
                     test["description"], int(test.get("version", 1)), canonical_json(test), now),
                )
            for rule in manifest.get("vulnerability_rules", []):
                conn.execute(
                    """INSERT INTO vulnerability_rules
                       (id, capability_package_id, vulnerability_id, rule_json, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (new_id("vulnerability_rule"), capability_id, rule["vulnerability_id"],
                     canonical_json(rule), now),
                )
            conn.execute(
                """UPDATE derivation_tasks
                   SET current_capability_id=?, status='candidate_review', updated_at=? WHERE id=?""",
                (capability_id, now, task_id),
            )
            self._insert_event(conn, task_id, None, "candidate_registered", {
                "capability_id": capability_id,
                "asset_type": asset_type,
                "version": version,
                "harness_run_id": harness["id"],
            }, now)
            return self._get_capability(conn, capability_id)

    def get_capability(self, capability_id: str) -> dict:
        self.initialize()
        with self.connection() as conn:
            return self._get_capability(conn, capability_id)

    def _get_capability(self, conn: sqlite3.Connection, capability_id: str) -> dict:
        row = conn.execute(
            "SELECT * FROM capability_packages WHERE id=?", (capability_id,)
        ).fetchone()
        if not row:
            raise DerivationNotFoundError(f"能力包不存在：{capability_id}")
        item = dict(row)
        item["manifest"] = json.loads(item.pop("manifest_json"))
        item["project_tests"] = [
            json.loads(value["definition_json"])
            for value in conn.execute(
                "SELECT definition_json FROM project_tests WHERE capability_package_id=? ORDER BY stable_key",
                (capability_id,),
            )
        ]
        item["vulnerability_rules"] = [
            json.loads(value["rule_json"])
            for value in conn.execute(
                "SELECT rule_json FROM vulnerability_rules WHERE capability_package_id=? ORDER BY vulnerability_id",
                (capability_id,),
            )
        ]
        return item

    def list_capabilities(self, task_id: str | None = None) -> list[dict]:
        self.initialize()
        with self.connection() as conn:
            if task_id:
                self._require_task(conn, task_id)
                rows = conn.execute(
                    "SELECT * FROM capability_packages WHERE task_id=? ORDER BY version DESC",
                    (task_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM capability_packages ORDER BY created_at DESC"
                ).fetchall()
            output = []
            for row in rows:
                item = dict(row)
                item["manifest"] = json.loads(item.pop("manifest_json"))
                output.append(item)
            return output

    def review_capability(
        self,
        capability_id: str,
        *,
        approve: bool,
        note: str | None,
        package_path: str | None = None,
        manifest: dict | None = None,
    ) -> dict:
        now = utc_now()
        with self.transaction() as conn:
            current = conn.execute(
                """SELECT task_id, asset_type, capability_key, status
                   FROM capability_packages WHERE id=?""",
                (capability_id,),
            ).fetchone()
            if not current:
                raise DerivationNotFoundError(f"能力包不存在：{capability_id}")
            if current["status"] != "candidate":
                raise DerivationConflictError("只有候选能力包可以审核")
            status = "admitted" if approve else "rejected"
            if approve:
                conn.execute(
                    """UPDATE capability_packages SET status='superseded', reviewed_at=?
                       WHERE asset_type=? AND capability_key=? AND status='admitted'""",
                    (now, current["asset_type"], current["capability_key"]),
                )
            conn.execute(
                """UPDATE capability_packages
                   SET status=?, review_note=?, reviewed_at=?,
                       package_path=COALESCE(?, package_path),
                       manifest_json=COALESCE(?, manifest_json)
                   WHERE id=?""",
                (status, note, now, package_path,
                 canonical_json(manifest) if manifest is not None else None,
                 capability_id),
            )
            conn.execute(
                """UPDATE derivation_tasks SET status=?, updated_at=? WHERE id=?""",
                ("admitted" if approve else "waiting_user", now, current["task_id"]),
            )
            self._insert_event(conn, current["task_id"], None, "capability_reviewed", {
                "capability_id": capability_id,
                "status": status,
                "note": note,
            }, now)
            return self._get_capability(conn, capability_id)

    @staticmethod
    def _require_task(conn: sqlite3.Connection, task_id: str) -> None:
        if not conn.execute("SELECT 1 FROM derivation_tasks WHERE id=?", (task_id,)).fetchone():
            raise DerivationNotFoundError(f"派生任务不存在：{task_id}")
