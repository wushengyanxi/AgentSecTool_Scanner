from __future__ import annotations

import json
import threading
from collections.abc import Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None

from agentsectool_scanner.agent_runtime.trace.events import EventType, Outcome, Stage, TraceEvent


class TraceSink:
    """把 ``TraceEvent`` 按 JSONL 格式写入本次运行的 trace 文件。

    每个 sink 绑定一个 ``run_id``、一个 ``task_id`` 和一个 trace 目录。
    ``emit`` 在锁内完成 seq 分配与落盘，避免并发写入时出现重号或行交错。
    """

    def __init__(self, *, run_id: str, task_id: str, trace_dir: str | Path) -> None:
        """初始化 trace sink。

        :param run_id: 本次运行标识。
        :param task_id: 本次分析任务标识。
        :param trace_dir: JSONL trace 文件所在目录。
        """

        self.run_id = _normalize_run_id(run_id)
        self.task_id = _normalize_task_id(task_id)
        self.trace_dir = Path(trace_dir)
        self.path = self.trace_dir / f"{self.run_id}.jsonl"
        self._lock_path = self.trace_dir / f".{self.run_id}.lock"
        self._lock = threading.Lock()

        self.trace_dir.mkdir(parents=True, exist_ok=True)
        self._next_seq = self._load_next_seq()

    def emit(
        self,
        *,
        stage: Stage,
        type: EventType,
        payload: dict[str, Any],
        parents: Sequence[str] | None = None,
        refs: Sequence[str] | None = None,
        outcome: Outcome | None = None,
    ) -> TraceEvent:
        """生成事件 id 与 seq，并将事件追加写入 JSONL 文件。

        :param stage: 事件所属分析阶段。
        :param type: 事件类型。
        :param payload: 与事件类型相关的结构化内容。
        :param parents: 因果前驱事件 id 列表；为 ``None`` 时表示根事件。
        :param refs: 语义关联事件 id 列表；为 ``None`` 时表示无语义关联。
        :param outcome: 运行终止结果，仅 ``run_exit`` 事件可使用。
        :return: 已写入文件的完整 ``TraceEvent``。
        :raises pydantic.ValidationError: 当事件字段不符合 ``TraceEvent`` 约束时抛出。
        """

        with self._lock:
            with self._interprocess_lock():
                seq = max(self._next_seq, self._load_next_seq())
                event = TraceEvent(
                    id=self._event_id(seq),
                    seq=seq,
                    parents=_normalize_reference_list(parents, "parents"),
                    ts=_utc_timestamp_ms(),
                    run_id=self.run_id,
                    task_id=self.task_id,
                    stage=stage,
                    type=type,
                    outcome=outcome,
                    payload=payload,
                    refs=_normalize_reference_list(refs, "refs"),
                )

                self._append_event(event)
                self._next_seq = seq + 1
                return event

    def _event_id(self, seq: int) -> str:
        """根据 run id 与 seq 生成事件 id。

        :param seq: 已分配的 run 内逻辑序号。
        :return: 可被 ``parents`` 和 ``refs`` 引用的事件 id。
        """

        return f"{self.run_id}:{seq}"

    def _append_event(self, event: TraceEvent) -> None:
        """将单个事件序列化成一行 JSON 并追加写盘。

        :param event: 已通过 pydantic 校验的 trace 事件。
        """

        line = json.dumps(event.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":"))
        with self.path.open("a", encoding="utf-8") as file:
            file.write(f"{line}\n")

    @contextmanager
    def _interprocess_lock(self):
        """Serialize sequence allocation across concurrent trace writers."""

        if fcntl is None:
            yield
            return

        self.trace_dir.mkdir(parents=True, exist_ok=True)
        with self._lock_path.open("a", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _load_next_seq(self) -> int:
        """从既有 trace 文件推导下一条事件应使用的 seq。

        :return: 既有最大 seq 加一；文件不存在或为空时返回 0。
        """

        if not self.path.exists():
            return 0

        sequences = [
            event.seq for event in read_trace(run_id=self.run_id, trace_dir=self.trace_dir)
        ]
        return max(sequences, default=-1) + 1


def read_trace(*, run_id: str, trace_dir: str | Path) -> list[TraceEvent]:
    """读取指定 run 的 JSONL trace 文件。

    :param run_id: 待读取的运行标识。
    :param trace_dir: JSONL trace 文件所在目录。
    :return: 按文件行顺序解析出的 ``TraceEvent`` 列表。
    :raises FileNotFoundError: 当 trace 文件不存在时抛出。
    :raises json.JSONDecodeError: 当某行不是合法 JSON 时抛出。
    :raises pydantic.ValidationError: 当某行 JSON 不符合 ``TraceEvent`` schema 时抛出。
    """

    normalized_run_id = _normalize_run_id(run_id)
    path = Path(trace_dir) / f"{normalized_run_id}.jsonl"
    events: list[TraceEvent] = []
    with path.open(encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue
            events.append(TraceEvent(**json.loads(line)))
    return events


def _utc_timestamp_ms() -> str:
    """生成 ISO-8601 毫秒精度 UTC 时间戳。

    :return: 形如 ``2026-06-01T12:00:00.000+00:00`` 的时间戳。
    """

    return datetime.now(UTC).isoformat(timespec="milliseconds")


def _normalize_run_id(run_id: str) -> str:
    """校验 run id 可安全用作 trace 文件名。

    :param run_id: 外部传入的运行标识。
    :return: 去除首尾空白后的 run id。
    :raises ValueError: 当 run id 为空或包含路径语义时抛出。
    """

    normalized = run_id.strip()
    if not normalized:
        raise ValueError("run_id must not be empty")
    if "/" in normalized or "\\" in normalized or normalized.endswith(".jsonl"):
        raise ValueError("run_id must be a flat name without path separators or .jsonl suffix")
    return normalized


def _normalize_task_id(task_id: str) -> str:
    """校验 task id 不为空。

    :param task_id: 外部传入的任务标识。
    :return: 去除首尾空白后的 task id。
    :raises ValueError: 当 task id 为空时抛出。
    """

    normalized = task_id.strip()
    if not normalized:
        raise ValueError("task_id must not be empty")
    return normalized


def _normalize_reference_list(value: Sequence[str] | None, field_name: str) -> list[str]:
    """把可选引用序列规范化为列表。

    :param value: ``parents`` 或 ``refs`` 的调用方输入。
    :param field_name: 字段名，用于错误消息。
    :return: 引用 id 列表；输入为 ``None`` 时返回空列表。
    :raises TypeError: 当调用方误传单个字符串时抛出。
    """

    if value is None:
        return []
    if isinstance(value, str):
        raise TypeError(f"{field_name} must be a sequence of ids, not a single string")
    return list(value)
