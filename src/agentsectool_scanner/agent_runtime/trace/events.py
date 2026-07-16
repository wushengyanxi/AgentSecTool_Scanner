from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

Stage = Literal["P0", "P1", "P2", "P3", "P4", "core", "obs"]
Outcome = Literal["ok", "error", "killed"]
EventType = Literal[
    "task_input",
    "scope_decision",
    "plan_fork",
    "discovery_probe",
    "asset_record",
    "fingerprint_result",
    "llm_request_hash",
    "llm_request",
    "llm_response",
    "llm_stream_event",
    "runtime_metadata",
    "parsed_tool_call",
    "tool_call_start",
    "policy_decision",
    "approval_event",
    "sandbox_exec",
    "skill_summary",
    "tool_result",
    "check_run",
    "finding",
    "path_join",
    "credential_assert",
    "report_section",
    "run_exit",
    "ui_output",
]


class TraceEvent(BaseModel):
    """一次智能体运行中的结构化 trace 事件。

    事件字段对齐开发文档中的 trace schema。``seq`` 表达 run 内逻辑顺序，
    ``parents`` 表达因果前驱，``ts`` 只用于展示和跨 run 对齐，不用于排序。
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    seq: int
    parents: list[str]
    ts: str
    run_id: str
    task_id: str
    stage: Stage
    type: EventType
    outcome: Outcome | None
    payload: dict[str, Any]
    refs: list[str]

    @field_validator("id", "ts", "run_id", "task_id")
    @classmethod
    def require_non_empty_text(cls, value: str) -> str:
        """校验 trace 事件的基础文本字段不为空。

        :param value: 待校验的文本字段值。
        :return: 去除首尾空白后的字段值。
        :raises ValueError: 当字段为空字符串时抛出。
        """

        normalized = value.strip()
        if not normalized:
            raise ValueError("field must not be empty")
        return normalized

    @field_validator("seq")
    @classmethod
    def require_non_negative_seq(cls, value: int) -> int:
        """校验 run 内逻辑序号不为负数。

        :param value: 待校验的 ``seq`` 值。
        :return: 原始 ``seq`` 值。
        :raises ValueError: 当 ``seq`` 为负数时抛出。
        """

        if value < 0:
            raise ValueError("seq must be non-negative")
        return value

    @field_validator("parents", "refs")
    @classmethod
    def require_non_empty_refs(cls, value: list[str]) -> list[str]:
        """校验引用列表中不含空字符串。

        :param value: ``parents`` 或 ``refs`` 字段值。
        :return: 去除每项首尾空白后的列表。
        :raises ValueError: 当列表中包含空字符串时抛出。
        """

        normalized = [item.strip() for item in value]
        if any(not item for item in normalized):
            raise ValueError("reference ids must not be empty")
        return normalized

    @model_validator(mode="after")
    def validate_outcome_scope(self) -> "TraceEvent":
        """校验 ``outcome`` 只出现在运行终止事件上。

        :return: 校验通过后的事件对象自身。
        :raises ValueError: 当 ``run_exit`` 缺少 outcome，或非终止事件携带 outcome 时抛出。
        """

        if self.type == "run_exit" and self.outcome is None:
            raise ValueError("run_exit event requires outcome")
        if self.type != "run_exit" and self.outcome is not None:
            raise ValueError("only run_exit event can carry outcome")
        return self
