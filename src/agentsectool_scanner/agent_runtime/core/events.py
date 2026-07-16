from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

LoopOutcome = Literal["ok", "error", "killed"]
LoopProgressEventType = Literal[
    "model_text_delta",
    "tool_call_delta",
    "tool_call_start",
    "tool_call_finish",
    "run_exit",
]


class RunResult(BaseModel):
    """一次 SDK agent 运行的终止结果。"""

    model_config = ConfigDict(extra="forbid")

    outcome: LoopOutcome
    steps: int

    @field_validator("steps")
    @classmethod
    def require_non_negative_steps(cls, value: int) -> int:
        """校验运行步数不为负数。"""

        if value < 0:
            raise ValueError("steps must be non-negative")
        return value


class LoopProgressEvent(BaseModel):
    """给 CLI 渲染层消费的运行进展事件；不写入 trace。"""

    model_config = ConfigDict(extra="forbid")

    type: LoopProgressEventType
    step: int | None = None
    text: str | None = None
    tool_name: str | None = None
    call_id: str | None = None
    arguments_delta: str | None = None
    arguments: dict[str, Any] | None = None
    display: str | None = None
    result: Any | None = None
    outcome: LoopOutcome | None = None
    reason: str | None = None
