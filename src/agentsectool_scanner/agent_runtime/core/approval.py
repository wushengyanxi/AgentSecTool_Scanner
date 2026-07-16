from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ApprovalChoice = Literal["accept", "acceptForSession", "decline", "cancel"]
ApprovalKind = Literal["command", "file_change", "network", "unknown"]


class ApprovalRequest(BaseModel):
    """A native Codex approval request rendered by the local terminal UI."""

    model_config = ConfigDict(extra="forbid")

    method: str
    kind: ApprovalKind
    thread_id: str | None = None
    turn_id: str | None = None
    item_id: str | None = None
    reason: str | None = None
    command: str | None = None
    cwd: str | None = None
    grant_root: str | None = None
    network_context: dict[str, Any] | None = None
    available_decisions: list[str] = Field(default_factory=list)


class ApprovalDecision(BaseModel):
    """The app-server decision returned for one native approval request."""

    model_config = ConfigDict(extra="forbid")

    decision: ApprovalChoice
    reason: str


ApprovalCallback = Callable[[ApprovalRequest], ApprovalDecision]
