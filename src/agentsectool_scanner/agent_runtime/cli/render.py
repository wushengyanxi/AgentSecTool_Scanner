from __future__ import annotations

import json
import sys
from typing import TextIO

from agentsectool_scanner.agent_runtime.config import CliConfig
from agentsectool_scanner.agent_runtime.core import LoopProgressEvent

CliRenderSettings = CliConfig


class CliProgressRenderer:
    """把 loop 进展事件渲染成终端文本。"""

    def __init__(
        self,
        stream: TextIO | None = None,
        *,
        settings: CliRenderSettings | None = None,
    ) -> None:
        """初始化渲染器。"""

        self._stream = stream or sys.stderr
        self._settings = settings or CliConfig()
        self._color_enabled = _should_use_color(self._settings.color_mode, self._stream)
        self._open_text_line = False
        self._model_text_seen = False

    @property
    def model_text_seen(self) -> bool:
        """本次渲染是否已经显示过模型文本。"""

        return self._model_text_seen

    def handle_event(self, event: LoopProgressEvent) -> None:
        """消费一条 loop 进展事件。"""

        if event.type == "model_text_delta":
            if event.text:
                self._model_text_seen = True
            self._write(self._style("model", event.text or ""))
            self._open_text_line = not (event.text or "").endswith("\n")
            return

        if event.type == "tool_call_delta":
            return

        if event.type == "tool_call_start":
            self._render_tool_start(event)
            return

        if event.type == "tool_call_finish":
            self._render_tool_finish(event)
            return

        if event.type == "run_exit":
            self._render_run_exit(event)

    def finish(self) -> None:
        """结束渲染，补齐悬空的文本行。"""

        if self._open_text_line:
            self._write("\n")
            self._open_text_line = False
        self._stream.flush()

    def _render_tool_start(self, event: LoopProgressEvent) -> None:
        """渲染工具开始事件。"""

        self._ensure_newline()
        label = self._style("tool", "[tool start]")
        line = f"{label} {event.tool_name or 'unknown'}"
        if event.call_id:
            line += f" {self._style('muted', event.call_id)}"
        if self._settings.show_tool_arguments and event.arguments:
            line += f" {self._style('muted', _compact_json(event.arguments))}"
        if event.display:
            line += f" {self._style('muted', event.display)}"
        self._write(line + "\n")

    def _render_tool_finish(self, event: LoopProgressEvent) -> None:
        """渲染工具完成事件。"""

        self._ensure_newline()
        summary = self._summarize_result(event.result)
        is_error = summary.startswith("error:")
        label = self._style("error" if is_error else "result", "[tool done]")
        line = f"{label} {event.tool_name or 'unknown'}"
        if event.call_id:
            line += f" {self._style('muted', event.call_id)}"
        if summary:
            line += f" {summary}"
        self._write(line + "\n")

    def _render_run_exit(self, event: LoopProgressEvent) -> None:
        """渲染运行结束事件。"""

        self._ensure_newline()
        color = "result" if event.outcome == "ok" else "error"
        label = self._style(color, "[run]")
        reason = f" reason={event.reason}" if event.reason else ""
        self._write(f"{label} outcome={event.outcome}{reason}\n")

    def _summarize_result(self, result: object) -> str:
        """生成单行工具结果摘要。"""

        if not isinstance(result, dict):
            return self._truncate(_compact_json(result))

        payload = result.get("result")
        if isinstance(payload, dict):
            error = payload.get("error")
            if isinstance(error, str):
                return self._truncate(f"error: {error}")
            if payload.get("type") == "commandExecution":
                return self._summarize_command_result(payload)
            parts = [
                f"{key}={value}"
                for key, value in payload.items()
                if isinstance(value, str | int | float | bool)
            ]
            return self._truncate(", ".join(parts) or _compact_json(payload))

        return self._truncate(_compact_json(payload))

    def _summarize_command_result(self, payload: dict[str, object]) -> str:
        """生成通用命令执行摘要。"""

        parts = [f"exit_code={payload.get('exitCode')}"]
        status = payload.get("status")
        if isinstance(status, str) and status:
            parts.append(f"status={status}")
        output = payload.get("aggregatedOutput")
        if isinstance(output, str) and output.strip():
            parts.append("output=" + _single_line(output.strip()))
        return self._truncate(", ".join(parts))

    def _truncate(self, text: str) -> str:
        """按配置截断过长摘要。"""

        max_chars = self._settings.max_result_chars
        if len(text) <= max_chars:
            return text
        return text[: max_chars - 1] + "..."

    def _ensure_newline(self) -> None:
        """确保后续状态行不会贴在模型文本后面。"""

        if self._open_text_line:
            self._write("\n")
            self._open_text_line = False

    def _style(self, name: str, text: str) -> str:
        """按设置应用 ANSI 样式。"""

        if not self._color_enabled:
            return text
        code = self._settings.colors.get(name)
        reset = self._settings.colors.get("reset", "0")
        if not code:
            return text
        return f"\033[{code}m{text}\033[{reset}m"

    def _write(self, text: str) -> None:
        """写入终端流。"""

        self._stream.write(text)
        self._stream.flush()


def _should_use_color(color_mode: str, stream: TextIO) -> bool:
    """判断当前输出流是否应该使用 ANSI 颜色。"""

    if color_mode == "always":
        return True
    if color_mode == "never":
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def _compact_json(value: object) -> str:
    """生成紧凑 JSON 文本。"""

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _single_line(text: str) -> str:
    """把多行输出压缩成终端摘要中的单行。"""

    return " ".join(text.split())
