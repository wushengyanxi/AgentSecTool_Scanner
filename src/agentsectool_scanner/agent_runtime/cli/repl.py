from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Protocol, TextIO

from agentsectool_scanner.agent_runtime.config import Config

AgentExecutor = Callable[[Config, str, TextIO, TextIO], None]


class ReplExit(Exception):
    """交互式 CLI 正常退出信号。"""


class PromptSessionLike(Protocol):
    """交互式输入 session 的最小协议。"""

    def prompt(self, message: str) -> str:
        """读取一行带行编辑能力的输入。"""


def run_agent_repl(
    cfg: Config,
    execute: AgentExecutor,
    *,
    input_stream: TextIO | None = None,
    output_stream: TextIO | None = None,
) -> int:
    """运行交互式智能体 CLI。"""

    active_cfg = cfg
    stdin = input_stream or sys.stdin
    stdout = output_stream or sys.stdout
    interactive = _is_tty(stdin)
    prompt_session = _create_prompt_session() if _should_use_prompt_session(stdin, stdout) else None

    if interactive:
        stdout.write("sec agent CLI. Type /help for commands, /exit to quit.\n")
        stdout.flush()

    while True:
        prompt = f"sec[{active_cfg.active_model}]> "
        if interactive:
            line = _read_repl_line(
                stdin,
                stdout,
                prompt,
                interactive=True,
                prompt_session=prompt_session,
            )
        else:
            line = _read_repl_line(stdin, stdout, prompt, interactive=False)

        if line is None:
            return 0

        text = line.strip()
        if not text:
            continue

        if text.startswith("/"):
            try:
                active_cfg = _handle_command(text, active_cfg, stdout)
            except ReplExit:
                return 0
            continue

        execute(active_cfg.model_copy(update={"run_id": None}), text, stdin, stdout)


def _handle_command(command: str, cfg: Config, stdout: TextIO) -> Config:
    """处理一条 slash command。"""

    parts = command.split()
    name = parts[0].lower()

    if name in {"/exit", "/quit"}:
        raise ReplExit

    if name == "/help":
        stdout.write("Commands: /exit\n")
        stdout.flush()
        return cfg

    stdout.write(f"unknown command: {name}\n")
    stdout.flush()
    return cfg
def _is_tty(stream: TextIO) -> bool:
    """判断输入流是否为交互式终端。"""

    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def _read_repl_line(
    stdin: TextIO,
    stdout: TextIO,
    prompt: str,
    *,
    interactive: bool,
    prompt_session: PromptSessionLike | None = None,
) -> str | None:
    """读取一行 REPL 输入。

    真实交互式终端使用 prompt_toolkit，让它按字符显示宽度重绘输入行；
    管道、文件和测试注入流继续使用 ``readline``，避免向非交互输出写 prompt。
    """

    if interactive and prompt_session is not None:
        try:
            return prompt_session.prompt(prompt)
        except EOFError:
            return None
        except KeyboardInterrupt:
            return ""

    if interactive:
        stdout.write(prompt)
        stdout.flush()

    line = stdin.readline()
    if line == "":
        return None
    return line


def _should_use_prompt_session(stdin: TextIO, stdout: TextIO) -> bool:
    """真实终端流才启用 prompt_toolkit。"""

    return stdin is sys.stdin and stdout is sys.stdout and _is_tty(stdin)


def _create_prompt_session() -> PromptSessionLike:
    """创建支持宽字符重绘的 prompt_toolkit session。"""

    from prompt_toolkit import PromptSession

    return PromptSession()
