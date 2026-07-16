"""运行时入口。"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Sequence, TextIO

from pydantic import ValidationError

from agentsectool_scanner.agent_runtime.cli.render import CliProgressRenderer
from agentsectool_scanner.agent_runtime.cli.repl import run_agent_repl
from agentsectool_scanner.agent_runtime.codex_runtime import run_codex
from agentsectool_scanner.agent_runtime.config import CONFIG_ENV_VAR, Config, ConfigNotFound, load_config
from agentsectool_scanner.agent_runtime.core import (
    ApprovalCallback,
    ApprovalDecision,
    ApprovalRequest,
    LoopProgressEvent,
    RunResult,
)
from agentsectool_scanner.agent_runtime.doctor import evaluate_live_trace, run_static_checks
from agentsectool_scanner.agent_runtime.render import write_behavior_graph_html
from agentsectool_scanner.agent_runtime.trace import TraceEvent, TraceSink, read_trace

_ANSI_ESCAPE_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def generate_run_id() -> str:
    """生成带时间戳和随机后缀的运行标识。

    :return: 形如 ``YYYYMMDD-HHMMSS-<6位随机hex>`` 的 run id。
    """

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    suffix = secrets.token_hex(3)
    return f"{stamp}-{suffix}"


def with_run_id(cfg: Config, explicit_run_id: str | None = None) -> Config:
    """确保配置对象带有 run id。

    :param cfg: 从 TOML 加载得到的配置对象。
    :param explicit_run_id: CLI 显式传入的 run id；优先级高于配置中的 run id。
    :return: 原配置或注入自动生成 run id 后的新配置对象。
    """

    if explicit_run_id is not None:
        return cfg.model_copy(update={"run_id": explicit_run_id})
    if cfg.run_id is not None:
        return cfg
    return cfg.model_copy(update={"run_id": generate_run_id()})


def run(
    config: Config,
    raw_text: str,
    *,
    progress_callback: Callable[[LoopProgressEvent], None] | None = None,
    approval_callback: ApprovalCallback | None = None,
    thread_id: str | None = None,
    dangerously_bypass: bool = False,
) -> RunResult:
    """把配置、trace sink 和 Codex SDK 装配成一次运行。

    :param config: 已加载并校验的运行配置。
    :param raw_text: 用户输入的自然语言指令。
    :param progress_callback: 可选 CLI 进展回调；不影响 trace。
    :param approval_callback: Codex 权限提升请求的可选批准回调。
    :param thread_id: 可继续执行的 Codex thread id。
    :param dangerously_bypass: 是否取消容器内审批与 Codex 沙箱限制。
    :return: SDK 运行结果。
    """

    cfg = with_run_id(config)
    run_id = cfg.run_id
    if run_id is None:
        raise RuntimeError("run_id was not initialized")

    sink = TraceSink(run_id=run_id, task_id=cfg.task_id, trace_dir=cfg.trace_dir)
    return run_codex(
        cfg,
        raw_text,
        sink=sink,
        progress_callback=progress_callback,
        approval_callback=approval_callback,
        thread_id=thread_id,
        dangerously_bypass=dangerously_bypass,
    )


def masked_config_dump(cfg: Config) -> dict[str, object]:
    """生成可安全打印的配置字典。

    :param cfg: 已生效的运行配置。
    :return: 可序列化为 JSON 的配置字典；真实 key 字段会被 ``***`` 替换。
    """

    data = cfg.model_dump(mode="json")
    return _mask_secret_fields(data)


def _mask_secret_fields(value: object) -> object:
    """递归遮蔽可能承载真实密钥的字段。"""

    if isinstance(value, dict):
        masked: dict[str, object] = {}
        for field, item in value.items():
            if "key" in field.lower():
                masked[field] = "***"
            else:
                masked[field] = _mask_secret_fields(item)
        return masked
    if isinstance(value, list):
        return [_mask_secret_fields(item) for item in value]
    return value


def build_parser(prog: str = "scanner-agent") -> argparse.ArgumentParser:
    """构建命令行解析器。

    :param prog: argparse 显示的程序名。
    :return: 支持 ``--config`` 与发现工具子命令的 argparse 解析器。
    """

    parser = argparse.ArgumentParser(prog=prog)
    parser.add_argument(
        "--config",
        default=None,
        help=(
            "配置文件路径；未指定时优先读取 "
            f"{CONFIG_ENV_VAR}，其次读取 config/agent-runtime.toml，"
            "否则使用 config/agent-runtime.example.toml"
        ),
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="显式指定本次运行的 run id；未指定时自动生成",
    )
    parser.add_argument(
        "--dangerously-bypass",
        action="store_true",
        help="取消 Codex 容器内审批和内层沙箱；外层容器限制保持生效",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("repl", help="启动交互式智能体 CLI")

    run_parser = subparsers.add_parser("run", help="执行一条自然语言任务")
    run_parser.add_argument(
        "--stream",
        action="store_true",
        help="实时把模型文本和工具进展渲染到 stderr；stdout 仍输出最终 JSON",
    )
    run_parser.add_argument("raw_text", help="要交给智能体执行的自然语言指令")

    render_parser = subparsers.add_parser("render", help="把一次运行 trace 渲染成行为图 HTML")
    render_parser.add_argument("trace_run_id", help="要渲染的 run id")
    render_parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="HTML 输出路径；未指定时写入 trace_dir/<run_id>.html",
    )

    doctor_parser = subparsers.add_parser("doctor", help="检查 Codex 运行时和模型协议")
    doctor_parser.add_argument(
        "--live",
        action="store_true",
        help="执行两个真实模型 turn，验证流式响应、连续工具调用和 thread 续接",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    default_repl: bool = False,
    prog: str = "scanner-agent",
    input_stream: TextIO | None = None,
    output_stream: TextIO | None = None,
) -> int:
    """加载配置文件，并按命令执行当前入口行为。

    :param argv: 命令行参数序列；为 ``None`` 时由 argparse 使用系统参数。
    :param default_repl: 无子命令时是否进入交互式智能体 CLI。
    :param prog: argparse 显示的程序名。
    :param input_stream: 交互式 CLI 输入流；测试可注入。
    :param output_stream: 交互式 CLI 输出流；测试可注入。
    :return: 进程退出码。正常执行返回 0，参数或配置错误由 argparse 退出。
    """

    parser = build_parser(prog)
    args = parser.parse_args(argv)

    try:
        cfg = with_run_id(load_config(args.config), args.run_id)
    except ConfigNotFound as exc:
        parser.exit(2, f"{exc}\n")
    except ValidationError as exc:
        parser.exit(2, f"配置校验失败：{exc}\n")

    if args.run_id is not None and (
        args.command == "repl" or (args.command is None and default_repl)
    ):
        parser.error("--run-id cannot be used with an interactive session")

    if args.command == "repl":
        return run_repl_command(
            cfg,
            input_stream=input_stream,
            output_stream=output_stream,
            dangerously_bypass=args.dangerously_bypass,
        )

    if args.command == "run":
        renderer = CliProgressRenderer(settings=cfg.cli) if args.stream else None
        approval_callback = (
            _approval_callback(sys.stdin, sys.stderr)
            if not args.dangerously_bypass and _is_tty(sys.stdin)
            else None
        )
        try:
            result = run(
                cfg,
                args.raw_text,
                progress_callback=renderer.handle_event if renderer else None,
                approval_callback=approval_callback,
                dangerously_bypass=args.dangerously_bypass,
            )
        except RuntimeError as exc:
            parser.exit(2, f"{exc}\n")
        if renderer is not None:
            renderer.finish()
        output = run_output(cfg, result)
        output_text = json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True)
        _emit_ui_output(
            cfg,
            interface="run",
            text=output_text + "\n",
            source="json",
            final_text=(
                output.get("final_text") if isinstance(output.get("final_text"), str) else None
            ),
            trace_path=str(output["trace_path"]),
        )
        print(output_text)
        return 0 if result.outcome == "ok" else 1

    if args.command == "render":
        try:
            output = render_trace_command(args, cfg)
        except (FileNotFoundError, RuntimeError, ValueError) as exc:
            parser.exit(2, f"{exc}\n")
        print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    if args.command == "doctor":
        static_result = run_static_checks(cfg)
        output: dict[str, object] = {"static": static_result}
        exit_code = 0 if static_result["ok"] else 1
        if args.live and static_result["ok"]:
            first_prompt = (
                "Run these as three separate shell tool calls and do not combine them: "
                "`printf protocol-check-a`; "
                "`sh -c 'printf expected-failure >&2; exit 7'`; "
                "`printf protocol-check-marker > /workspace/protocol-check.txt`. "
                "The second command is expected to fail. Continue after it and finish the third "
                "command, then answer protocol-first-turn-complete."
            )
            run(cfg, first_prompt, dangerously_bypass=True)
            thread_id = _thread_id_from_trace(run_id=str(cfg.run_id), trace_dir=cfg.trace_dir)
            if thread_id is not None:
                second_prompt = (
                    "Continue this thread. In one shell tool call, run "
                    "`cat /workspace/protocol-check.txt`, then answer "
                    "protocol-resume-complete."
                )
                run(
                    cfg,
                    second_prompt,
                    thread_id=thread_id,
                    dangerously_bypass=True,
                )
            live_result = evaluate_live_trace(cfg)
            output["live"] = live_result
            if not live_result["ok"]:
                exit_code = 1
        print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))
        return exit_code

    if default_repl:
        return run_repl_command(
            cfg,
            input_stream=input_stream,
            output_stream=output_stream,
            dangerously_bypass=args.dangerously_bypass,
        )

    print(json.dumps(masked_config_dump(cfg), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def cli_entry() -> None:
    """console script 入口。"""

    raise SystemExit(main())


def sec_entry() -> None:
    """短命令入口；无子命令时启动智能体 CLI。"""

    raise SystemExit(main(default_repl=True, prog="sec"))


def run_repl_command(
    cfg: Config,
    *,
    input_stream: TextIO | None = None,
    output_stream: TextIO | None = None,
    dangerously_bypass: bool = False,
) -> int:
    """执行交互式智能体 CLI。"""

    thread_id: str | None = None

    def execute_with_context(
        active_cfg: Config,
        raw_text: str,
        task_input_stream: TextIO,
        task_output_stream: TextIO,
    ) -> None:
        nonlocal thread_id
        thread_id = (
            execute_repl_task(
                active_cfg,
                raw_text,
                task_input_stream,
                task_output_stream,
                dangerously_bypass=dangerously_bypass,
                thread_id=thread_id,
            )
            or thread_id
        )

    return run_agent_repl(
        cfg,
        execute_with_context,
        input_stream=input_stream,
        output_stream=output_stream,
    )


def execute_repl_task(
    cfg: Config,
    raw_text: str,
    input_stream: TextIO,
    output_stream: TextIO | None = None,
    *,
    dangerously_bypass: bool = False,
    thread_id: str | None = None,
) -> str | None:
    """执行 REPL 中的一条自然语言任务并把进展渲染到同一终端。"""

    if output_stream is None:
        output_stream = input_stream
        approval_input_stream: TextIO | None = None
    else:
        approval_input_stream = input_stream

    run_cfg = cfg.model_copy(update={"run_id": generate_run_id()})
    renderer = CliProgressRenderer(output_stream, settings=run_cfg.cli)
    approval_callback = (
        _approval_callback(approval_input_stream, output_stream)
        if not dangerously_bypass
        and approval_input_stream is not None
        and _is_tty(approval_input_stream)
        else None
    )
    try:
        result = run(
            run_cfg,
            raw_text,
            progress_callback=renderer.handle_event,
            approval_callback=approval_callback,
            thread_id=thread_id,
            dangerously_bypass=dangerously_bypass,
        )
    except RuntimeError as exc:
        renderer.finish()
        output_stream.write(f"error: {exc}\n")
        output_stream.flush()
        return thread_id
    renderer.finish()
    output = run_output(run_cfg, result)
    final_text = output.get("final_text")
    post_run_text_parts: list[str] = []
    if isinstance(final_text, str) and final_text.strip() and not renderer.model_text_seen:
        final_line = final_text.rstrip() + "\n"
        output_stream.write(final_line)
        post_run_text_parts.append(final_line)
    fallback_summary: str | None = None
    if result.outcome != "ok" or not final_text:
        fallback_summary = _repl_fallback_summary(
            run_id=str(output["run_id"]),
            trace_dir=run_cfg.trace_dir,
            result=result,
        )
        if fallback_summary:
            fallback_text = fallback_summary + "\n"
            output_stream.write(fallback_text)
            post_run_text_parts.append(fallback_text)
    trace_line = f"trace: {output['trace_path']}\n"
    output_stream.write(trace_line)
    post_run_text_parts.append(trace_line)
    _emit_ui_output(
        run_cfg,
        interface="repl",
        text="".join(post_run_text_parts),
        source="streamed_model" if renderer.model_text_seen else "post_run",
        final_text=final_text if isinstance(final_text, str) else None,
        fallback_summary=fallback_summary,
        trace_path=str(output["trace_path"]),
    )
    output_stream.flush()
    return _thread_id_from_trace(run_id=str(output["run_id"]), trace_dir=run_cfg.trace_dir)


def _approval_callback(
    input_stream: TextIO,
    output_stream: TextIO,
) -> ApprovalCallback:
    """构造交互式工具执行批准回调。"""

    def approve(request: ApprovalRequest) -> ApprovalDecision:
        output_stream.write("\nAllow Codex operation?\n")
        output_stream.write(f"kind: {request.kind}\n")
        if request.command:
            output_stream.write(f"command: {request.command}\n")
        if request.cwd:
            output_stream.write(f"cwd: {request.cwd}\n")
        if request.grant_root:
            output_stream.write(f"grant root: {request.grant_root}\n")
        if request.network_context:
            output_stream.write(
                "network: "
                + json.dumps(request.network_context, ensure_ascii=False, sort_keys=True)
                + "\n"
            )
        if request.reason:
            output_stream.write(f"reason: {request.reason}\n")
        output_stream.write("[y] once / [s] session / [N] block\n")
        output_stream.write("> ")
        output_stream.flush()

        answer = _normalize_approval_answer(input_stream.readline())
        if answer in {"y", "yes"}:
            output_stream.write("approved\n")
            output_stream.flush()
            return ApprovalDecision(decision="accept", reason="user_approved")
        if answer in {"s", "session"}:
            output_stream.write("approved for session\n")
            output_stream.flush()
            return ApprovalDecision(
                decision="acceptForSession", reason="user_approved_for_session"
            )
        output_stream.write("denied\n")
        output_stream.flush()
        return ApprovalDecision(decision="decline", reason="user_denied")

    return approve


def _normalize_approval_answer(answer: str) -> str:
    """清理终端控制字符，避免确认输入被误判。"""

    without_ansi = _ANSI_ESCAPE_RE.sub("", answer)
    printable = "".join(char for char in without_ansi if char.isprintable())
    return printable.strip().lower()


def _is_tty(stream: TextIO) -> bool:
    """判断流是否为真实交互式终端。"""

    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def run_output(cfg: Config, result: RunResult) -> dict[str, object]:
    """生成 ``run`` 子命令的终端输出。

    :param cfg: 已带 run id 的运行配置。
    :param result: ``run`` 返回的运行结果。
    :return: 可打印的运行摘要；包含最终模型文本和 trace 路径。
    """

    run_id = cfg.run_id
    if run_id is None:
        raise RuntimeError("run_id was not initialized")

    trace_path = Path(cfg.trace_dir) / f"{run_id}.jsonl"
    output: dict[str, object] = {
        "run_id": run_id,
        "outcome": result.outcome,
        "steps": result.steps,
        "trace_path": str(trace_path),
    }
    final_text = _final_text_from_trace(run_id=run_id, trace_dir=cfg.trace_dir)
    if final_text is not None:
        output["final_text"] = final_text
    return output


def _emit_ui_output(
    cfg: Config,
    *,
    interface: str,
    text: str,
    source: str,
    trace_path: str,
    final_text: str | None = None,
    fallback_summary: str | None = None,
) -> None:
    """Append the final user-visible output summary to the run trace."""

    run_id = cfg.run_id
    if run_id is None:
        return

    try:
        events = read_trace(run_id=run_id, trace_dir=cfg.trace_dir)
    except FileNotFoundError:
        return

    exit_event = _last_event_of_type(events, event_type="run_exit")
    parents = [exit_event.id] if exit_event is not None else []
    payload: dict[str, object] = {
        "interface": interface,
        "source": source,
        "text": text,
        "trace_path": trace_path,
    }
    if final_text is not None:
        payload["final_text"] = final_text
    if fallback_summary is not None:
        payload["fallback_summary"] = fallback_summary

    TraceSink(run_id=run_id, task_id=cfg.task_id, trace_dir=cfg.trace_dir).emit(
        stage="core",
        type="ui_output",
        parents=parents,
        payload=payload,
    )


def render_trace_command(args: argparse.Namespace, cfg: Config) -> dict[str, object]:
    """执行 ``render`` 子命令并返回终端摘要。

    :param args: argparse 解析出的 render 参数。
    :param cfg: 已加载的运行配置，用于确定 trace 目录。
    :return: 可打印的渲染结果摘要。
    """

    run_id = args.trace_run_id
    output_path = Path(args.output) if args.output else Path(cfg.trace_dir) / f"{run_id}.html"
    written_path = write_behavior_graph_html(
        run_id=run_id,
        trace_dir=cfg.trace_dir,
        output_path=output_path,
    )
    return {
        "run_id": run_id,
        "trace_path": str(Path(cfg.trace_dir) / f"{run_id}.jsonl"),
        "output_path": str(written_path),
    }


def _final_text_from_trace(*, run_id: str, trace_dir: str | Path) -> str | None:
    """从 trace 的 run_exit 事件读取最终模型文本。

    :param run_id: 本次运行标识。
    :param trace_dir: trace 目录。
    :return: ``run_exit.payload.text``；不存在或不是字符串时返回 ``None``。
    """

    exit_event = _last_event_of_type(
        read_trace(run_id=run_id, trace_dir=trace_dir),
        event_type="run_exit",
    )
    if exit_event is None:
        return None

    text = exit_event.payload.get("text")
    if isinstance(text, str):
        return text
    return None


def _thread_id_from_trace(*, run_id: str, trace_dir: str | Path) -> str | None:
    """从 run_exit 事件读取可用于下一轮 resume 的 Codex thread id。"""

    try:
        events = read_trace(run_id=run_id, trace_dir=trace_dir)
    except FileNotFoundError:
        return None

    exit_event = _last_event_of_type(events, event_type="run_exit")
    if exit_event is None:
        return None

    thread_id = exit_event.payload.get("thread_id")
    if isinstance(thread_id, str) and thread_id.strip():
        return thread_id
    return None


def _last_event_of_type(events: list[TraceEvent], *, event_type: str) -> TraceEvent | None:
    """从事件列表末尾查找指定类型事件。

    :param events: 按 trace 文件顺序读取出的事件列表。
    :param event_type: 目标事件类型。
    :return: 最后一条匹配事件；没有匹配时返回 ``None``。
    """

    for event in reversed(events):
        if event.type == event_type:
            return event
    return None


def _repl_fallback_summary(*, run_id: str, trace_dir: str | Path, result: RunResult) -> str:
    """在模型没有最终总结时，为 REPL 生成基于 trace 的简短摘要。"""

    events = read_trace(run_id=run_id, trace_dir=trace_dir)
    if result.outcome == "ok":
        return "模型没有返回可显示的文本。"

    lines = [f"本次运行未完成最终总结：outcome={result.outcome}。"]
    tool_lines = [
        _tool_result_summary(event, event.payload.get("tool_name"))
        for event in events
        if event.type == "tool_result"
    ]
    tool_lines = [line for line in tool_lines if line]
    if tool_lines:
        lines.append("已取得的工具结果：")
        lines.extend(f"- {line}" for line in tool_lines[-6:])
    return "\n".join(lines)


def _tool_result_summary(event: TraceEvent, tool_name: object) -> str | None:
    """把单个 tool_result 事件压缩成一行 REPL 摘要。"""

    payload = event.payload
    call_id = payload.get("call_id")
    result = payload.get("result")
    label = f"{tool_name or 'tool'} {call_id}"

    if isinstance(result, dict):
        error = result.get("error")
        if isinstance(error, str):
            return f"{label}: error={error}"

        if result.get("type") == "commandExecution":
            parts = [f"exit_code={result.get('exitCode')}"]
            status = result.get("status")
            if isinstance(status, str) and status:
                parts.append(f"status={status}")
            output = result.get("aggregatedOutput")
            if isinstance(output, str) and output.strip():
                parts.append("output=" + " ".join(output.split())[:160])
            return f"{label}: " + ", ".join(parts)

    return None
