"""Project-local derivation agent built on the OpenAI Responses API."""

from __future__ import annotations

import json
import hashlib
import threading
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable

from agentsectool_scanner.paths import DERIVATION_ARTIFACTS

from .config import AgentConfig
from .capabilities import CapabilityRegistry
from .harness import LocalDockerHarness
from .repository import (
    DerivationConflictError,
    DerivationRepository,
    canonical_json,
)

MAX_TOOL_CALLS = 48
MAX_ARTIFACT_READ = 64 * 1024
MAX_CANDIDATE_FILE = 2 * 1024 * 1024

AGENT_INSTRUCTIONS = """你是资产测绘平台内的测绘能力派生智能体。你的输入是一份漏洞需求快照、按时间追加的补充包、验收项版本和用户持续会话。

你的职责是从漏洞代码和主文档中识别可在互联网实例上安全观测的项目事实，生成一个或多个独立项目测试项，为每个测试项生成固定容器 worker、隔离样例环境、Harness 配置、漏洞关联规则和展示模板，并用本地 Docker Harness 产出可复查证据。

严格区分两类对象：项目测试项在生产扫描中判断目标是否满足项目级条件；验收项只在 Harness 中判断生成的项目测试项是否可靠。单个弱特征不得直接判定漏洞成立。禁止执行全网扫描，禁止把未经验证的候选能力视为已入仓能力。

manifest.json 只提供材料清单，不承载项目语义。代码文件和主文档是主要分析材料，辅助文件与补充包只提供附加线索。先用工具读取材料，不得编造未读取的内容。用户消息既可能是问题，也可能是继续执行、修订或补充约束的指令；需要人工判断时使用 request_user_input，说明卡点、证据和需要补充的具体信息。

候选 worker 使用逐行 JSON 协议。每行输入包含 request_id、target(host/port/tls) 和 timeout_ms；每行输出包含 request_id、test_id、status、facts、evidence 和 error。status 只能是 satisfied、not_satisfied、unknown 或 error。worker 必须持续读取标准输入，不能为单个目标退出。

同一 asset_type 可以同时运行多个独立项目测试项。facts 字段必须使用稳定的项目命名空间，避免与同类其他能力重名；多个能力引用同一 vulnerability_id 时必须使用一致的结构化适用条件。不得通过覆盖同类既有能力来规避事实或漏洞规则冲突。

通过 begin_attempt 创建工作目录，再用 write_candidate_file 写入候选文件。harness.json 必须描述一个 project_test_id、worker、内部 Compose 环境和逐项 case。环境不得使用 privileged、host network、Docker socket、设备映射、额外 capability、宿主端口或可写宿主目录。Harness 失败后应分析证据；能自主修订时创建新 attempt，缺少事实时向用户提问。

只有 Harness 通过且所有启用验收项均已由用户确认时，才能调用 register_candidate。不得代替用户确认验收项，也不得修改已经确认的验收项；如需调整，应在会话中说明依据并请用户决定。

外部检索只用于官方仓库、官方文档、可信 registry 和镜像来源。引用检索结果时保留 URL、commit 或镜像 digest。回答用户时使用专业、直接的中文，明确说明当前判断、证据、下一动作或等待信息。"""


class ResponsesAPIError(RuntimeError):
    """Raised when the remote Responses API request fails."""


class ResponsesTransport:
    def __init__(self, config: AgentConfig):
        self.config = config

    def create(self, payload: dict) -> dict:
        request = urllib.request.Request(
            f"{self.config.base_url}/responses",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[-4000:]
            raise ResponsesAPIError(f"Responses API 返回 HTTP {exc.code}：{detail}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ResponsesAPIError(f"Responses API 调用失败：{exc}") from exc


@dataclass
class _Runtime:
    task_id: str
    run_id: str
    active_attempt_id: str | None = None
    waiting_user: bool = False


class DerivationAgent:
    def __init__(
        self,
        repository: DerivationRepository,
        harness: LocalDockerHarness,
        config: AgentConfig,
        *,
        capability_registry: CapabilityRegistry | None = None,
        transport: ResponsesTransport | None = None,
        attempts_root: str | Path = DERIVATION_ARTIFACTS / "attempts",
    ):
        self.repository = repository
        self.harness = harness
        self.config = config
        self.capability_registry = capability_registry or CapabilityRegistry(repository)
        self.transport = transport or ResponsesTransport(config)
        self.attempts_root = Path(attempts_root)

    def run(self, task_id: str, triggering_message_id: str) -> dict:
        if not self.config.enabled:
            raise ResponsesAPIError("派生智能体尚未配置 API key 或项目级外发授权")
        run = self.repository.create_agent_run(task_id, triggering_message_id, self.config.model)
        runtime = _Runtime(task_id=task_id, run_id=run["id"])
        response_id = None
        try:
            input_items = self._conversation_input(task_id)
            tools = self._tool_definitions()
            for _ in range(MAX_TOOL_CALLS):
                payload = {
                    "model": self.config.model,
                    "instructions": AGENT_INSTRUCTIONS,
                    "input": input_items,
                    "tools": tools,
                    "tool_choice": "auto",
                    "parallel_tool_calls": False,
                    "reasoning": {
                        "effort": self.config.reasoning_effort,
                        "summary": "concise",
                    },
                    "include": [
                        "reasoning.encrypted_content",
                        "web_search_call.action.sources",
                    ],
                    "store": False,
                    "max_output_tokens": 32768,
                }
                response = self.transport.create(payload)
                response_id = response.get("id") or response_id
                output = response.get("output")
                if not isinstance(output, list):
                    raise ResponsesAPIError("Responses API 响应缺少 output 数组")
                self._record_remote_events(task_id, output)
                input_items.extend(output)
                calls = [item for item in output if item.get("type") == "function_call"]
                if calls:
                    for call in calls:
                        result = self._execute_call(runtime, call)
                        input_items.append({
                            "type": "function_call_output",
                            "call_id": call.get("call_id"),
                            "output": canonical_json(result),
                        })
                    continue
                text = self._output_text(output)
                if text:
                    self.repository.append_message(task_id, role="assistant", content=text)
                    self.repository.add_event(task_id, "assistant_message", {"content": text})
                current_status = self.repository.get_task(task_id)["status"]
                final_status = "waiting_user" if runtime.waiting_user else "completed"
                task_status = "waiting_user" if runtime.waiting_user else (
                    "ready" if current_status == "running" else current_status
                )
                self.repository.finish_agent_run(
                    run["id"],
                    status=final_status,
                    response_id=response_id,
                    task_status=task_status,
                )
                return {
                    "run_id": run["id"],
                    "status": final_status,
                    "response_id": response_id,
                    "message": text,
                }
            raise ResponsesAPIError(f"智能体超过 {MAX_TOOL_CALLS} 次工具调用安全上限")
        except Exception as exc:
            self.repository.finish_agent_run(
                run["id"],
                status="failed",
                response_id=response_id,
                error=str(exc),
                task_status="infra_failed",
            )
            raise

    def _conversation_input(self, task_id: str) -> list[dict]:
        task = self.repository.get_task(task_id)
        materials = [
            {
                "artifact_id": item["id"],
                "package_kind": item["package_kind"],
                "role": item["role"],
                "kind": item["kind"],
                "relative_path": item["relative_path"],
                "sha256": item["sha256"],
                "size_bytes": item["size_bytes"],
            }
            for item in self.repository.list_artifacts(task_id)
        ]
        context = {
            "task_id": task_id,
            "request_id": task["request_id"],
            "project_name": task["project_name"],
            "vulnerability_id": task["vulnerability_id"],
            "source_package_hash": task["source_package_hash"],
            "materials": materials,
            "acceptance_tests": self.repository.list_acceptance_tests(task_id),
            "attempts": self.repository.list_attempts(task_id),
            "harness_runs": self.repository.list_harness_runs(task_id),
        }
        items = [{
            "role": "user",
            "content": "当前任务结构化上下文：\n" + json.dumps(context, ensure_ascii=False),
        }]
        for message in self.repository.list_messages(task_id):
            items.append({"role": message["role"], "content": message["content"]})
        return items

    def _execute_call(self, runtime: _Runtime, call: dict) -> dict:
        name = call.get("name")
        try:
            arguments = json.loads(call.get("arguments") or "{}")
            if not isinstance(arguments, dict):
                raise ValueError("工具参数必须为对象")
            handlers: dict[str, Callable[[dict, _Runtime], dict]] = {
                "list_materials": self._list_materials,
                "read_material": self._read_material,
                "list_acceptance_tests": self._list_acceptance_tests,
                "set_task_identity": self._set_task_identity,
                "define_acceptance_test": self._define_acceptance_test,
                "begin_attempt": self._begin_attempt,
                "write_candidate_file": self._write_candidate_file,
                "run_harness": self._run_harness,
                "read_harness_run": self._read_harness_run,
                "register_candidate": self._register_candidate,
                "request_user_input": self._request_user_input,
            }
            if name not in handlers:
                raise ValueError(f"未知工具：{name}")
            self.repository.add_event(runtime.task_id, "tool_call", {
                "name": name,
                "arguments": arguments,
            })
            result = handlers[name](arguments, runtime)
            self.repository.add_event(runtime.task_id, "tool_result", {
                "name": name,
                "result": result,
            })
            return {"ok": True, "result": result}
        except Exception as exc:
            result = {"ok": False, "error": str(exc)}
            self.repository.add_event(runtime.task_id, "tool_error", {
                "name": name,
                "error": str(exc),
            })
            return result

    def _list_materials(self, _arguments: dict, runtime: _Runtime) -> dict:
        return {"materials": [
            {
                "artifact_id": item["id"],
                "package_kind": item["package_kind"],
                "role": item["role"],
                "kind": item["kind"],
                "relative_path": item["relative_path"],
                "sha256": item["sha256"],
                "size_bytes": item["size_bytes"],
            }
            for item in self.repository.list_artifacts(runtime.task_id)
        ]}

    def _read_material(self, arguments: dict, runtime: _Runtime) -> dict:
        artifact = self.repository.get_artifact(runtime.task_id, arguments.get("artifact_id", ""))
        path = Path(artifact["storage_path"])
        if artifact["size_bytes"] > 8 * 1024 * 1024:
            raise ValueError("材料过大，不能直接发送给模型")
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("该辅助材料不是 UTF-8 文本，当前工具只返回文本材料") from exc
        offset = max(0, int(arguments.get("offset", 0)))
        limit = min(max(int(arguments.get("limit", MAX_ARTIFACT_READ)), 1), MAX_ARTIFACT_READ)
        fragment = content[offset:offset + limit]
        return {
            "artifact_id": artifact["id"],
            "relative_path": artifact["relative_path"],
            "sha256": artifact["sha256"],
            "offset": offset,
            "next_offset": offset + len(fragment) if offset + len(fragment) < len(content) else None,
            "content": fragment,
        }

    def _list_acceptance_tests(self, _arguments: dict, runtime: _Runtime) -> dict:
        return {"acceptance_tests": self.repository.list_acceptance_tests(runtime.task_id)}

    def _set_task_identity(self, arguments: dict, runtime: _Runtime) -> dict:
        project = str(arguments.get("project_name", "")).strip()
        vulnerability = str(arguments.get("vulnerability_id", "")).strip()
        if not project or not vulnerability:
            raise ValueError("项目名和漏洞身份不能为空")
        self.repository.update_task_identity(
            runtime.task_id, project_name=project, vulnerability_id=vulnerability
        )
        return {"project_name": project, "vulnerability_id": vulnerability}

    def _define_acceptance_test(self, arguments: dict, runtime: _Runtime) -> dict:
        definition = {
            "stable_key": arguments.get("stable_key"),
            "name": arguments.get("name"),
            "purpose": arguments.get("purpose"),
            "enabled": arguments.get("enabled", True),
            "blocking": arguments.get("blocking", True),
            "assertion": arguments.get("assertion"),
            "user_confirmed": False,
        }
        return self.repository.upsert_acceptance_test(
            runtime.task_id,
            definition,
            actor="agent",
            change_reason=arguments.get("change_reason"),
        )

    def _begin_attempt(self, arguments: dict, runtime: _Runtime) -> dict:
        if runtime.active_attempt_id:
            current = self.repository.get_attempt(runtime.active_attempt_id)
            if current["status"] == "draft":
                return current
        token = uuid.uuid4().hex
        workspace = self.attempts_root / runtime.task_id / token
        workspace.mkdir(parents=True, exist_ok=False)
        attempt = self.repository.create_attempt(
            runtime.task_id,
            agent_run_id=runtime.run_id,
            input_hash=self.repository.input_hash(runtime.task_id),
            workspace_path=str(workspace),
        )
        runtime.active_attempt_id = attempt["id"]
        summary = str(arguments.get("summary", "")).strip()
        if summary:
            self.repository.set_attempt_status(attempt["id"], "draft", summary=summary)
            attempt["summary"] = summary
        return attempt

    def _write_candidate_file(self, arguments: dict, runtime: _Runtime) -> dict:
        if not runtime.active_attempt_id:
            raise DerivationConflictError("先调用 begin_attempt 创建候选工作目录")
        attempt = self.repository.get_attempt(runtime.active_attempt_id)
        if attempt["status"] != "draft":
            raise DerivationConflictError("当前 attempt 已运行 Harness，必须创建新的 attempt")
        relative_path = arguments.get("relative_path")
        content = arguments.get("content")
        if not isinstance(relative_path, str) or not isinstance(content, str):
            raise ValueError("relative_path 和 content 必须为字符串")
        if len(content.encode("utf-8")) > MAX_CANDIDATE_FILE:
            raise ValueError("单个候选文件不能超过 2 MiB")
        pure = PurePosixPath(relative_path)
        if (
            pure.is_absolute()
            or "\\" in relative_path
            or any(part in {"", ".", ".."} for part in pure.parts)
        ):
            raise ValueError("候选文件路径不是安全相对路径")
        root = Path(attempt["workspace_path"]).resolve()
        path = root.joinpath(*pure.parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        parent = path.parent.resolve()
        parent.relative_to(root)
        if path.exists() and path.is_symlink():
            raise ValueError("候选文件不能覆盖符号链接")
        path.write_text(content, encoding="utf-8")
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return {"relative_path": pure.as_posix(), "sha256": digest, "size_bytes": len(content.encode("utf-8"))}

    def _run_harness(self, _arguments: dict, runtime: _Runtime) -> dict:
        if not runtime.active_attempt_id:
            raise DerivationConflictError("没有可运行的 attempt")
        result = self.harness.run(runtime.task_id, runtime.active_attempt_id)
        if result["status"] != "passed":
            runtime.active_attempt_id = None
        return result

    def _read_harness_run(self, arguments: dict, runtime: _Runtime) -> dict:
        result = self.repository.get_harness_run(arguments.get("run_id", ""))
        if result["task_id"] != runtime.task_id:
            raise DerivationConflictError("Harness 运行不属于当前任务")
        return result

    def _register_candidate(self, _arguments: dict, runtime: _Runtime) -> dict:
        if not runtime.active_attempt_id:
            raise DerivationConflictError("没有可登记的 attempt")
        return self.capability_registry.register_candidate(
            runtime.task_id, runtime.active_attempt_id
        )

    def _request_user_input(self, arguments: dict, runtime: _Runtime) -> dict:
        question = str(arguments.get("question", "")).strip()
        reason = str(arguments.get("reason", "")).strip()
        needed = arguments.get("needed_files", [])
        if not question or not reason or not isinstance(needed, list):
            raise ValueError("request_user_input 需要 question、reason 和 needed_files")
        runtime.waiting_user = True
        return {"waiting": True, "question": question, "reason": reason, "needed_files": needed}

    def _record_remote_events(self, task_id: str, output: list[dict]) -> None:
        for item in output:
            if item.get("type") == "reasoning" and item.get("summary"):
                self.repository.add_event(task_id, "reasoning_summary", {
                    "summary": item["summary"],
                })
            if item.get("type") == "web_search_call":
                action = item.get("action") or {}
                self.repository.add_event(task_id, "web_research", {
                    "query": action.get("query"),
                    "sources": action.get("sources", []),
                })

    @staticmethod
    def _output_text(output: list[dict]) -> str:
        parts = []
        for item in output:
            if item.get("type") != "message":
                continue
            for content in item.get("content", []):
                if content.get("type") == "output_text" and content.get("text"):
                    parts.append(content["text"])
        return "\n\n".join(parts).strip()

    def _tool_definitions(self) -> list[dict]:
        functions = [
            ("list_materials", "列出原始需求和补充包中已登记的材料。", {}, []),
            ("read_material", "按 artifact_id 读取 UTF-8 材料片段。", {
                "artifact_id": {"type": "string"},
                "offset": {"type": "integer", "minimum": 0},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_ARTIFACT_READ},
            }, ["artifact_id", "offset", "limit"]),
            ("list_acceptance_tests", "列出当前验收项及版本。", {}, []),
            ("set_task_identity", "从主文档中确认项目和漏洞身份。", {
                "project_name": {"type": "string"},
                "vulnerability_id": {"type": "string"},
            }, ["project_name", "vulnerability_id"]),
            ("define_acceptance_test", "创建或修订草稿验收项。", {
                "stable_key": {"type": "string"},
                "name": {"type": "string"},
                "purpose": {"type": "string"},
                "enabled": {"type": "boolean"},
                "blocking": {"type": "boolean"},
                "assertion": {"type": "object", "additionalProperties": True},
                "change_reason": {"type": ["string", "null"]},
            }, ["stable_key", "name", "purpose", "enabled", "blocking", "assertion", "change_reason"]),
            ("begin_attempt", "创建新的候选能力工作目录。", {
                "summary": {"type": "string"},
            }, ["summary"]),
            ("write_candidate_file", "在当前 attempt 内写入 UTF-8 候选文件。", {
                "relative_path": {"type": "string"},
                "content": {"type": "string"},
            }, ["relative_path", "content"]),
            ("run_harness", "在本地 Docker 隔离环境中验证当前 attempt。", {}, []),
            ("read_harness_run", "读取一次 Harness 的逐项结果和证据。", {
                "run_id": {"type": "string"},
            }, ["run_id"]),
            ("register_candidate", "把通过 Harness 且验收口径已确认的 attempt 登记为待审核能力包。", {}, []),
            ("request_user_input", "缺少事实或需要人工取舍时提出具体问题。", {
                "question": {"type": "string"},
                "reason": {"type": "string"},
                "needed_files": {"type": "array", "items": {"type": "string"}},
            }, ["question", "reason", "needed_files"]),
        ]
        tools = []
        for name, description, properties, required in functions:
            tools.append({
                "type": "function",
                "name": name,
                "description": description,
                "strict": True,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                    "additionalProperties": False,
                },
            })
        tools.append({
            "type": "web_search",
            "filters": {"allowed_domains": list(self.config.allowed_domains)},
        })
        return tools


class AgentCoordinator:
    """Runs at most one background agent job per task."""

    def __init__(self, agent_factory: Callable[[], DerivationAgent]):
        self.agent_factory = agent_factory
        self._lock = threading.Lock()
        self._running: set[str] = set()
        self._pending: dict[str, str] = {}

    def submit(self, task_id: str, message_id: str) -> bool:
        with self._lock:
            if task_id in self._running:
                self._pending[task_id] = message_id
                return False
            self._running.add(task_id)
        thread = threading.Thread(
            target=self._run,
            args=(task_id, message_id),
            name=f"derivation-{task_id[-8:]}",
            daemon=True,
        )
        thread.start()
        return True

    def _run(self, task_id: str, message_id: str) -> None:
        current = message_id
        while True:
            try:
                self.agent_factory().run(task_id, current)
            except Exception:
                pass
            with self._lock:
                pending = self._pending.pop(task_id, None)
                if not pending:
                    self._running.discard(task_id)
                    return
                current = pending
