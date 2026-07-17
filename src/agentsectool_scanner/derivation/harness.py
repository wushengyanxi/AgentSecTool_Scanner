"""Local Docker harness for validating generated project tests."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import uuid
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any

from agentsectool_scanner.paths import DERIVATION_RUNS

from .repository import DerivationRepository, canonical_json

ALLOWED_WORKER_REGISTRIES = {"docker.io", "ghcr.io", "quay.io"}
VALID_RESULT_STATUSES = {"satisfied", "not_satisfied", "unknown", "error"}
MAX_CASES = 100


class HarnessConfigurationError(ValueError):
    """Raised when generated harness material violates its contract."""


class HarnessInfrastructureError(RuntimeError):
    """Raised when Docker cannot execute an otherwise valid harness."""


def _safe_path(root: Path, relative_path: object, *, expect_dir: bool = False) -> Path:
    if not isinstance(relative_path, str) or not relative_path:
        raise HarnessConfigurationError("Harness 路径不能为空")
    if "\\" in relative_path:
        raise HarnessConfigurationError(f"Harness 路径必须使用 /：{relative_path}")
    pure = PurePosixPath(relative_path)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise HarnessConfigurationError(f"Harness 路径不是安全相对路径：{relative_path}")
    candidate = root.joinpath(*pure.parts)
    if candidate.is_symlink():
        raise HarnessConfigurationError(f"Harness 不接受符号链接：{relative_path}")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve())
    except (FileNotFoundError, ValueError) as exc:
        raise HarnessConfigurationError(f"Harness 路径不存在或越界：{relative_path}") from exc
    if expect_dir and not resolved.is_dir():
        raise HarnessConfigurationError(f"Harness 路径不是目录：{relative_path}")
    if not expect_dir and not resolved.is_file():
        raise HarnessConfigurationError(f"Harness 路径不是文件：{relative_path}")
    return resolved


def _image_registry(image: str) -> str:
    if "/" not in image:
        return "docker.io"
    first = image.split("/", 1)[0]
    if "." in first or ":" in first or first == "localhost":
        return first.split(":", 1)[0]
    return "docker.io"


def _json_path(value: Any, path: str) -> tuple[bool, Any]:
    current = value
    if not path:
        return True, current
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return False, None
    return True, current


def evaluate_assertion(assertion: dict, actual: Any) -> tuple[bool, str | None]:
    if "all" in assertion:
        children = assertion["all"]
        if not isinstance(children, list) or not children:
            return False, "all 断言必须包含非空数组"
        for child in children:
            passed, reason = evaluate_assertion(child, actual)
            if not passed:
                return False, reason
        return True, None
    if "any" in assertion:
        children = assertion["any"]
        if not isinstance(children, list) or not children:
            return False, "any 断言必须包含非空数组"
        reasons = []
        for child in children:
            passed, reason = evaluate_assertion(child, actual)
            if passed:
                return True, None
            reasons.append(reason)
        return False, "; ".join(filter(None, reasons))
    if "not" in assertion:
        passed, _ = evaluate_assertion(assertion["not"], actual)
        return (not passed, None if not passed else "not 断言内的条件成立")

    path = assertion.get("path", "")
    operator = assertion.get("operator")
    expected = assertion.get("value")
    if not isinstance(path, str) or not isinstance(operator, str):
        return False, "断言缺少 path 或 operator"
    exists, observed = _json_path(actual, path)
    if operator == "exists":
        passed = exists is bool(expected)
    elif not exists:
        return False, f"结果中不存在字段 {path!r}"
    elif operator == "eq":
        passed = observed == expected
    elif operator == "ne":
        passed = observed != expected
    elif operator == "contains":
        try:
            passed = expected in observed
        except TypeError:
            passed = False
    elif operator == "in":
        try:
            passed = observed in expected
        except TypeError:
            passed = False
    elif operator == "ge":
        try:
            passed = observed >= expected
        except TypeError:
            passed = False
    elif operator == "le":
        try:
            passed = observed <= expected
        except TypeError:
            passed = False
    elif operator == "truthy":
        passed = bool(observed)
    elif operator == "falsey":
        passed = not bool(observed)
    else:
        return False, f"不支持的断言操作符：{operator}"
    if passed:
        return True, None
    return False, f"字段 {path!r} 的实际值为 {observed!r}，操作符为 {operator}"


class LocalDockerHarness:
    def __init__(
        self,
        repository: DerivationRepository,
        runs_root: str | Path = DERIVATION_RUNS,
        *,
        docker_bin: str = "docker",
        allowed_registries: set[str] | None = None,
    ):
        self.repository = repository
        self.runs_root = Path(runs_root)
        self.docker_bin = docker_bin
        self.allowed_registries = allowed_registries or ALLOWED_WORKER_REGISTRIES

    def run(self, task_id: str, attempt_id: str) -> dict:
        attempt = self.repository.get_attempt(attempt_id)
        if attempt["task_id"] != task_id:
            raise HarnessConfigurationError("attempt 不属于当前任务")
        workspace = Path(attempt["workspace_path"]).resolve()
        config_path = _safe_path(workspace, "harness.json")
        token = uuid.uuid4().hex[:16]
        run_dir = self.runs_root / token
        run_dir.mkdir(parents=True, exist_ok=False)
        run = self.repository.start_harness_run(task_id, attempt_id, str(run_dir))
        started_projects: list[tuple[str, Path]] = []
        try:
            config = self._load_config(config_path)
            acceptance = {
                item["stable_key"]: item
                for item in self.repository.list_acceptance_tests(task_id)
                if item["enabled"]
            }
            self._validate_case_references(config, acceptance)
            worker_context = _safe_path(
                workspace, config["worker"]["context"], expect_dir=True
            )
            dockerfile = _safe_path(
                worker_context, config["worker"].get("dockerfile", "Dockerfile")
            )
            self._validate_dockerfile(dockerfile)
            image_tag = f"agentsectool-derivation:{token}"
            iidfile = run_dir / "worker.iid"
            self._command(
                [
                    self.docker_bin,
                    "build",
                    "--network=none",
                    "--iidfile",
                    str(iidfile),
                    "-f",
                    str(dockerfile),
                    "-t",
                    image_tag,
                    str(worker_context),
                ],
                run_dir,
                "worker-build",
                timeout=300,
            )
            image_digest = iidfile.read_text(encoding="utf-8").strip()
            outputs: dict[str, dict] = {}
            evidence: dict[str, list[dict]] = defaultdict(list)
            cases_by_environment: dict[str, list[dict]] = defaultdict(list)
            for case in config["cases"]:
                cases_by_environment[case["environment_id"]].append(case)

            environments = {item["id"]: item for item in config["environments"]}
            for environment_id, cases in cases_by_environment.items():
                environment = environments[environment_id]
                compose_file = _safe_path(workspace, environment["compose_file"])
                project = f"ast_{token}_{re.sub(r'[^a-z0-9]', '', environment_id.lower())[:12]}"
                compose = self._compose_config(project, compose_file, run_dir)
                network_name = self._validate_compose(compose, workspace, environment)
                self._command(
                    [
                        self.docker_bin,
                        "compose",
                        "-p",
                        project,
                        "-f",
                        str(compose_file),
                        "up",
                        "-d",
                        "--build",
                        "--wait",
                        "--wait-timeout",
                        str(int(environment.get("wait_timeout_seconds", 60))),
                    ],
                    run_dir,
                    f"environment-{environment_id}-up",
                    timeout=180,
                )
                started_projects.append((project, compose_file))
                responses, stderr = self._run_worker(image_tag, network_name, cases, run_dir)
                for case, response in zip(cases, responses, strict=True):
                    outputs[case["id"]] = response
                    evidence[case["acceptance_test"]].append({
                        "case_id": case["id"],
                        "environment_id": environment_id,
                        "response": response,
                        "worker_stderr": stderr,
                    })

            results = self._evaluate_results(acceptance, config["cases"], outputs, evidence)
            blocking_failed = any(
                result["status"] != "passed"
                and acceptance[result["stable_key"]]["blocking"]
                for result in results
            )
            status = "failed" if blocking_failed else "passed"
            persisted = [
                {key: value for key, value in item.items() if key != "stable_key"}
                for item in results
            ]
            return self.repository.finish_harness_run(
                run["id"], status=status, results=persisted,
                image_reference=image_tag, image_digest=image_digest
            )
        except (HarnessConfigurationError, HarnessInfrastructureError) as exc:
            return self.repository.finish_harness_run(
                run["id"], status="blocked", results=[], error=str(exc)
            )
        except Exception as exc:
            return self.repository.finish_harness_run(
                run["id"], status="blocked", results=[], error=f"未预期的 Harness 错误：{exc}"
            )
        finally:
            for project, compose_file in reversed(started_projects):
                try:
                    self._command(
                        [
                            self.docker_bin,
                            "compose",
                            "-p",
                            project,
                            "-f",
                            str(compose_file),
                            "down",
                            "--volumes",
                            "--remove-orphans",
                        ],
                        run_dir,
                        f"environment-{project}-down",
                        timeout=90,
                    )
                except HarnessInfrastructureError:
                    pass

    @staticmethod
    def _load_config(path: Path) -> dict:
        try:
            config = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HarnessConfigurationError(f"harness.json 无效：{exc}") from exc
        if not isinstance(config, dict) or config.get("schema_version") != "1.0":
            raise HarnessConfigurationError("harness.json.schema_version 必须为 1.0")
        if not isinstance(config.get("project_test_id"), str) or not config["project_test_id"]:
            raise HarnessConfigurationError("harness.json 缺少 project_test_id")
        worker = config.get("worker")
        environments = config.get("environments")
        cases = config.get("cases")
        if not isinstance(worker, dict) or not isinstance(worker.get("context"), str):
            raise HarnessConfigurationError("harness.json 缺少 worker.context")
        if not isinstance(environments, list) or not environments:
            raise HarnessConfigurationError("harness.json 至少需要一个环境")
        if not isinstance(cases, list) or not cases or len(cases) > MAX_CASES:
            raise HarnessConfigurationError("harness.json cases 数量必须在 1 到 100 之间")
        environment_ids = set()
        for environment in environments:
            if (
                not isinstance(environment, dict)
                or not isinstance(environment.get("id"), str)
                or not isinstance(environment.get("compose_file"), str)
            ):
                raise HarnessConfigurationError("每个环境必须包含 id 和 compose_file")
            if environment["id"] in environment_ids:
                raise HarnessConfigurationError(f"环境 id 重复：{environment['id']}")
            environment_ids.add(environment["id"])
        case_ids = set()
        for case in cases:
            if not isinstance(case, dict) or any(
                not isinstance(case.get(key), str)
                for key in ("id", "environment_id", "acceptance_test")
            ):
                raise HarnessConfigurationError(
                    "每个 case 必须包含 id、environment_id 和 acceptance_test"
                )
            if case["id"] in case_ids:
                raise HarnessConfigurationError(f"case id 重复：{case['id']}")
            case_ids.add(case["id"])
            if case["environment_id"] not in environment_ids:
                raise HarnessConfigurationError(
                    f"case 引用了未知环境：{case['environment_id']}"
                )
            target = case.get("target")
            if (
                not isinstance(target, dict)
                or not isinstance(target.get("host"), str)
                or not isinstance(target.get("port"), int)
                or not 1 <= target["port"] <= 65535
                or not isinstance(target.get("tls", False), bool)
            ):
                raise HarnessConfigurationError(f"case {case['id']} 的 target 无效")
        return config

    @staticmethod
    def _validate_case_references(config: dict, acceptance: dict[str, dict]) -> None:
        referenced = {case["acceptance_test"] for case in config["cases"]}
        unknown = sorted(referenced - set(acceptance))
        if unknown:
            raise HarnessConfigurationError(f"case 引用了未知或已禁用验收项：{unknown}")
        missing = sorted(set(acceptance) - referenced)
        if missing:
            raise HarnessConfigurationError(f"启用的验收项没有对应 case：{missing}")

    def _validate_dockerfile(self, dockerfile: Path) -> None:
        try:
            text = dockerfile.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise HarnessConfigurationError("Worker Dockerfile 必须为 UTF-8 文本") from exc
        if re.search(r"(?im)^\s*ADD\s+https?://", text):
            raise HarnessConfigurationError("Worker Dockerfile 不允许通过 ADD 下载远程内容")
        images = re.findall(r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)", text)
        if not images:
            raise HarnessConfigurationError("Worker Dockerfile 缺少 FROM")
        for image in images:
            if image.lower() == "scratch" or image.startswith("$"):
                continue
            registry = _image_registry(image)
            if registry not in self.allowed_registries:
                raise HarnessConfigurationError(f"Worker 基础镜像来自未授权 registry：{registry}")

    def _compose_config(self, project: str, compose_file: Path, run_dir: Path) -> dict:
        completed = self._command(
            [
                self.docker_bin,
                "compose",
                "-p",
                project,
                "-f",
                str(compose_file),
                "config",
                "--format",
                "json",
            ],
            run_dir,
            f"environment-{project}-config",
            timeout=30,
        )
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise HarnessConfigurationError("docker compose 未返回可解析的 JSON 配置") from exc

    @staticmethod
    def _validate_compose(config: dict, workspace: Path, environment: dict) -> str:
        services = config.get("services")
        networks = config.get("networks")
        if not isinstance(services, dict) or not services:
            raise HarnessConfigurationError("Compose 环境没有服务")
        if not isinstance(networks, dict) or not networks:
            raise HarnessConfigurationError("Compose 环境必须声明内部网络")
        network_key = environment.get("network", "default")
        network = networks.get(network_key)
        if not isinstance(network, dict) or network.get("internal") is not True:
            raise HarnessConfigurationError("Harness 网络必须设置 internal: true")
        network_name = network.get("name")
        if not isinstance(network_name, str) or not network_name:
            raise HarnessConfigurationError("Compose 未生成可用网络名")
        root = workspace.resolve()
        for name, service in services.items():
            if service.get("privileged"):
                raise HarnessConfigurationError(f"服务 {name} 不允许 privileged")
            if service.get("network_mode") == "host" or service.get("pid") == "host" or service.get("ipc") == "host":
                raise HarnessConfigurationError(f"服务 {name} 不允许共享宿主命名空间")
            if service.get("devices") or service.get("cap_add"):
                raise HarnessConfigurationError(f"服务 {name} 不允许设备映射或增加 capabilities")
            if service.get("ports"):
                raise HarnessConfigurationError(f"服务 {name} 不允许发布宿主端口")
            if service.get("extra_hosts"):
                raise HarnessConfigurationError(f"服务 {name} 不允许 extra_hosts")
            for volume in service.get("volumes", []):
                if not isinstance(volume, dict):
                    raise HarnessConfigurationError(f"服务 {name} 的 volume 配置无效")
                if volume.get("type") == "bind":
                    source = Path(volume.get("source", "")).resolve()
                    try:
                        source.relative_to(root)
                    except ValueError as exc:
                        raise HarnessConfigurationError(
                            f"服务 {name} 的 bind mount 越出 attempt 目录"
                        ) from exc
                    if not volume.get("read_only"):
                        raise HarnessConfigurationError(f"服务 {name} 的 bind mount 必须只读")
                target = str(volume.get("target", ""))
                source_text = str(volume.get("source", ""))
                if "docker.sock" in target or "docker.sock" in source_text:
                    raise HarnessConfigurationError("Harness 不允许挂载 Docker socket")
        return network_name

    def _run_worker(
        self, image_tag: str, network_name: str, cases: list[dict], run_dir: Path
    ) -> tuple[list[dict], str]:
        requests = []
        for case in cases:
            requests.append({
                "request_id": case["id"],
                "target": {
                    "host": case["target"]["host"],
                    "port": case["target"]["port"],
                    "tls": case["target"].get("tls", False),
                },
                "timeout_ms": min(max(int(case.get("timeout_ms", 8000)), 100), 60000),
            })
        payload = "\n".join(canonical_json(item) for item in requests) + "\n"
        timeout = min(300, sum(item["timeout_ms"] for item in requests) / 1000 + 30)
        completed = self._command(
            [
                self.docker_bin,
                "run",
                "--rm",
                "-i",
                "--network",
                network_name,
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit=64",
                "--memory=256m",
                "--cpus=1",
                "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
                "--env=PYTHONDONTWRITEBYTECODE=1",
                image_tag,
            ],
            run_dir,
            f"worker-{cases[0]['environment_id']}",
            timeout=timeout,
            input_text=payload,
        )
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        if len(lines) != len(cases):
            raise HarnessInfrastructureError(
                f"Worker 应返回 {len(cases)} 行 JSONL，实际返回 {len(lines)} 行"
            )
        responses = []
        for case, line in zip(cases, lines, strict=True):
            try:
                response = json.loads(line)
            except json.JSONDecodeError as exc:
                raise HarnessInfrastructureError(
                    f"Worker 为 case {case['id']} 返回了无效 JSON"
                ) from exc
            if response.get("request_id") != case["id"]:
                raise HarnessInfrastructureError(f"Worker request_id 与 case {case['id']} 不一致")
            if response.get("status") not in VALID_RESULT_STATUSES:
                raise HarnessInfrastructureError(f"Worker 为 case {case['id']} 返回了无效状态")
            if not isinstance(response.get("test_id"), str) or not response["test_id"]:
                raise HarnessInfrastructureError(f"Worker 为 case {case['id']} 缺少 test_id")
            if not isinstance(response.get("facts", {}), dict):
                raise HarnessInfrastructureError(f"Worker 为 case {case['id']} 返回了无效 facts")
            if not isinstance(response.get("evidence", []), list):
                raise HarnessInfrastructureError(f"Worker 为 case {case['id']} 返回了无效 evidence")
            responses.append(response)
        return responses, completed.stderr[-12000:]

    @staticmethod
    def _evaluate_results(
        acceptance: dict[str, dict],
        cases: list[dict],
        outputs: dict[str, dict],
        evidence: dict[str, list[dict]],
    ) -> list[dict]:
        cases_by_test: dict[str, list[dict]] = defaultdict(list)
        for case in cases:
            cases_by_test[case["acceptance_test"]].append(case)
        results = []
        for stable_key, test in acceptance.items():
            failures = []
            actual = []
            for case in cases_by_test[stable_key]:
                response = outputs[case["id"]]
                passed, reason = evaluate_assertion(test["assertion"], response)
                actual.append({"case_id": case["id"], "response": response, "passed": passed})
                if not passed:
                    failures.append({"case_id": case["id"], "reason": reason})
            results.append({
                "stable_key": stable_key,
                "acceptance_test_id": test["id"],
                "acceptance_test_version": test["current_version"],
                "status": "failed" if failures else "passed",
                "actual": {"cases": actual, "failures": failures},
                "evidence": evidence.get(stable_key, []),
                "failure_kind": "assertion_not_satisfied" if failures else None,
            })
        return results

    def _command(
        self,
        command: list[str],
        run_dir: Path,
        label: str,
        *,
        timeout: float,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if shutil.which(self.docker_bin) is None:
            raise HarnessInfrastructureError(f"找不到 Docker 命令：{self.docker_bin}")
        command_log = run_dir / "commands.jsonl"
        with command_log.open("a", encoding="utf-8") as stream:
            stream.write(canonical_json({"label": label, "command": command}) + "\n")
        try:
            completed = subprocess.run(
                command,
                input=input_text,
                text=True,
                capture_output=True,
                timeout=timeout,
                env={**os.environ, "DOCKER_BUILDKIT": "1"},
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HarnessInfrastructureError(f"命令 {label} 执行失败：{exc}") from exc
        (run_dir / f"{label}.stdout.log").write_text(completed.stdout, encoding="utf-8")
        (run_dir / f"{label}.stderr.log").write_text(completed.stderr, encoding="utf-8")
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise HarnessInfrastructureError(
                f"命令 {label} 返回 {completed.returncode}：{detail[-2000:]}"
            )
        return completed
