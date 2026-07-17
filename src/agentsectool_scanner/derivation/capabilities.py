"""Candidate capability packaging and admission registry."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

from agentsectool_scanner.paths import CAPABILITY_PACKAGES, DERIVATION_ARTIFACTS

from .repository import (
    DerivationConflictError,
    DerivationRepository,
    canonical_json,
    utc_now,
)

ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
MAX_CAPABILITY_BYTES = 64 * 1024 * 1024


class CapabilityValidationError(ValueError):
    """Raised when a candidate capability does not satisfy its contract."""


class CapabilityRegistry:
    def __init__(
        self,
        repository: DerivationRepository,
        *,
        candidate_root: str | Path = DERIVATION_ARTIFACTS / "candidates",
        registry_root: str | Path = CAPABILITY_PACKAGES,
        docker_bin: str = "docker",
    ):
        self.repository = repository
        self.candidate_root = Path(candidate_root)
        self.registry_root = Path(registry_root)
        self.docker_bin = docker_bin
        self._index_lock = threading.Lock()

    def register_candidate(self, task_id: str, attempt_id: str) -> dict:
        attempt = self.repository.get_attempt(attempt_id)
        if attempt["task_id"] != task_id:
            raise CapabilityValidationError("attempt 不属于当前任务")
        if attempt["status"] != "candidate":
            raise CapabilityValidationError("attempt 尚未通过 Harness")
        workspace = Path(attempt["workspace_path"]).resolve()
        manifest_path = workspace / "capability.json"
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise CapabilityValidationError("attempt 根目录缺少 capability.json")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CapabilityValidationError(f"capability.json 无效：{exc}") from exc
        self.validate_manifest(manifest)
        harness = next(
            (
                item for item in self.repository.list_harness_runs(task_id)
                if item["attempt_id"] == attempt_id and item["status"] == "passed"
            ),
            None,
        )
        if not harness or not harness.get("image_reference") or not harness.get("image_digest"):
            raise CapabilityValidationError("通过的 Harness 运行缺少 worker 镜像引用或 digest")
        snapshot = self.candidate_root / task_id / attempt_id
        if snapshot.exists():
            raise DerivationConflictError("当前 attempt 已登记候选能力包")
        self._validate_tree(workspace)
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        temp = Path(tempfile.mkdtemp(prefix=".candidate-", dir=snapshot.parent))
        try:
            shutil.rmtree(temp)
            shutil.copytree(workspace, temp, symlinks=False)
            manifest["runtime"] = {
                "protocol": "jsonl-v1",
                "image_reference": harness["image_reference"],
                "image_digest": harness["image_digest"],
            }
            manifest["provenance"] = {
                "task_id": task_id,
                "attempt_id": attempt_id,
                "input_hash": attempt["input_hash"],
                "harness_run_id": harness["id"],
                "registered_at": utc_now(),
            }
            (temp / "capability.json").write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            os.replace(temp, snapshot)
            return self.repository.create_capability_package(
                task_id=task_id,
                attempt_id=attempt_id,
                asset_type=manifest["asset_type"],
                package_path=str(snapshot),
                image_reference=harness["image_reference"],
                image_digest=harness["image_digest"],
                manifest=manifest,
            )
        except Exception:
            shutil.rmtree(temp, ignore_errors=True)
            shutil.rmtree(snapshot, ignore_errors=True)
            raise

    def approve(self, capability_id: str, note: str | None = None) -> dict:
        capability = self.repository.get_capability(capability_id)
        if capability["status"] != "candidate":
            raise DerivationConflictError("只有候选能力包可以入仓")
        observed_digest = self._inspect_image(capability["image_reference"])
        if observed_digest != capability["image_digest"]:
            raise DerivationConflictError(
                f"worker 镜像 digest 已变化：期望 {capability['image_digest']}，实际 {observed_digest}"
            )
        manifest = capability["manifest"]
        destination = (
            self.registry_root
            / manifest["asset_type"]
            / manifest["capability_id"]
            / f"v{capability['version']}"
        )
        if destination.exists():
            raise DerivationConflictError(f"能力入仓目录已存在：{destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temp = Path(tempfile.mkdtemp(prefix=".admission-", dir=destination.parent))
        try:
            shutil.rmtree(temp)
            shutil.copytree(capability["package_path"], temp, symlinks=False)
            manifest["admission"] = {
                "status": "admitted",
                "admitted_at": utc_now(),
                "image_digest": observed_digest,
            }
            (temp / "capability.json").write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            os.replace(temp, destination)
            self._update_index(capability, destination)
            try:
                return self.repository.review_capability(
                    capability_id,
                    approve=True,
                    note=note,
                    package_path=str(destination),
                    manifest=manifest,
                )
            except Exception:
                self._remove_index(capability_id)
                raise
        except Exception:
            shutil.rmtree(temp, ignore_errors=True)
            shutil.rmtree(destination, ignore_errors=True)
            raise

    def reject(self, capability_id: str, note: str) -> dict:
        if not note.strip():
            raise ValueError("退回候选能力包必须填写原因")
        return self.repository.review_capability(
            capability_id, approve=False, note=note.strip()
        )

    @staticmethod
    def validate_manifest(manifest: dict) -> None:
        if not isinstance(manifest, dict) or manifest.get("schema_version") != "1.0":
            raise CapabilityValidationError("capability.schema_version 必须为 1.0")
        for key in ("capability_id", "asset_type"):
            if not isinstance(manifest.get(key), str) or not ID_RE.fullmatch(manifest[key]):
                raise CapabilityValidationError(f"capability.{key} 格式无效")
        project = manifest.get("project")
        if not isinstance(project, dict) or not isinstance(project.get("name"), str) or not project["name"].strip():
            raise CapabilityValidationError("capability.project.name 不能为空")
        ports = manifest.get("default_ports")
        if (
            not isinstance(ports, list)
            or not ports
            or any(not isinstance(port, int) or not 1 <= port <= 65535 for port in ports)
        ):
            raise CapabilityValidationError("capability.default_ports 必须是有效端口数组")
        tests = manifest.get("project_tests")
        if not isinstance(tests, list) or len(tests) != 1:
            raise CapabilityValidationError("一个候选能力包必须包含一个独立项目测试项")
        test = tests[0]
        if any(not isinstance(test.get(key), str) or not test[key].strip() for key in ("test_id", "name", "description")):
            raise CapabilityValidationError("项目测试项缺少 test_id、name 或 description")
        if not ID_RE.fullmatch(test["test_id"]):
            raise CapabilityValidationError("project_test.test_id 格式无效")
        identity = manifest.get("identity_rule")
        if not isinstance(identity, dict) or identity.get("operator") not in {"all", "any"}:
            raise CapabilityValidationError("identity_rule.operator 必须为 all 或 any")
        required = identity.get("tests")
        if not isinstance(required, list) or test["test_id"] not in required:
            raise CapabilityValidationError("identity_rule.tests 必须引用当前项目测试项")
        rules = manifest.get("vulnerability_rules")
        if not isinstance(rules, list) or not rules:
            raise CapabilityValidationError("能力包至少需要一条漏洞关联规则")
        for rule in rules:
            if (
                not isinstance(rule, dict)
                or not isinstance(rule.get("vulnerability_id"), str)
                or not isinstance(rule.get("condition"), dict)
            ):
                raise CapabilityValidationError("漏洞关联规则缺少 vulnerability_id 或 condition")
        display = manifest.get("display_template")
        if not isinstance(display, dict):
            raise CapabilityValidationError("能力包缺少 display_template")
        if not isinstance(display.get("title"), str) or not display["title"].strip():
            raise CapabilityValidationError("display_template.title 不能为空")
        fact_fields = display.get("facts")
        if (
            not isinstance(fact_fields, list)
            or any(not isinstance(field, str) or not field.strip() for field in fact_fields)
        ):
            raise CapabilityValidationError("display_template.facts 必须是字段名数组")

    @staticmethod
    def _validate_tree(root: Path) -> None:
        total = 0
        for path in root.rglob("*"):
            if path.is_symlink():
                raise CapabilityValidationError(f"候选能力目录不接受符号链接：{path}")
            if path.is_file():
                total += path.stat().st_size
                if total > MAX_CAPABILITY_BYTES:
                    raise CapabilityValidationError("候选能力目录超过 64 MiB")

    def _inspect_image(self, image_reference: str) -> str:
        if shutil.which(self.docker_bin) is None:
            raise DerivationConflictError("找不到 Docker，无法核验候选 worker 镜像")
        completed = subprocess.run(
            [self.docker_bin, "image", "inspect", "--format", "{{.Id}}", image_reference],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            raise DerivationConflictError(
                f"无法核验 worker 镜像：{completed.stderr.strip()[-1000:]}"
            )
        return completed.stdout.strip()

    def _update_index(self, capability: dict, destination: Path) -> None:
        with self._index_lock:
            self.registry_root.mkdir(parents=True, exist_ok=True)
            index_path = self.registry_root / "index.json"
            if index_path.is_file():
                index = json.loads(index_path.read_text(encoding="utf-8"))
            else:
                index = {"schema_version": "1.0", "capabilities": {}}
            relative = destination.relative_to(self.registry_root).as_posix() + "/capability.json"
            manifest = capability["manifest"]
            capabilities = index.setdefault("capabilities", {})
            entries = capabilities.get(capability["asset_type"], [])
            if isinstance(entries, dict):
                entries = [entries]
            entries = [
                item for item in entries
                if item.get("capability_id") != manifest["capability_id"]
            ]
            entries.append({
                "capability_id": manifest["capability_id"],
                "capability_package_id": capability["id"],
                "manifest_path": relative,
                "image_digest": capability["image_digest"],
            })
            capabilities[capability["asset_type"]] = sorted(
                entries, key=lambda item: item["capability_id"]
            )
            index["updated_at"] = utc_now()
            self._write_index(index_path, index)

    def _is_indexed(self, capability_id: str) -> bool:
        index_path = self.registry_root / "index.json"
        if not index_path.is_file():
            return False
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return False
        return any(
            item.get("capability_package_id") == capability_id
            for entries in index.get("capabilities", {}).values()
            for item in ([entries] if isinstance(entries, dict) else entries)
        )

    def _remove_index(self, capability_id: str) -> None:
        with self._index_lock:
            index_path = self.registry_root / "index.json"
            if not index_path.is_file():
                return
            try:
                index = json.loads(index_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return
            capabilities = index.get("capabilities", {})
            removed = False
            for asset_type, raw_entries in list(capabilities.items()):
                entries = [raw_entries] if isinstance(raw_entries, dict) else raw_entries
                kept = [
                    item for item in entries
                    if item.get("capability_package_id") != capability_id
                ]
                removed = removed or len(kept) != len(entries)
                if kept:
                    capabilities[asset_type] = kept
                else:
                    capabilities.pop(asset_type, None)
            if removed:
                index["updated_at"] = utc_now()
                self._write_index(index_path, index)

    @staticmethod
    def _write_index(index_path: Path, index: dict) -> None:
        fd, temp_name = tempfile.mkstemp(prefix=".index-", dir=index_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(json.dumps(index, ensure_ascii=False, indent=2) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, index_path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
