"""Application service used by the derivation HTTP workbench."""

from __future__ import annotations

import base64
import binascii
from pathlib import Path

from agentsectool_scanner.paths import (
    DERIVATION_ARTIFACTS,
    DERIVATION_CONFIG,
    DERIVATION_DB,
    DERIVATION_RUNS,
    CAPABILITY_PACKAGES,
)

from .agent import AgentCoordinator, DerivationAgent
from .capabilities import CapabilityRegistry
from .config import config_status, load_agent_config
from .harness import LocalDockerHarness
from .packages import RequestPackageImporter, SupplementPackageBuilder
from .repository import DerivationRepository


class DerivationService:
    def __init__(
        self,
        *,
        db_path: str | Path = DERIVATION_DB,
        artifacts_root: str | Path = DERIVATION_ARTIFACTS,
        runs_root: str | Path = DERIVATION_RUNS,
        capability_root: str | Path = CAPABILITY_PACKAGES,
        config_path: str | Path = DERIVATION_CONFIG,
    ):
        self.repository = DerivationRepository(db_path)
        self.repository.initialize()
        self.artifacts_root = Path(artifacts_root)
        self.runs_root = Path(runs_root)
        self.config_path = Path(config_path)
        self.importer = RequestPackageImporter(self.repository, self.artifacts_root)
        self.supplements = SupplementPackageBuilder(self.repository, self.artifacts_root)
        self.capabilities = CapabilityRegistry(
            self.repository,
            candidate_root=self.artifacts_root / "candidates",
            registry_root=capability_root,
        )
        self.coordinator = AgentCoordinator(self._agent)

    def _agent(self) -> DerivationAgent:
        config = load_agent_config(self.config_path)
        harness = LocalDockerHarness(self.repository, self.runs_root)
        return DerivationAgent(
            self.repository,
            harness,
            config,
            capability_registry=self.capabilities,
            attempts_root=self.artifacts_root / "attempts",
        )

    def status(self) -> dict:
        return config_status(self.config_path)

    def preview_import(self, package_path: str) -> dict:
        preview = self.importer.preview(package_path)
        return {
            key: value
            for key, value in preview.items()
            if key != "artifacts"
        } | {
            "artifacts": [
                {key: value for key, value in item.items() if key != "source_path"}
                for item in preview["artifacts"]
            ]
        }

    def import_package(self, package_path: str, expected_hash: str | None = None) -> dict:
        return self.importer.import_package(package_path, expected_hash)

    def list_tasks(self, *, status: str | None = None, query: str | None = None) -> list[dict]:
        return self.repository.list_tasks(status=status, query=query)

    def task_detail(self, task_id: str) -> dict:
        task = self.repository.get_task(task_id)
        task["materials"] = self.repository.list_artifacts(task_id)
        for material in task["materials"]:
            material.pop("storage_path", None)
        task["messages"] = self.repository.list_messages(task_id)
        task["events"] = self.repository.list_events(task_id)
        task["acceptance_tests"] = self.repository.list_acceptance_tests(task_id)
        task["attempts"] = self.repository.list_attempts(task_id)
        task["harness_runs"] = self.repository.list_harness_runs(task_id)
        task["capabilities"] = self.repository.list_capabilities(task_id)
        return task

    def send_message(self, task_id: str, content: str, attachments: list[dict] | None = None) -> dict:
        supplement_id = None
        if attachments:
            uploads = []
            for attachment in attachments:
                encoded = attachment.get("content_base64")
                if not isinstance(encoded, str):
                    raise ValueError("附件缺少 content_base64")
                try:
                    raw = base64.b64decode(encoded, validate=True)
                except (ValueError, binascii.Error) as exc:
                    raise ValueError("附件 content_base64 无效") from exc
                uploads.append({
                    "filename": attachment.get("filename"),
                    "kind": attachment.get("kind") or "user_attachment",
                    "content": raw,
                })
            supplement = self.supplements.create(task_id, uploads)
            supplement_id = supplement["id"]
        message = self.repository.append_message(
            task_id,
            role="user",
            content=content,
            supplement_package_id=supplement_id,
        )
        status = self.status()
        if not status.get("enabled"):
            self.repository.set_task_status(task_id, "waiting_user")
            self.repository.add_event(task_id, "agent_configuration_required", status, message["id"])
            return {"message": message, "agent_started": False, "queued": False, "config": status}
        started = self.coordinator.submit(task_id, message["id"])
        if not started:
            self.repository.add_event(
                task_id, "user_message_queued", {"message_id": message["id"]}, message["id"]
            )
        return {"message": message, "agent_started": started, "queued": not started}

    def save_acceptance_test(self, task_id: str, definition: dict, reason: str | None = None) -> dict:
        return self.repository.upsert_acceptance_test(
            task_id,
            definition,
            actor="user",
            change_reason=reason,
        )

    def confirm_acceptance_test(self, task_id: str, stable_key: str) -> dict:
        current = next(
            (
                item for item in self.repository.list_acceptance_tests(task_id)
                if item["stable_key"] == stable_key
            ),
            None,
        )
        if current is None:
            raise ValueError(f"验收项不存在：{stable_key}")
        definition = {
            "stable_key": current["stable_key"],
            "name": current["name"],
            "purpose": current["purpose"],
            "enabled": current["enabled"],
            "blocking": current["blocking"],
            "assertion": current["assertion"],
            "script_artifact_id": current["script_artifact_id"],
            "user_confirmed": True,
        }
        return self.repository.upsert_acceptance_test(
            task_id,
            definition,
            actor="user",
            change_reason="用户确认当前验收口径",
        )

    def approve_capability(self, capability_id: str, note: str | None = None) -> dict:
        return self.capabilities.approve(capability_id, note)

    def reject_capability(self, capability_id: str, note: str) -> dict:
        return self.capabilities.reject(capability_id, note)
