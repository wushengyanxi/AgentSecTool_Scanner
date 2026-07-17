import json
import tempfile
import unittest
from pathlib import Path

from agentsectool_scanner.derivation.capabilities import CapabilityRegistry
from agentsectool_scanner.derivation.packages import RequestPackageImporter
from agentsectool_scanner.derivation.repository import DerivationRepository


class FakeImageRegistry(CapabilityRegistry):
    def _inspect_image(self, image_reference):
        return "sha256:verified-worker"


class CapabilityRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.repo = DerivationRepository(self.root / "derivation.sqlite")
        package = self.root / "request"
        package.mkdir()
        (package / "probe.py").write_text("print('probe')\n", encoding="utf-8")
        (package / "report.md").write_text("# Project X / CVE-TEST\n", encoding="utf-8")
        (package / "manifest.json").write_text(json.dumps({
            "schema_version": "1.0",
            "request_id": "CAPABILITY-FIXTURE",
            "code_files": ["probe.py"],
            "document_file": "report.md",
        }), encoding="utf-8")
        self.task = RequestPackageImporter(
            self.repo, self.root / "artifacts"
        ).import_package(package)
        self.acceptance = self.repo.upsert_acceptance_test(self.task["id"], {
            "stable_key": "positive.sample",
            "name": "正向样例命中",
            "purpose": "验证项目条件。",
            "enabled": True,
            "blocking": True,
            "user_confirmed": True,
            "assertion": {"path": "status", "operator": "eq", "value": "satisfied"},
        }, actor="user")
        self.workspace = self.root / "attempt"
        self.workspace.mkdir()
        self._write_capability(self.workspace)
        self.attempt = self.repo.create_attempt(
            self.task["id"],
            agent_run_id=None,
            input_hash=self.repo.input_hash(self.task["id"]),
            workspace_path=str(self.workspace),
        )
        run = self.repo.start_harness_run(
            self.task["id"], self.attempt["id"], str(self.root / "run")
        )
        self.repo.finish_harness_run(
            run["id"],
            status="passed",
            image_reference="agentsectool-derivation:fixture",
            image_digest="sha256:verified-worker",
            results=[{
                "acceptance_test_id": self.acceptance["id"],
                "acceptance_test_version": self.acceptance["version"],
                "status": "passed",
                "actual": {"status": "satisfied"},
                "evidence": [{"case_id": "positive-1"}],
            }],
        )
        self.registry = FakeImageRegistry(
            self.repo,
            candidate_root=self.root / "candidates",
            registry_root=self.root / "registry",
        )

    def tearDown(self):
        self.tempdir.cleanup()

    @staticmethod
    def _write_capability(
        workspace,
        capability_id="project-x-marker",
        test_id="project-x.marker",
    ):
        (workspace / "worker").mkdir()
        (workspace / "worker" / "worker.py").write_text("# worker\n", encoding="utf-8")
        manifest = {
            "schema_version": "1.0",
            "capability_id": capability_id,
            "asset_type": "project-x",
            "project": {"name": "Project X"},
            "default_ports": [8080],
            "project_tests": [{
                "test_id": test_id,
                "name": "Project X 标记",
                "description": "读取公开响应中的稳定项目标记。",
                "version": 1,
            }],
            "identity_rule": {"operator": "all", "tests": [test_id]},
            "vulnerability_rules": [{
                "vulnerability_id": "CVE-TEST",
                "condition": {"path": "facts.vulnerable", "operator": "eq", "value": True},
            }],
            "display_template": {"title": "Project X", "facts": ["marker"]},
        }
        (workspace / "capability.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def test_candidate_is_snapshotted_and_approval_updates_runtime_index(self):
        candidate = self.registry.register_candidate(self.task["id"], self.attempt["id"])
        self.assertEqual(candidate["status"], "candidate")
        self.assertNotEqual(candidate["package_path"], str(self.workspace))
        self.assertEqual(candidate["manifest"]["runtime"]["protocol"], "jsonl-v1")

        admitted = self.registry.approve(candidate["id"], "证据完整")
        self.assertEqual(admitted["status"], "admitted")
        index = json.loads((self.root / "registry" / "index.json").read_text(encoding="utf-8"))
        entries = index["capabilities"]["project-x"]
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["capability_package_id"], candidate["id"])
        self.assertTrue(
            (self.root / "registry" / entry["manifest_path"]).is_file()
        )
        self.assertEqual(self.repo.get_task(self.task["id"])["status"], "admitted")

    def test_sibling_project_test_does_not_supersede_admitted_capability(self):
        first = self.registry.register_candidate(self.task["id"], self.attempt["id"])
        first = self.registry.approve(first["id"], "首个测试项证据完整")

        workspace = self.root / "attempt-version"
        workspace.mkdir()
        self._write_capability(workspace, "project-x-version", "project-x.version")
        attempt = self.repo.create_attempt(
            self.task["id"],
            agent_run_id=None,
            input_hash=self.repo.input_hash(self.task["id"]),
            workspace_path=str(workspace),
        )
        run = self.repo.start_harness_run(
            self.task["id"], attempt["id"], str(self.root / "run-version")
        )
        self.repo.finish_harness_run(
            run["id"],
            status="passed",
            image_reference="agentsectool-derivation:fixture-version",
            image_digest="sha256:verified-worker",
            results=[{
                "acceptance_test_id": self.acceptance["id"],
                "acceptance_test_version": self.acceptance["version"],
                "status": "passed",
                "actual": {"status": "satisfied"},
                "evidence": [{"case_id": "positive-version"}],
            }],
        )
        second = self.registry.register_candidate(self.task["id"], attempt["id"])
        second = self.registry.approve(second["id"], "第二个测试项证据完整")

        self.assertEqual(self.repo.get_capability(first["id"])["status"], "admitted")
        self.assertEqual(self.repo.get_capability(second["id"])["status"], "admitted")
        index = json.loads((self.root / "registry" / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(
            [item["capability_id"] for item in index["capabilities"]["project-x"]],
            ["project-x-marker", "project-x-version"],
        )


if __name__ == "__main__":
    unittest.main()
