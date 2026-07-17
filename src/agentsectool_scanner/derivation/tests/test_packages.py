import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agentsectool_scanner.derivation.packages import (
    PackageValidationError,
    RequestPackageImporter,
    SupplementPackageBuilder,
)
from agentsectool_scanner.derivation.repository import (
    DerivationConflictError,
    DerivationRepository,
)


class DerivationPackageTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.repo = DerivationRepository(self.root / "derivation.sqlite")
        self.importer = RequestPackageImporter(self.repo, self.root / "artifacts")

    def tearDown(self):
        self.tempdir.cleanup()

    def make_package(self, request_id="REQ-001"):
        package = self.root / f"package-{request_id}"
        package.mkdir()
        (package / "scripts").mkdir()
        (package / "notes").mkdir()
        (package / "scanner.py").write_text("print('probe')\n", encoding="utf-8")
        (package / "scripts" / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
        (package / "report.md").write_text("# Project X / CVE-TEST\n", encoding="utf-8")
        (package / "environment.yaml").write_text("service: sample\n", encoding="utf-8")
        (package / "notes" / "not-listed.txt").write_text("not imported\n", encoding="utf-8")
        manifest = {
            "schema_version": "1.0",
            "request_id": request_id,
            "code_files": ["scanner.py", "scripts/helper.py"],
            "document_file": "report.md",
            "auxiliary_files": [
                {"path": "environment.yaml", "kind": "environment_hint"}
            ],
        }
        (package / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False), encoding="utf-8"
        )
        return package

    def test_preview_and_import_create_an_immutable_inventory(self):
        package = self.make_package()
        preview = self.importer.preview(package)

        self.assertEqual(preview["request_id"], "REQ-001")
        self.assertEqual(len(preview["artifacts"]), 4)
        self.assertEqual(preview["unlisted_files"], ["notes/not-listed.txt"])

        task = self.importer.import_package(package, preview["package_hash"])
        self.assertEqual(task["request_id"], "REQ-001")
        self.assertEqual(len(task["artifacts"]), 4)
        snapshot_root = Path(task["source_storage_path"])
        self.assertTrue((snapshot_root / "snapshot.json").is_file())
        self.assertFalse((snapshot_root / "notes" / "not-listed.txt").exists())

        (package / "scanner.py").write_text("print('changed')\n", encoding="utf-8")
        self.assertEqual(
            (snapshot_root / "scanner.py").read_text(encoding="utf-8"),
            "print('probe')\n",
        )

    def test_same_request_is_idempotent_and_changed_content_conflicts(self):
        package = self.make_package()
        first = self.importer.import_package(package)
        second = self.importer.import_package(package)
        self.assertEqual(first["id"], second["id"])

        (package / "scanner.py").write_text("print('changed')\n", encoding="utf-8")
        with self.assertRaises(DerivationConflictError):
            self.importer.import_package(package)

    def test_concurrent_import_keeps_one_registered_snapshot(self):
        package = self.make_package()
        with ThreadPoolExecutor(max_workers=2) as pool:
            tasks = list(pool.map(self.importer.import_package, [package, package]))

        self.assertEqual(tasks[0]["id"], tasks[1]["id"])
        snapshot_root = Path(tasks[0]["source_storage_path"])
        self.assertTrue((snapshot_root / "snapshot.json").is_file())
        self.assertEqual(
            (snapshot_root / "scanner.py").read_text(encoding="utf-8"),
            "print('probe')\n",
        )

    def test_manifest_path_escape_is_rejected(self):
        outside = self.root / "outside.py"
        outside.write_text("print('outside')\n", encoding="utf-8")
        package = self.make_package()
        manifest_path = package / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["code_files"] = ["../outside.py"]
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(PackageValidationError):
            self.importer.preview(package)

    def test_main_document_type_is_restricted(self):
        package = self.make_package()
        (package / "report.docx").write_bytes(b"not-a-document")
        manifest_path = package / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["document_file"] = "report.docx"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(PackageValidationError, "HTML"):
            self.importer.preview(package)

    def test_supplement_is_separate_and_message_references_it(self):
        task = self.importer.import_package(self.make_package())
        builder = SupplementPackageBuilder(self.repo, self.root / "artifacts")
        supplement = builder.create(task["id"], [{
            "filename": "extra.log",
            "kind": "runtime_log",
            "content": b"trace line\n",
        }])
        message = self.repo.append_message(
            task["id"],
            role="user",
            content="结合日志继续定位并修订。",
            supplement_package_id=supplement["id"],
        )

        self.assertEqual(message["supplement_package_id"], supplement["id"])
        self.assertNotEqual(task["source_storage_path"], supplement["storage_path"])
        self.assertEqual(
            Path(supplement["storage_path"], "extra.log").read_bytes(), b"trace line\n"
        )

    def test_confirmed_acceptance_cannot_be_changed_by_agent(self):
        task = self.importer.import_package(self.make_package())
        definition = {
            "stable_key": "probe.positive",
            "name": "正向样例命中",
            "purpose": "验证项目测试项能够识别正向样例。",
            "blocking": True,
            "enabled": True,
            "assertion": {"path": "status", "operator": "eq", "value": "satisfied"},
            "user_confirmed": True,
        }
        first = self.repo.upsert_acceptance_test(task["id"], definition, actor="user")
        with self.assertRaises(DerivationConflictError):
            self.repo.upsert_acceptance_test(
                task["id"],
                {**definition, "purpose": "智能体尝试改写说明。", "user_confirmed": False},
                actor="agent",
            )
        second = self.repo.upsert_acceptance_test(
            task["id"],
            {**definition, "purpose": "补充人工确认后的说明。"},
            actor="user",
            change_reason="调整表述",
        )
        self.assertEqual(first["version"], 1)
        self.assertEqual(second["version"], 2)
        self.assertEqual(len(self.repo.acceptance_history(first["id"])), 2)

    def test_acceptance_key_and_disable_reason_are_validated(self):
        task = self.importer.import_package(self.make_package())
        definition = {
            "stable_key": "probe.positive",
            "name": "正向样例命中",
            "purpose": "验证项目测试项能够识别正向样例。",
            "blocking": True,
            "enabled": True,
            "assertion": {"path": "status", "operator": "eq", "value": "satisfied"},
        }
        with self.assertRaisesRegex(ValueError, "stable_key"):
            self.repo.upsert_acceptance_test(
                task["id"], {**definition, "stable_key": "bad'key"}, actor="user"
            )
        with self.assertRaisesRegex(ValueError, "停用"):
            self.repo.upsert_acceptance_test(
                task["id"], {**definition, "enabled": False}, actor="user"
            )
        result = self.repo.upsert_acceptance_test(
            task["id"],
            {**definition, "enabled": False},
            actor="user",
            change_reason="该样例环境已失效",
        )
        self.assertFalse(result["enabled"])


if __name__ == "__main__":
    unittest.main()
