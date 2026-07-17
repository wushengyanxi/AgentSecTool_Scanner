import base64
import json
import tempfile
import unittest
from pathlib import Path

from agentsectool_scanner.derivation.service import DerivationService
from agentsectool_scanner.derivation.web import DerivationAPI


class DerivationAPITests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.service = DerivationService(
            db_path=self.root / "derivation.sqlite",
            artifacts_root=self.root / "artifacts",
            runs_root=self.root / "runs",
            capability_root=self.root / "capabilities",
            config_path=self.root / "missing.ini",
        )
        self.api = DerivationAPI(self.service)
        self.package = self.root / "request"
        self.package.mkdir()
        (self.package / "probe.py").write_text("print('probe')\n", encoding="utf-8")
        (self.package / "report.md").write_text("# Project X\n", encoding="utf-8")
        (self.package / "manifest.json").write_text(json.dumps({
            "schema_version": "1.0",
            "request_id": "WEB-FIXTURE",
            "code_files": ["probe.py"],
            "document_file": "report.md",
        }), encoding="utf-8")

    def tearDown(self):
        self.tempdir.cleanup()

    def test_import_message_attachment_and_acceptance_routes(self):
        code, preview = self.api.handle(
            "POST", "/api/derivation/imports/preview", {},
            {"package_path": str(self.package)},
        )
        self.assertEqual(code, 200)
        self.assertEqual(preview["request_id"], "WEB-FIXTURE")

        code, task = self.api.handle(
            "POST", "/api/derivation/imports", {},
            {"package_path": str(self.package), "expected_hash": preview["package_hash"]},
        )
        self.assertEqual(code, 201)
        code, sent = self.api.handle(
            "POST", f"/api/derivation/tasks/{task['id']}/messages", {},
            {
                "content": "结合补充日志继续。",
                "attachments": [{
                    "filename": "runtime.log",
                    "kind": "runtime_log",
                    "content_base64": base64.b64encode(b"failure trace\n").decode(),
                }],
            },
        )
        self.assertEqual(code, 202)
        self.assertFalse(sent["agent_started"])
        self.assertIsNotNone(sent["message"]["supplement_package_id"])

        definition = {
            "stable_key": "positive.sample",
            "name": "正向样例命中",
            "purpose": "验证项目条件。",
            "enabled": True,
            "blocking": True,
            "assertion": {"path": "status", "operator": "eq", "value": "satisfied"},
        }
        code, acceptance = self.api.handle(
            "POST", f"/api/derivation/tasks/{task['id']}/acceptance-tests", {},
            {"definition": definition, "reason": "人工建立验收口径"},
        )
        self.assertEqual(code, 201)
        self.assertTrue(acceptance["user_confirmed"])

        code, detail = self.api.handle(
            "GET", f"/api/derivation/tasks/{task['id']}", {}, None
        )
        self.assertEqual(code, 200)
        self.assertEqual(len(detail["messages"]), 1)
        self.assertEqual(len(detail["acceptance_tests"]), 1)
        self.assertEqual(detail["status"], "waiting_user")


if __name__ == "__main__":
    unittest.main()
