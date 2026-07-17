import json
import tempfile
import unittest
from pathlib import Path

from agentsectool_scanner.dashboard import server
from agentsectool_scanner.store.load import load


class DashboardReportTests(unittest.TestCase):
    def test_dynamic_report_exposes_facts_rules_and_display_templates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jsonl = root / "dynamic.jsonl"
            database = root / "scan.sqlite"
            record = {
                "asset_type": "project-x",
                "detector": "dynamic/project-x",
                "ip": "192.0.2.10",
                "port": 8080,
                "is_match": True,
                "category": "confirmed_no_version",
                "matched": ["project-x.marker"],
                "facts": {"marker": "project-x"},
                "test_results": [{
                    "request_id": "request-1",
                    "test_id": "project-x.marker",
                    "status": "satisfied",
                    "facts": {"marker": "project-x"},
                    "evidence": [{"kind": "http_header", "value": "x-project: project-x"}],
                    "error": None,
                }],
                "vulnerability_rules": [{
                    "vulnerability_id": "CVE-TEST",
                    "condition": {
                        "path": "facts.marker", "operator": "eq", "value": "project-x"
                    },
                }],
                "display_templates": [{
                    "title": "Project X",
                    "facts": ["marker"],
                    "_project_test_id": "project-x.marker",
                }],
                "tls": False,
                "ts": "2026-07-15T00:00:00Z",
            }
            jsonl.write_text(json.dumps(record) + "\n", encoding="utf-8")
            self.assertEqual(load(str(database), str(jsonl)), 1)

            previous = server.DB_PATH
            server.DB_PATH = str(database)
            try:
                report = server.api_report("192.0.2.10", 8080, "project-x")
            finally:
                server.DB_PATH = previous

            self.assertEqual(report["facts"]["marker"], "project-x")
            self.assertEqual(report["project_tests"][0]["status"], "satisfied")
            self.assertEqual(report["vulnerability_matches"][0]["status"], "applicable")
            self.assertEqual(report["display_templates"][0]["title"], "Project X")
            self.assertEqual(report["summary"], "")


if __name__ == "__main__":
    unittest.main()
