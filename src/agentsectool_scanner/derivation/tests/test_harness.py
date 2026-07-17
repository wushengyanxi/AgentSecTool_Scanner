import json
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from agentsectool_scanner.derivation.capabilities import CapabilityRegistry
from agentsectool_scanner.derivation.harness import (
    HarnessConfigurationError,
    LocalDockerHarness,
    evaluate_assertion,
)
from agentsectool_scanner.derivation.packages import RequestPackageImporter
from agentsectool_scanner.derivation.repository import DerivationRepository
from agentsectool_scanner.store import load as store_load

REPO_ROOT = Path(__file__).resolve().parents[4]
ASSETPROBE = REPO_ROOT / "prober" / "bin" / "assetprobe"


class AssertionTests(unittest.TestCase):
    def test_nested_boolean_assertions(self):
        actual = {"status": "satisfied", "facts": {"title": "Project X", "score": 3}}
        assertion = {
            "all": [
                {"path": "status", "operator": "eq", "value": "satisfied"},
                {"path": "facts.score", "operator": "ge", "value": 2},
                {"not": {"path": "facts.title", "operator": "eq", "value": "Other"}},
            ]
        }
        self.assertEqual(evaluate_assertion(assertion, actual), (True, None))

    def test_missing_path_is_reported(self):
        passed, reason = evaluate_assertion(
            {"path": "facts.version", "operator": "eq", "value": "1.0"},
            {"facts": {}},
        )
        self.assertFalse(passed)
        self.assertIn("facts.version", reason)


class ComposePolicyTests(unittest.TestCase):
    def test_host_port_and_non_internal_network_are_rejected(self):
        config = {
            "services": {"target": {"ports": [{"target": 80, "published": "8080"}]}},
            "networks": {"default": {"name": "test_default", "internal": False}},
        }
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(HarnessConfigurationError):
                LocalDockerHarness._validate_compose(
                    config, Path(temp), {"network": "default"}
                )


@unittest.skipUnless(shutil.which("docker"), "Docker is not available")
class LocalDockerHarnessIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.repo = DerivationRepository(self.root / "derivation.sqlite")
        self.task = self._create_task()
        self.workspace = self.root / "attempt"
        self._write_fixture(self.workspace)
        self.attempt = self.repo.create_attempt(
            self.task["id"],
            agent_run_id=None,
            input_hash=self.repo.input_hash(self.task["id"]),
            workspace_path=str(self.workspace),
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def _create_task(self):
        package = self.root / "request"
        package.mkdir()
        (package / "probe.py").write_text("print('source')\n", encoding="utf-8")
        (package / "report.md").write_text("# Fixture\n", encoding="utf-8")
        (package / "manifest.json").write_text(json.dumps({
            "schema_version": "1.0",
            "request_id": "HARNESS-FIXTURE",
            "code_files": ["probe.py"],
            "document_file": "report.md",
        }), encoding="utf-8")
        task = RequestPackageImporter(self.repo, self.root / "artifacts").import_package(package)
        self.repo.upsert_acceptance_test(task["id"], {
            "stable_key": "positive.sample",
            "name": "正向样例命中",
            "purpose": "验证项目测试项识别带固定标记的服务。",
            "blocking": True,
            "enabled": True,
            "user_confirmed": True,
            "assertion": {
                "all": [
                    {"path": "status", "operator": "eq", "value": "satisfied"},
                    {"path": "facts.marker", "operator": "eq", "value": "fixture-ok"},
                ]
            },
        }, actor="user")
        return task

    @staticmethod
    def _write_fixture(workspace: Path):
        target = workspace / "environment" / "target"
        worker = workspace / "worker"
        target.mkdir(parents=True)
        worker.mkdir(parents=True)
        (target / "Dockerfile").write_text(
            "FROM python:3.12-slim\nCOPY server.py /app/server.py\n"
            "CMD [\"python\", \"/app/server.py\"]\n",
            encoding="utf-8",
        )
        (target / "server.py").write_text(
            "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
            "class H(BaseHTTPRequestHandler):\n"
            "    def do_GET(self):\n"
            "        body=b'fixture-ok'\n"
            "        self.send_response(200); self.send_header('Content-Length', str(len(body)))\n"
            "        self.end_headers(); self.wfile.write(body)\n"
            "    def log_message(self, *args): pass\n"
            "HTTPServer(('0.0.0.0', 8080), H).serve_forever()\n",
            encoding="utf-8",
        )
        (workspace / "environment" / "compose.yaml").write_text(
            "services:\n"
            "  target:\n"
            "    build: ./target\n"
            "    healthcheck:\n"
            "      test: [\"CMD\", \"python\", \"-c\", "
            "\"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080', timeout=1)\"]\n"
            "      interval: 1s\n"
            "      timeout: 1s\n"
            "      retries: 20\n"
            "networks:\n"
            "  default:\n"
            "    internal: true\n",
            encoding="utf-8",
        )
        (worker / "Dockerfile").write_text(
            "FROM python:3.12-slim\nCOPY worker.py /app/worker.py\n"
            "ENTRYPOINT [\"python\", \"/app/worker.py\"]\n",
            encoding="utf-8",
        )
        (worker / "worker.py").write_text(
            "import json, sys, urllib.request\n"
            "for line in sys.stdin:\n"
            "    req=json.loads(line); target=req['target']\n"
            "    try:\n"
            "        body=urllib.request.urlopen(f\"http://{target['host']}:{target['port']}\", timeout=5).read().decode()\n"
            "        ok='fixture-ok' in body\n"
            "        out={'request_id':req['request_id'],'test_id':'fixture.marker','status':'satisfied' if ok else 'not_satisfied','facts':{'marker':body},'evidence':[{'kind':'http_body','value':body}],'error':None}\n"
            "    except Exception as exc:\n"
            "        out={'request_id':req['request_id'],'test_id':'fixture.marker','status':'error','facts':{},'evidence':[],'error':str(exc)}\n"
            "    print(json.dumps(out), flush=True)\n",
            encoding="utf-8",
        )
        (workspace / "harness.json").write_text(json.dumps({
            "schema_version": "1.0",
            "project_test_id": "fixture.marker",
            "worker": {"context": "worker", "dockerfile": "Dockerfile"},
            "environments": [{
                "id": "positive",
                "compose_file": "environment/compose.yaml",
                "network": "default",
                "wait_timeout_seconds": 30,
            }],
            "cases": [{
                "id": "positive-1",
                "environment_id": "positive",
                "acceptance_test": "positive.sample",
                "target": {"host": "target", "port": 8080, "tls": False},
                "timeout_ms": 5000,
            }],
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        (workspace / "capability.json").write_text(json.dumps({
            "schema_version": "1.0",
            "capability_id": "fixture-marker",
            "asset_type": "fixture-project",
            "project": {"name": "Fixture Project"},
            "default_ports": [8080],
            "project_tests": [{
                "test_id": "fixture.marker",
                "name": "Fixture marker",
                "description": "Reads the public fixture marker.",
                "version": 1,
            }],
            "identity_rule": {"operator": "all", "tests": ["fixture.marker"]},
            "vulnerability_rules": [{
                "vulnerability_id": "CVE-FIXTURE",
                "condition": {
                    "path": "facts.marker", "operator": "eq", "value": "fixture-ok"
                },
            }],
            "display_template": {"title": "Fixture Project", "facts": ["marker"]},
        }, ensure_ascii=False, indent=2), encoding="utf-8")

    def test_worker_is_built_and_validated_against_an_isolated_target(self):
        harness = LocalDockerHarness(self.repo, self.root / "runs")
        result = harness.run(self.task["id"], self.attempt["id"])
        self.assertEqual(result["status"], "passed", result.get("error"))
        self.assertTrue(result["image_digest"].startswith("sha256:"))
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["status"], "passed")

    @unittest.skipUnless(ASSETPROBE.is_file(), "assetprobe binary has not been built")
    def test_admitted_worker_scans_a_container_and_facts_are_loaded(self):
        harness = LocalDockerHarness(self.repo, self.root / "runs")
        run = harness.run(self.task["id"], self.attempt["id"])
        self.assertEqual(run["status"], "passed", run.get("error"))
        registry = CapabilityRegistry(
            self.repo,
            candidate_root=self.root / "candidates",
            registry_root=self.root / "capabilities",
        )
        candidate = registry.register_candidate(self.task["id"], self.attempt["id"])
        admitted = registry.approve(candidate["id"], "端到端验证")
        self.assertEqual(admitted["status"], "admitted")

        container = f"ast-fixture-{uuid.uuid4().hex[:10]}"
        output = self.root / "dynamic.jsonl"
        db = self.root / "scan.sqlite"
        try:
            subprocess.run([
                "docker", "run", "-d", "--rm", "--name", container,
                "python:3.12-slim", "sh", "-c",
                "mkdir -p /tmp/site && printf fixture-ok >/tmp/site/index.html && "
                "python -m http.server 8080 --directory /tmp/site",
            ], check=True, capture_output=True, text=True, timeout=60)
            for _ in range(20):
                ready = subprocess.run([
                    "docker", "exec", container, "python", "-c",
                    "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080', timeout=1)",
                ], capture_output=True, text=True, timeout=5)
                if ready.returncode == 0:
                    break
                time.sleep(0.25)
            else:
                self.fail("fixture target did not become ready")
            target_ip = subprocess.run([
                "docker", "inspect", "--format",
                "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container,
            ], check=True, capture_output=True, text=True, timeout=10).stdout.strip()
            scan = subprocess.run([
                str(ASSETPROBE),
                "--type", "fixture-project",
                "--capabilities", str(self.root / "capabilities"),
                "--concurrency", "1",
                "--port", "8080",
                "--timeout", "5s",
                "-o", str(output),
                target_ip,
            ], capture_output=True, text=True, timeout=60)
            self.assertEqual(scan.returncode, 0, scan.stderr)
            rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(rows[0]["asset_type"], "fixture-project")
            self.assertTrue(rows[0]["is_match"])
            self.assertEqual(rows[0]["facts"]["marker"], "fixture-ok")
            self.assertEqual(rows[0]["display_templates"][0]["title"], "Fixture Project")

            self.assertEqual(store_load.load(str(db), str(output)), 1)
            conn = sqlite3.connect(db)
            try:
                self.assertEqual(
                    conn.execute(
                        "SELECT test_id, status FROM project_test_results"
                    ).fetchone(),
                    ("fixture.marker", "satisfied"),
                )
                self.assertEqual(
                    conn.execute(
                        "SELECT vulnerability_id, status FROM vulnerability_matches"
                    ).fetchone(),
                    ("CVE-FIXTURE", "applicable"),
                )
                presentation = conn.execute(
                    "SELECT template FROM observation_presentations"
                ).fetchone()
                self.assertEqual(json.loads(presentation[0])[0]["title"], "Fixture Project")
            finally:
                conn.close()
        finally:
            subprocess.run(
                ["docker", "rm", "-f", container], capture_output=True, text=True, timeout=30
            )
            subprocess.run(
                ["docker", "image", "rm", "-f", run["image_reference"]],
                capture_output=True,
                text=True,
                timeout=30,
            )


if __name__ == "__main__":
    unittest.main()
