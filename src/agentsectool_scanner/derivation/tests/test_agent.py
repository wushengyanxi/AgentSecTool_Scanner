import json
import tempfile
import unittest
from pathlib import Path

from agentsectool_scanner.derivation.agent import DerivationAgent
from agentsectool_scanner.derivation.config import AgentConfig
from agentsectool_scanner.derivation.harness import LocalDockerHarness
from agentsectool_scanner.derivation.packages import RequestPackageImporter
from agentsectool_scanner.derivation.repository import DerivationRepository


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.payloads = []

    def create(self, payload):
        self.payloads.append(payload)
        return self.responses.pop(0)


class DerivationAgentTests(unittest.TestCase):
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
            "request_id": "AGENT-FIXTURE",
            "code_files": ["probe.py"],
            "document_file": "report.md",
        }), encoding="utf-8")
        self.task = RequestPackageImporter(
            self.repo, self.root / "artifacts"
        ).import_package(package)
        self.user_message = self.repo.append_message(
            self.task["id"], role="user", content="先阅读主文档并说明判断。"
        )
        self.config = AgentConfig(
            api_key="test-key",
            allow_external_model=True,
            allowed_domains=("github.com",),
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def make_agent(self, transport):
        harness = LocalDockerHarness(self.repo, self.root / "runs")
        return DerivationAgent(
            self.repo,
            harness,
            self.config,
            transport=transport,
            attempts_root=self.root / "attempts",
        )

    def test_function_result_is_returned_with_store_disabled(self):
        document = next(
            item for item in self.repo.list_artifacts(self.task["id"])
            if item["role"] == "document"
        )
        transport = FakeTransport([
            {
                "id": "resp-1",
                "output": [
                    {
                        "type": "reasoning",
                        "id": "reasoning-1",
                        "summary": [],
                        "encrypted_content": "encrypted-reasoning-fixture",
                    },
                    {
                        "type": "function_call",
                        "call_id": "call-1",
                        "name": "read_material",
                        "arguments": json.dumps({
                            "artifact_id": document["id"], "offset": 0, "limit": 4096
                        }),
                    },
                ],
            },
            {
                "id": "resp-2",
                "output": [{
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "主文档标识了 Project X。"}],
                }],
            },
        ])
        result = self.make_agent(transport).run(self.task["id"], self.user_message["id"])

        self.assertEqual(result["status"], "completed")
        self.assertFalse(transport.payloads[0]["store"])
        self.assertEqual(transport.payloads[0]["model"], "gpt-5.6")
        self.assertIn(
            "reasoning.encrypted_content", transport.payloads[0]["include"]
        )
        self.assertEqual(
            transport.payloads[0]["tools"][-1]["filters"]["allowed_domains"],
            ["github.com"],
        )
        replayed_reasoning = [
            item for item in transport.payloads[1]["input"]
            if item.get("type") == "reasoning"
        ]
        self.assertEqual(
            replayed_reasoning[0]["encrypted_content"],
            "encrypted-reasoning-fixture",
        )
        tool_outputs = [
            item for item in transport.payloads[1]["input"]
            if item.get("type") == "function_call_output"
        ]
        self.assertEqual(len(tool_outputs), 1)
        self.assertIn("Project X", tool_outputs[0]["output"])
        self.assertEqual(self.repo.list_messages(self.task["id"])[-1]["role"], "assistant")

    def test_user_input_tool_moves_task_to_waiting_state(self):
        transport = FakeTransport([
            {
                "id": "resp-1",
                "output": [{
                    "type": "function_call",
                    "call_id": "call-1",
                    "name": "request_user_input",
                    "arguments": json.dumps({
                        "question": "请提供失败实例日志。",
                        "reason": "当前材料无法区分环境失败和协议失败。",
                        "needed_files": ["runtime.log"],
                    }),
                }],
            },
            {
                "id": "resp-2",
                "output": [{
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "请补充失败实例的 runtime.log。"}],
                }],
            },
        ])
        result = self.make_agent(transport).run(self.task["id"], self.user_message["id"])
        self.assertEqual(result["status"], "waiting_user")
        self.assertEqual(self.repo.get_task(self.task["id"])["status"], "waiting_user")


if __name__ == "__main__":
    unittest.main()
