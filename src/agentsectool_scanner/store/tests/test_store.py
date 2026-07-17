"""落地层单测（`python3 -m unittest agentsectool_scanner.store.tests.test_store`）。"""

import json
import os
import sqlite3
import tempfile
import unittest

from agentsectool_scanner.store import load


class TestIdentity(unittest.TestCase):
    def test_ipport_per_host(self):
        # 每台主机一条记录：按 ip:port 去重，不跨 IP 合并（即便内容相同）。
        r1 = {"ip": "1.1.1.1", "port": 18789, "is_openclaw": True,
              "evidence": {"favicon_md5": "f", "asset_hashes": ["b.js", "a.css"]}}
        r2 = {"ip": "9.9.9.9", "port": 18789, "is_openclaw": True,
              "evidence": {"favicon_md5": "f", "asset_hashes": ["b.js", "a.css"]}}
        self.assertTrue(load.identity_key(r1).startswith("openclaw:ipport:"))
        # 同内容、不同 IP → 不同身份（是两台主机）
        self.assertNotEqual(load.identity_key(r1), load.identity_key(r2))
        # 同 IP:端口 → 同身份
        self.assertEqual(load.identity_key(r1),
                         load.identity_key({"asset_type": "openclaw", "ip": "1.1.1.1", "port": 18789}))
        # 同 IP:端口、不同资产类型 → 不同身份
        self.assertNotEqual(load.identity_key(r1),
                            load.identity_key({"asset_type": "example", "ip": "1.1.1.1", "port": 18789}))


class TestClassify(unittest.TestCase):
    def test_buckets(self):
        self.assertEqual(load.classify(
            {"is_openclaw": True, "version": "2026.5.17"}), "confirmed")
        self.assertEqual(load.classify(
            {"is_openclaw": True, "version_candidates": ["a", "b"]}), "confirmed")
        self.assertEqual(load.classify(
            {"is_openclaw": True}), "confirmed_no_version")
        self.assertEqual(load.classify(
            {"is_openclaw": False, "matched": ["T5", "T6"]}), "suspect")
        # 超时/纯无命中 → None（不收录）
        self.assertIsNone(load.classify(
            {"is_openclaw": False, "matched": [], "error_type": "timeout"}))
        self.assertEqual(load.classify(
            {"asset_type": "example", "is_match": True, "version": "1.0.0"}), "confirmed")


class TestUnwrap(unittest.TestCase):
    def test_zgrab2_envelope(self):
        env = {"ip": "1.2.3.4", "data": {"openclaw": {"status": "success", "port": 18789,
               "result": {"is_openclaw": True, "version": "2026.5.17"}}}}
        r = load._unwrap(env)
        self.assertEqual(r["ip"], "1.2.3.4")
        self.assertEqual(r["port"], 18789)
        self.assertTrue(r["is_openclaw"])

    def test_flat_passthrough(self):
        flat = {"ip": "1.1.1.1", "port": 80, "is_openclaw": False}
        self.assertIs(load._unwrap(flat), flat)

    def test_envelope_without_result(self):
        self.assertIsNone(load._unwrap({"ip": "1.2.3.4", "data": {"openclaw": {"status": "connection-refused"}}}))


class TestLoad(unittest.TestCase):
    def test_load_dedup_and_stats(self):
        d = tempfile.mkdtemp()
        jsonl = os.path.join(d, "r.jsonl")
        db = os.path.join(d, "s.sqlite")
        recs = [
            {"ip": "1.1.1.1", "port": 18789, "is_openclaw": True, "rule": "C2",
             "version": "2026.5.17", "version_source": "implicit", "matched": ["T2", "T3", "T5"],
             "tls": False, "ts": "2026-06-11T00:00:00Z",
             "evidence": {"favicon_md5": "f", "asset_hashes": ["x.js"], "csp_sha256": "c",
                          "probes": [{"id": "T2", "request": "GET / ...", "response": "101 ...", "hit": True}]}},
            {"ip": "1.1.1.1", "port": 18789, "is_openclaw": True, "rule": "C2",
             "version": "2026.5.17", "version_source": "implicit", "matched": ["T2", "T3", "T5"],
             "tls": False, "ts": "2026-06-12T00:00:00Z",
             "evidence": {"favicon_md5": "f", "asset_hashes": ["x.js"], "csp_sha256": "c",
                          "probes": [{"id": "T2", "request": "GET / ...", "response": "101 ...", "hit": True}]}},
            {"ip": "2.2.2.2", "port": 80, "is_openclaw": False, "rule": "",
             "matched": [], "error_type": "timeout", "tls": False,
             "ts": "2026-06-11T00:00:00Z", "evidence": {}},
        ]
        with open(jsonl, "w") as f:
            for r in recs:
                f.write(json.dumps(r) + "\n")

        n = load.load(db, jsonl)
        # 第三条是 timeout（无命中）→ 被跳过不收录；前两条同 IP:端口 → 都收录
        self.assertEqual(n, 2)
        summary, _ = load.stats(db)
        self.assertEqual(summary["assets_total"], 1)     # 同 IP:端口 → 1 台主机一条资产
        self.assertEqual(summary["confirmed"], 1)        # 该主机确认 OpenClaw + 有版本
        self.assertEqual(summary["suspect"], 0)
        self.assertEqual(summary["observations"], 2)     # 两次观测
        self.assertEqual(summary["probe_records"], 2)    # 各 1 个 probe

        # observations 存了平台字段和 OpenClaw 兼容字段
        conn = sqlite3.connect(db)
        row = conn.execute(
            "SELECT asset_type, detector, is_match, is_openclaw, rule, matched, category "
            "FROM observations WHERE is_openclaw=1 LIMIT 1").fetchone()
        asset_type, detector, is_match, is_openclaw, rule, matched, category = row
        self.assertEqual(asset_type, "openclaw")
        self.assertEqual(detector, "openclaw")
        self.assertEqual(is_match, 1)
        self.assertEqual(is_openclaw, 1)
        self.assertEqual(rule, "C2")
        self.assertEqual(json.loads(matched), ["T2", "T3", "T5"])
        self.assertEqual(category, "confirmed")
        # timeout 那条被跳过，库里没有 is_openclaw=0 的观测
        self.assertEqual(conn.execute(
            "SELECT COUNT(*) FROM observations WHERE is_openclaw=0").fetchone()[0], 0)
        conn.close()

    def test_load_generic_asset_type(self):
        d = tempfile.mkdtemp()
        jsonl = os.path.join(d, "r.jsonl")
        db = os.path.join(d, "s.sqlite")
        rec = {
            "asset_type": "example",
            "detector": "example-detector",
            "ip": "3.3.3.3",
            "port": 8080,
            "is_match": True,
            "category": "confirmed",
            "version": "1.0.0",
            "matched": ["E1"],
            "tls": False,
            "ts": "2026-06-11T00:00:00Z",
            "evidence": {},
        }
        with open(jsonl, "w") as f:
            f.write(json.dumps(rec) + "\n")

        self.assertEqual(load.load(db, jsonl), 1)
        conn = sqlite3.connect(db)
        row = conn.execute(
            "SELECT asset_type, detector, is_match, is_openclaw, category, latest_version "
            "FROM assets LIMIT 1").fetchone()
        self.assertEqual(row, ("example", "example-detector", 1, 0, "confirmed", "1.0.0"))
        conn.close()

    def test_load_dynamic_project_facts_and_vulnerability_matches(self):
        d = tempfile.mkdtemp()
        jsonl = os.path.join(d, "dynamic.jsonl")
        db = os.path.join(d, "dynamic.sqlite")
        rec = {
            "asset_type": "project-x",
            "detector": "project-x-marker",
            "ip": "4.4.4.4",
            "port": 8080,
            "is_match": True,
            "category": "confirmed",
            "version": "1.2.3",
            "matched": ["project-x.marker"],
            "facts": {"version": "1.2.3", "feature_enabled": True},
            "test_results": [{
                "request_id": "r1",
                "test_id": "project-x.marker",
                "status": "satisfied",
                "facts": {"version": "1.2.3", "feature_enabled": True},
                "evidence": [{"kind": "http_header", "value": "x-project: x"}],
                "error": None,
            }],
            "vulnerability_rules": [{
                "vulnerability_id": "CVE-TEST",
                "condition": {
                    "all": [
                        {"path": "facts.feature_enabled", "operator": "eq", "value": True},
                        {"path": "facts.version", "operator": "eq", "value": "1.2.3"},
                    ]
                },
            }],
            "display_templates": [{
                "title": "Project X",
                "facts": ["version", "feature_enabled"],
            }],
            "tls": False,
            "ts": "2026-07-15T00:00:00Z",
        }
        with open(jsonl, "w") as stream:
            stream.write(json.dumps(rec) + "\n")

        self.assertEqual(load.load(db, jsonl), 1)
        conn = sqlite3.connect(db)
        test_row = conn.execute(
            "SELECT test_id, status, facts, evidence FROM project_test_results"
        ).fetchone()
        self.assertEqual(test_row[0:2], ("project-x.marker", "satisfied"))
        self.assertTrue(json.loads(test_row[2])["feature_enabled"])
        self.assertEqual(json.loads(test_row[3])[0]["kind"], "http_header")
        stored_facts = conn.execute("SELECT facts FROM observation_facts").fetchone()
        self.assertTrue(json.loads(stored_facts[0])["feature_enabled"])
        vulnerability = conn.execute(
            "SELECT vulnerability_id, status FROM vulnerability_matches"
        ).fetchone()
        self.assertEqual(vulnerability, ("CVE-TEST", "applicable"))
        presentation = conn.execute(
            "SELECT template FROM observation_presentations"
        ).fetchone()
        self.assertEqual(json.loads(presentation[0])[0]["title"], "Project X")
        conn.close()


if __name__ == "__main__":
    unittest.main()
