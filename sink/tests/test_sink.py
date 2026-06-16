"""落地层单测（`python3 -m unittest sink.tests.test_sink`）。"""

import json
import os
import sqlite3
import tempfile
import unittest

from sink import load


class TestIdentity(unittest.TestCase):
    def test_content_based_order_independent(self):
        r1 = {"ip": "1.1.1.1", "port": 18789, "is_openclaw": True,
              "evidence": {"favicon_md5": "f", "asset_hashes": ["b.js", "a.css"], "csp_sha256": "c"}}
        r2 = {"ip": "9.9.9.9", "port": 18789, "is_openclaw": True,
              "evidence": {"favicon_md5": "f", "asset_hashes": ["a.css", "b.js"], "csp_sha256": "c"}}
        self.assertTrue(load.identity_key(r1).startswith("content:"))
        # 同内容、不同 IP → 同身份（资产去重跨 IP）
        self.assertEqual(load.identity_key(r1), load.identity_key(r2))

    def test_ipport_fallback(self):
        r = {"ip": "1.1.1.1", "port": 80, "is_openclaw": False, "evidence": {}}
        self.assertTrue(load.identity_key(r).startswith("ipport:"))


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
        self.assertEqual(n, 3)
        summary, _ = load.stats(db)
        self.assertEqual(summary["assets_total"], 2)     # 两条同内容 OpenClaw → 1 资产；非 OpenClaw → 1
        self.assertEqual(summary["assets_openclaw"], 1)
        self.assertEqual(summary["with_version"], 1)
        self.assertEqual(summary["observations"], 3)
        self.assertEqual(summary["probe_records"], 2)    # 两条 OpenClaw 各 1 个 probe

        # observations 存了 rule/matched/error_type
        conn = sqlite3.connect(db)
        rule, matched = conn.execute(
            "SELECT rule, matched FROM observations WHERE is_openclaw=1 LIMIT 1").fetchone()
        self.assertEqual(rule, "C2")
        self.assertEqual(json.loads(matched), ["T2", "T3", "T5"])
        et = conn.execute("SELECT error_type FROM observations WHERE is_openclaw=0").fetchone()[0]
        self.assertEqual(et, "timeout")
        conn.close()


if __name__ == "__main__":
    unittest.main()
