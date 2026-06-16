"""落地层单测（`python3 -m unittest sink.tests.test_sink`）。"""

import json
import os
import sqlite3
import tempfile
import unittest

from sink import load


class TestIdentity(unittest.TestCase):
    def test_ipport_per_host(self):
        # 每台主机一条记录：按 ip:port 去重，不跨 IP 合并（即便内容相同）。
        r1 = {"ip": "1.1.1.1", "port": 18789, "is_openclaw": True,
              "evidence": {"favicon_md5": "f", "asset_hashes": ["b.js", "a.css"]}}
        r2 = {"ip": "9.9.9.9", "port": 18789, "is_openclaw": True,
              "evidence": {"favicon_md5": "f", "asset_hashes": ["b.js", "a.css"]}}
        self.assertTrue(load.identity_key(r1).startswith("ipport:"))
        # 同内容、不同 IP → 不同身份（是两台主机）
        self.assertNotEqual(load.identity_key(r1), load.identity_key(r2))
        # 同 IP:端口 → 同身份
        self.assertEqual(load.identity_key(r1),
                         load.identity_key({"ip": "1.1.1.1", "port": 18789}))


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

        # observations 存了 rule/matched/category
        conn = sqlite3.connect(db)
        rule, matched, category = conn.execute(
            "SELECT rule, matched, category FROM observations WHERE is_openclaw=1 LIMIT 1").fetchone()
        self.assertEqual(rule, "C2")
        self.assertEqual(json.loads(matched), ["T2", "T3", "T5"])
        self.assertEqual(category, "confirmed")
        # timeout 那条被跳过，库里没有 is_openclaw=0 的观测
        self.assertEqual(conn.execute(
            "SELECT COUNT(*) FROM observations WHERE is_openclaw=0").fetchone()[0], 0)
        conn.close()


if __name__ == "__main__":
    unittest.main()
