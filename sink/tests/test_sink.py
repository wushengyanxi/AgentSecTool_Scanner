"""落地层单测（`python3 -m unittest sink.tests.test_sink`）。"""

import json
import os
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
            {"ip": "1.1.1.1", "port": 18789, "is_openclaw": True, "confidence": 1.0,
             "version": "2026.5.17", "version_source": "implicit", "signals": ["ws_challenge"],
             "tls": False, "ts": "2026-06-11T00:00:00Z",
             "evidence": {"favicon_md5": "f", "asset_hashes": ["x.js"], "csp_sha256": "c"}},
            {"ip": "1.1.1.1", "port": 18789, "is_openclaw": True, "confidence": 1.0,
             "version": "2026.5.17", "version_source": "implicit", "signals": ["ws_challenge"],
             "tls": False, "ts": "2026-06-12T00:00:00Z",
             "evidence": {"favicon_md5": "f", "asset_hashes": ["x.js"], "csp_sha256": "c"}},
            {"ip": "2.2.2.2", "port": 80, "is_openclaw": False, "confidence": 0.0,
             "signals": [], "tls": False, "ts": "2026-06-11T00:00:00Z", "evidence": {}},
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


if __name__ == "__main__":
    unittest.main()
