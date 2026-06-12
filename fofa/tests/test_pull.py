"""FOFA 拉取/入库单测（离线，注入 FakeClient，不耗额度）。"""

import os
import sqlite3
import tempfile
import unittest

from fofa import pull as pm

FIELDS = ["ip", "port", "host", "protocol", "region", "city", "as_organization", "server", "title"]


class FakeClient:
    """模拟 FofaClient.search_after：把预置的几批假数据喂给 on_batch。"""

    def __init__(self, batches):
        self.batches = batches

    def account_info(self):
        return {"remain_api_query": 9999, "remain_api_data": 99999}

    def search_after(self, query, page_size=2000, max_records=None, start_next="", on_batch=None):
        pulled = 0
        for i, rows in enumerate(self.batches):
            nxt = f"cursor{i + 1}" if i < len(self.batches) - 1 else ""
            if on_batch:
                on_batch(rows, FIELDS, nxt)
            pulled += len(rows)
        return pulled, ""


class TestPull(unittest.TestCase):
    def test_upsert_dedup_and_provinces(self):
        db = os.path.join(tempfile.mkdtemp(), "f.sqlite")
        rows1 = [
            ["1.1.1.1", "443", "h", "https", "Guangdong", "Shenzhen", "org", "nginx", "OpenClaw Control"],
            ["2.2.2.2", "80", "h", "http", "Beijing", "Beijing", "org", "", "OpenClaw Control"],
        ]
        rows2 = [
            ["1.1.1.1", "443", "h2", "https", "Guangdong", "Guangzhou", "org", "nginx2", "OpenClaw Control"],  # 同 (ip,port) → upsert
            ["3.3.3.3", "18789", "h", "http", "Guangdong", "Guangzhou", "org", "", "OpenClaw Control"],
        ]
        n, usage = pm.pull(db, mode="full", client=FakeClient([rows1, rows2]))
        self.assertEqual(n, 4)                        # 拉了 4 条
        self.assertEqual(pm.candidate_count(db), 3)   # 去重后 3 个资产

        prov = dict(pm.province_breakdown(db))
        self.assertEqual(prov.get("Guangdong"), 2)    # 1.1.1.1 + 3.3.3.3
        self.assertEqual(prov.get("Beijing"), 1)

        # upsert 更新了 city
        c = sqlite3.connect(db)
        city = c.execute("SELECT city FROM fofa_candidates WHERE ip='1.1.1.1'").fetchone()[0]
        c.close()
        self.assertEqual(city, "Guangzhou")


if __name__ == "__main__":
    unittest.main()
