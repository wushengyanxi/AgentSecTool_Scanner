"""发现层单测（stdlib unittest，`python3 -m unittest discovery.tests.test_discovery`）。"""

import os
import tempfile
import unittest

from discovery import active, merge, passive
from discovery import blocklist as bl


class TestBlocklist(unittest.TestCase):
    def test_reserved_default(self):
        b = bl.Blocklist()
        self.assertTrue(b.is_blocked("127.0.0.1"))
        self.assertTrue(b.is_blocked("10.1.2.3"))
        self.assertTrue(b.is_blocked("192.168.1.1"))
        self.assertFalse(b.is_blocked("1.1.1.1"))
        self.assertFalse(b.is_blocked("203.0.114.0"))

    def test_allow_reserved(self):
        b = bl.Blocklist(include_reserved=False)
        self.assertFalse(b.is_blocked("127.0.0.1"))

    def test_extra_cidr(self):
        b = bl.Blocklist(extra_cidrs=["8.8.8.0/24"], include_reserved=False)
        self.assertTrue(b.is_blocked("8.8.8.8"))
        self.assertFalse(b.is_blocked("8.8.9.1"))

    def test_invalid_ip_blocked(self):
        self.assertTrue(bl.Blocklist().is_blocked("not-an-ip"))


class TestMerge(unittest.TestCase):
    def test_dedup_and_blocklist(self):
        active = [("1.1.1.1", 18789), ("1.1.1.1", 18789), ("10.0.0.1", 18789)]
        passive = [("2.2.2.2", 443), ("1.1.1.1", 80)]
        b = bl.Blocklist()  # 默认排除 10/8
        out = merge.merge_candidates(active, passive, blocklist=b)
        self.assertIn(("1.1.1.1", 18789), out)
        self.assertIn(("1.1.1.1", 80), out)
        self.assertIn(("2.2.2.2", 443), out)
        self.assertNotIn(("10.0.0.1", 18789), out)  # 被黑名单剔除
        self.assertEqual(len(out), 3)  # 去重后


class TestFofaParse(unittest.TestCase):
    def test_results_to_pairs(self):
        data = {"results": [["1.2.3.4", "18789"], ["5.6.7.8", 443], ["bad"]]}
        pairs = passive.fofa_results_to_pairs(data)
        self.assertEqual(pairs, [("1.2.3.4", 18789), ("5.6.7.8", 443)])

    def test_empty(self):
        self.assertEqual(passive.fofa_results_to_pairs({}), [])

    def test_no_creds_returns_empty(self):
        self.assertEqual(passive.fofa_search("", "", "q"), [])


class TestShodanParse(unittest.TestCase):
    def test_results_to_pairs(self):
        data = {"matches": [
            {"ip_str": "1.2.3.4", "port": 18789},
            {"ip_str": "5.6.7.8", "port": "443"},
            {"port": 80},  # 缺 ip → 跳过
        ]}
        self.assertEqual(passive.shodan_results_to_pairs(data), [("1.2.3.4", 18789), ("5.6.7.8", 443)])

    def test_no_key_returns_empty(self):
        self.assertEqual(passive.shodan_search("", "q"), [])


class TestMasscanParse(unittest.TestCase):
    def test_parse_list_output(self):
        txt = (
            "#masscan\n"
            "open tcp 18789 1.2.3.4 1700000000\n"
            "open tcp 443 5.6.7.8 1700000001\n"
            "garbage line\n"
            "#end\n"
        )
        fd, path = tempfile.mkstemp(suffix=".lst")
        os.write(fd, txt.encode())
        os.close(fd)
        try:
            self.assertEqual(active._parse_masscan_list(path), [("1.2.3.4", 18789), ("5.6.7.8", 443)])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
