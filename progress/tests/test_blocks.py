"""块级进度单测（`python3 -m unittest progress.tests.test_blocks`）。"""

import os
import tempfile
import unittest

from progress import blocks


class TestSplit(unittest.TestCase):
    def test_exact(self):
        self.assertEqual(list(blocks.split_blocks(["1.0.0.0/16"], prefix=16)), ["1.0.0.0/16"])

    def test_split_down(self):
        self.assertEqual(len(list(blocks.split_blocks(["1.0.0.0/14"], prefix=16))), 4)

    def test_smaller_than_block_kept(self):
        self.assertEqual(list(blocks.split_blocks(["2.2.2.0/24"], prefix=16)), ["2.2.2.0/24"])


class TestQueue(unittest.TestCase):
    def setUp(self):
        self.db = os.path.join(tempfile.mkdtemp(), "p.sqlite")

    def test_seed_idempotent(self):
        self.assertEqual(blocks.seed_campaign(self.db, "c1", ["10.0.0.0/14"], prefix=16), 4)
        # 重复 seed 不重复登记
        self.assertEqual(blocks.seed_campaign(self.db, "c1", ["10.0.0.0/14"], prefix=16), 0)

    def test_claim_done_resume(self):
        blocks.seed_campaign(self.db, "c1", ["10.0.0.0/14"], prefix=16)  # 4 块
        claimed = set()
        # 续扫语义：反复领取直到取尽；每领一个就标完成
        while (blk := blocks.claim_block(self.db, "c1", "w1")) is not None:
            self.assertNotIn(blk, claimed)  # 不会重复领取
            claimed.add(blk)
            blocks.mark_done(self.db, "c1", blk)
        self.assertEqual(len(claimed), 4)
        self.assertEqual(blocks.progress(self.db, "c1").get("done"), 4)
        self.assertIsNone(blocks.claim_block(self.db, "c1", "w1"))  # 全 done

    def test_reset_stale_requeues(self):
        blocks.seed_campaign(self.db, "c1", ["10.0.0.0/16"], prefix=16)  # 1 块
        blk = blocks.claim_block(self.db, "c1", "w1")
        self.assertIsNotNone(blk)
        self.assertIsNone(blocks.claim_block(self.db, "c1", "w2"))  # 已被 w1 领走
        # 回收超时未完成的块（older_than 设 -1 强制回收）
        self.assertEqual(blocks.reset_stale(self.db, "c1", older_than_s=-1), 1)
        self.assertIsNotNone(blocks.claim_block(self.db, "c1", "w2"))  # 又可领取了


if __name__ == "__main__":
    unittest.main()
