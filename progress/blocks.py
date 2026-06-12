"""块级扫描进度（SQLite）。"""

import ipaddress
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_blocks (
  campaign    TEXT NOT NULL,
  block_cidr  TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'pending',  -- pending | in_progress | done
  worker      TEXT,
  claimed_at  REAL,
  done_at     REAL,
  PRIMARY KEY (campaign, block_cidr)
);
CREATE INDEX IF NOT EXISTS idx_blocks_status ON scan_blocks(campaign, status);
"""


def _conn(db: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def split_blocks(cidrs, prefix: int = 16):
    """把 CIDR 列表切成 /prefix 的块；比 /prefix 更小的段原样保留。"""
    for c in cidrs:
        net = ipaddress.ip_network(c, strict=False)
        if net.prefixlen >= prefix:
            yield str(net)
        else:
            for sub in net.subnets(new_prefix=prefix):
                yield str(sub)


def seed_campaign(db: str, campaign: str, cidrs, prefix: int = 16) -> int:
    """把一个范围切块并登记为某战役的待扫块（已存在则忽略）。返回新增块数。"""
    conn = _conn(db)
    n = 0
    try:
        for blk in split_blocks(cidrs, prefix):
            n += conn.execute(
                "INSERT OR IGNORE INTO scan_blocks (campaign, block_cidr) VALUES (?,?)",
                (campaign, blk),
            ).rowcount
        conn.commit()
    finally:
        conn.close()
    return n


def claim_block(db: str, campaign: str, worker: str):
    """原子地领取一个待扫块并标 in_progress；无待扫块则返回 None。

    用 BEGIN IMMEDIATE 串行化并发领取，保证多进程/多 worker 不会领到同一块。"""
    conn = _conn(db)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT block_cidr FROM scan_blocks WHERE campaign=? AND status='pending' LIMIT 1",
            (campaign,),
        ).fetchone()
        if row is None:
            conn.commit()
            return None
        blk = row[0]
        conn.execute(
            "UPDATE scan_blocks SET status='in_progress', worker=?, claimed_at=? "
            "WHERE campaign=? AND block_cidr=?",
            (worker, time.time(), campaign, blk),
        )
        conn.commit()
        return blk
    finally:
        conn.close()


def mark_done(db: str, campaign: str, block_cidr: str) -> None:
    conn = _conn(db)
    try:
        conn.execute(
            "UPDATE scan_blocks SET status='done', done_at=? WHERE campaign=? AND block_cidr=?",
            (time.time(), campaign, block_cidr),
        )
        conn.commit()
    finally:
        conn.close()


def reset_stale(db: str, campaign: str, older_than_s: float = 3600) -> int:
    """把领取超过 older_than_s 仍未完成的块退回 pending（worker 死亡后的回收）。"""
    conn = _conn(db)
    try:
        cur = conn.execute(
            "UPDATE scan_blocks SET status='pending', worker=NULL "
            "WHERE campaign=? AND status='in_progress' AND claimed_at < ?",
            (campaign, time.time() - older_than_s),
        )
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def progress(db: str, campaign: str) -> dict:
    conn = _conn(db)
    try:
        return dict(
            conn.execute(
                "SELECT status, COUNT(*) FROM scan_blocks WHERE campaign=? GROUP BY status",
                (campaign,),
            ).fetchall()
        )
    finally:
        conn.close()
