#!/usr/bin/env python3
"""一次性数据库拆库迁移：把旧 scan.sqlite 拆成 data/{fofa,clawsec,scanner} 各库。

- fofa_candidates + fofa_state → data/fofa/fofa.sqlite（不耗 FOFA 额度，直接 SQL 搬）
- clawsec_instances → data/clawsec/clawsec.sqlite 的 clawsec_snapshots，补 snapshot_date
  （旧数据是某一天的快照，作为该日的首个快照入库）
- scanner（assets/observations/probe_records）现几乎为空，不迁，新库从空开始

幂等：目标表已有数据则跳过对应迁移（避免重复）。仅标准库。

用法：
  python3 fingerprint/migrate_dbs.py --old scan.sqlite --clawsec-date 2026-06-14
"""
import argparse
import os
import sqlite3
import sys

# 让脚本无论从哪个目录跑都能 import 项目模块（项目根加入 path）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fofa import pull as fofa_pull
from clawsec import pull as clawsec_pull

FOFA_DB = "data/fofa/fofa.sqlite"
CLAWSEC_DB = "data/clawsec/clawsec.sqlite"

# clawsec_instances（旧）→ clawsec_snapshots（新）的列映射（新表多一个 snapshot_date）
CLAWSEC_COLS = ["id", "masked_ip", "port", "service", "their_version", "country", "province",
                "cn_city", "asn", "organization", "runtime_status", "is_china", "authenticated",
                "cred_leaked", "has_mcp", "vuln_count", "vuln_severity", "first_seen", "last_seen",
                "pulled_at", "raw", "scope"]


def ensure_dir(path):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


def table_count(conn, table):
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    except sqlite3.OperationalError:
        return None


def migrate_fofa(old):
    ensure_dir(FOFA_DB)
    dst = fofa_pull._conn(FOFA_DB)  # 建好 fofa schema
    if table_count(dst, "fofa_candidates"):
        print(f"  fofa: 目标库已有数据，跳过")
        dst.close()
        return
    dst.execute("ATTACH DATABASE ? AS old", (old,))
    n_c = dst.execute("SELECT COUNT(*) FROM old.fofa_candidates").fetchone()[0]
    dst.execute("INSERT INTO fofa_candidates SELECT * FROM old.fofa_candidates")
    try:
        dst.execute("INSERT INTO fofa_state SELECT * FROM old.fofa_state")
    except sqlite3.OperationalError:
        pass
    dst.commit()
    dst.execute("DETACH DATABASE old")
    dst.close()
    print(f"  fofa: 迁移 {n_c:,} 条 fofa_candidates → {FOFA_DB}")


def migrate_clawsec(old, snapshot_date):
    ensure_dir(CLAWSEC_DB)
    dst = clawsec_pull._conn(CLAWSEC_DB)  # 建好 clawsec_snapshots schema
    if table_count(dst, "clawsec_snapshots"):
        print(f"  clawsec: 目标库已有快照，跳过")
        dst.close()
        return
    src = sqlite3.connect(old)
    rows = src.execute(f"SELECT {','.join(CLAWSEC_COLS)} FROM clawsec_instances").fetchall()
    src.close()
    placeholders = ",".join(["?"] * (len(CLAWSEC_COLS) + 1))  # +1 = snapshot_date
    cols = "snapshot_date," + ",".join(CLAWSEC_COLS)
    dst.executemany(
        f"INSERT OR IGNORE INTO clawsec_snapshots ({cols}) VALUES ({placeholders})",
        [(snapshot_date, *r) for r in rows],
    )
    dst.commit()
    dst.close()
    print(f"  clawsec: 迁移 {len(rows):,} 条 → {CLAWSEC_DB}（snapshot_date={snapshot_date}）")


def main():
    ap = argparse.ArgumentParser("migrate_dbs")
    ap.add_argument("--old", default="scan.sqlite", help="旧的合并库")
    ap.add_argument("--clawsec-date", default="2026-06-14",
                    help="旧 clawsec 数据作为哪一天的快照（默认 2026-06-14）")
    args = ap.parse_args()
    if not os.path.exists(args.old):
        sys.exit(f"找不到旧库：{args.old}")
    print(f"拆库迁移：{args.old} → data/{{fofa,clawsec}}/")
    migrate_fofa(args.old)
    migrate_clawsec(args.old, args.clawsec_date)
    print("完成（scanner 库不迁，新库从空开始；旧 scan.sqlite 保留作备份）")


if __name__ == "__main__":
    main()
