#!/usr/bin/env python3
"""从最近一次【已完成】的 ClawSec 全量快照，派生全球范围的 IP 枚举目标表与扫描命令。

ClawSec 把暴露实例的 IP 第三位隐藏成 *（如 152.42.*.8）。本脚本取最近一次完整拉取的
快照里所有 18789 端口的 IPv4 通配段（去重），写成 ocprobe 的目标文件——ocprobe 会把每个
通配段的第三位枚举 0-255。同时生成一条与上次中国版同口径的单行扫描命令。

产出两个文件（均在 tools/scan_test/output/ 下，gitignore）：
  global_targets_18789.txt   每行一个 X.X.*.X 通配段，供 ocprobe 枚举
  global_scan_command.txt    一条可直接复制运行的单行 ocprobe 命令

「最近一次已完成」的确定性判据（不靠阈值、不写死日期）：
  ClawSec watch 拉取时，单个快照拉完所有页才算完成；中途遇平台日期变更会把当前快照标进
  clawsec_state 的 incomplete_snapshots，并切到新日期从头拉。因此：
    - incomplete_snapshots 里的快照 = 被中断，未完成；
    - 库内最新日期的快照 = watch 当前正在拉的那个（进行中），除非平台已翻篇到更新日期；
  脚本默认排除 incomplete 的、以及库内最新日期那个（视作进行中），在其余快照里取最新日期，
  即「最近一次已完成」。可用 --snapshot 显式指定日期覆盖此自动判定。
"""
import argparse
import json
import os
import re
import sqlite3
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentsectool_scanner.paths import CLAWSEC_DB, OPENCLAW_FINGERPRINTS, PROBER_ROOT

PORT = 18789
OUT_DIR = os.path.join(os.path.dirname(__file__), "output")
TARGETS_FILE = os.path.join(OUT_DIR, "global_targets_18789.txt")
COMMAND_FILE = os.path.join(OUT_DIR, "global_scan_command.txt")
IPV4_MASKED = re.compile(r"\d{1,3}\.\d{1,3}\.\*\.\d{1,3}$")  # 第三位隐位的 IPv4 通配段


def latest_completed_snapshot(conn, override=None):
    """返回最近一次已完成的快照日期；override 非空则直接用它（仍校验存在）。"""
    dates = [r[0] for r in conn.execute(
        "SELECT DISTINCT snapshot_date FROM clawsec_snapshots ORDER BY snapshot_date")]
    if not dates:
        raise SystemExit("clawsec 库里没有任何快照，先跑 python3 -m tools.clawsec pull")
    if override:
        if override not in dates:
            raise SystemExit(f"指定的快照 {override} 不在库中。库内快照：{dates}")
        return override
    row = conn.execute(
        "SELECT value FROM clawsec_state WHERE key='incomplete_snapshots'").fetchone()
    incomplete = set(json.loads(row[0]) if row and row[0] else [])
    in_progress = max(dates)  # 库内最新日期 = watch 当前在拉的（进行中）
    completed = [d for d in dates if d != in_progress and d not in incomplete]
    if not completed:
        raise SystemExit(
            f"没有已完成的快照可用（最新 {in_progress} 视作进行中、incomplete={sorted(incomplete)}）。"
            f"\n若确认某快照已完成，用 --snapshot 指定。库内快照：{dates}")
    return max(completed)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", help="显式指定快照日期 YYYY-MM-DD，覆盖自动判定")
    ap.add_argument("--db", default=str(CLAWSEC_DB))
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)
    try:
        sd = latest_completed_snapshot(conn, args.snapshot)
        total = conn.execute(
            "SELECT COUNT(*) FROM clawsec_snapshots WHERE snapshot_date=?", (sd,)).fetchone()[0]
        rows = conn.execute(
            "SELECT DISTINCT masked_ip FROM clawsec_snapshots WHERE snapshot_date=? AND port=?",
            (sd, PORT)).fetchall()
    finally:
        conn.close()

    segs = sorted({ip for (ip,) in rows if ip and IPV4_MASKED.fullmatch(ip)})
    skipped = len(rows) - len(segs)  # IPv6 / 非标准格式（ocprobe 通配枚举只对 IPv4 有意义）

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(TARGETS_FILE, "w") as f:
        f.write("\n".join(segs) + ("\n" if segs else ""))

    # 单行扫描命令：与上次中国版同口径（4000 并发、5s 超时、限速、单行进度、不落盘探不到的、
    # 带指纹库版本反推、结果落 output/results）。先确保输出目录存在，免得 ocprobe 落盘失败。
    os.makedirs(os.path.join(OUT_DIR, "results"), exist_ok=True)
    out_jsonl = os.path.join(OUT_DIR, "results", f"global-{sd}.jsonl")
    ocprobe = PROBER_ROOT / "bin" / "ocprobe"
    command = (
        f"{ocprobe} -port {PORT} -concurrency 4000 -timeout 5s -rate 50 "
        f"--progress --skip-unreachable -fingerprints {OPENCLAW_FINGERPRINTS} "
        f"-o {out_jsonl} {os.path.relpath(TARGETS_FILE)}"
    )
    with open(COMMAND_FILE, "w") as f:
        f.write(command + "\n")

    print(f"最近一次已完成的 ClawSec 快照：{sd}（该快照共 {total:,} 条记录）")
    print(f"18789 端口去重 IPv4 通配段：{len(segs):,} 个"
          f"（跳过 {skipped} 个 IPv6/非标准格式）")
    print(f"预计枚举探测次数：{len(segs) * 256:,}")
    print(f"\n已写出：")
    print(f"  目标文件 → {TARGETS_FILE}")
    print(f"  命令文件 → {COMMAND_FILE}")
    print(f"\n扫描命令（也已写入命令文件）：")
    print(f"  {command}")


if __name__ == "__main__":
    main()
