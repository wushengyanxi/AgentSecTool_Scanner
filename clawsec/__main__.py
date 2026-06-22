"""ClawSec 测绘平台每日全量快照拉取 CLI（与 fofa/ 平级的被动发现源）。

  python3 -m clawsec info                          # 平台汇总计数（含 lastScanTime）
  python3 -m clawsec pull                          # 拉当日全量快照入库（拉完为止、可续、日期变更自动切）
  python3 -m clawsec pull --scope china            # 只拉境内
  python3 -m clawsec longlived --min-days 3        # 跨快照分析长期有效实例（优先枚举对象）
  python3 -m clawsec overlap                       # 最新快照 × fofa_candidates 的隐位重叠
  python3 -m clawsec versions                      # 最新快照按平台标注版本统计

命令在项目根目录跑（python3 -m clawsec）。数据入 data/clawsec/clawsec.sqlite 的 clawsec_snapshots 表。
"""
import argparse
import datetime
import os
import sqlite3
import time

from . import pull as pullmod
from .client import ClawSecClient

DEFAULT_DB = "data/clawsec/clawsec.sqlite"
DEFAULT_FOFA_DB = "data/fofa/fofa.sqlite"


def _ensure_dir(path):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


def _ts():
    return datetime.datetime.now().strftime("%H:%M:%S")


def _watch_loop(args, pull_once):
    """持续运营：每 watch_interval 秒查平台 lastScanTime；比库内最新快照日期更新即拉新日期全量。

    启动即查一次（不必干等一个间隔），日期不变时只打心跳、不拉取（不做无谓全量）。Ctrl-C 退出。"""
    cli = ClawSecClient()
    conn = sqlite3.connect(args.db)
    try:
        have = pullmod.latest_snapshot(conn)
    finally:
        conn.close()
    print(f"\n[watch] 持续运营中：库内最新快照 {have}，每 {args.watch_interval}s 轮询一次，"
          f"平台出现更新日期即拉取（Ctrl-C 退出）", flush=True)
    try:
        while True:
            try:
                platform_date = cli.last_scan_time()
            except Exception as e:  # noqa: BLE001 — 单次轮询失败不该中断运营，下轮重试
                print(f"[{_ts()}] 轮询平台失败：{e}（{args.watch_interval}s 后重试）", flush=True)
                time.sleep(args.watch_interval)
                continue
            conn = sqlite3.connect(args.db)
            try:
                have = pullmod.latest_snapshot(conn)
            finally:
                conn.close()
            if platform_date and platform_date != have:
                print(f"[{_ts()}] 平台快照更新 {have} → {platform_date}，开始拉取新日期全量", flush=True)
                pull_once()
            else:
                print(f"[{_ts()}] 平台快照日期未变（{have}），等待下一轮", flush=True)
            time.sleep(args.watch_interval)
    except KeyboardInterrupt:
        print("\n[watch] 已停止持续运营", flush=True)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser("clawsec")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("pull", help="拉当日全量快照入库（拉完为止、可续、日期变更自动切）")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--scope", default="all", choices=["china", "overseas", "all"],
                   help="拉取范围（默认 all 全量）")
    p.add_argument("--active-only", action="store_true",
                   help="只拉 Active（默认含 Inactive，作完整记录）")
    p.add_argument("--snapshot-date", default=None,
                   help="指定快照日期（默认取平台 lastScanTime）")
    p.add_argument("--watch-interval", type=int, default=600,
                   help="轮询平台快照日期的间隔秒数（默认 600=10 分钟）")

    ll = sub.add_parser("longlived", help="跨快照分析长期有效实例")
    ll.add_argument("--db", default=DEFAULT_DB)
    ll.add_argument("--min-days", type=int, default=2, help="最少 Active 快照数（默认 2）")
    ll.add_argument("--all-scope", action="store_true", help="含海外（默认仅境内）")
    ll.add_argument("--limit", type=int, default=50)

    o = sub.add_parser("overlap", help="最新快照 × fofa_candidates 的隐位重叠")
    o.add_argument("--db", default=DEFAULT_DB)
    o.add_argument("--fofa-db", default=DEFAULT_FOFA_DB)

    v = sub.add_parser("versions", help="最新快照按平台标注版本统计")
    v.add_argument("--db", default=DEFAULT_DB)

    sub.add_parser("info", help="平台汇总计数")

    args = ap.parse_args(argv)

    if args.cmd == "pull":
        _ensure_dir(args.db)

        def _progress(cur, total, page, total_pages):
            print(f"\r  拉取中… 第 {page}/{total_pages} 页，本快照 {cur:,}/{total:,} 条",
                  end="", flush=True)

        def _snap_done(sd, n, interrupted):
            tag = "（被日期变更中断，标 incomplete）" if interrupted else "（完整）"
            print(f"\n  快照 {sd}：{n:,} 条 {tag}", flush=True)

        def _pull_once():
            n, n_total, sd = pullmod.pull(
                args.db, scope=args.scope, active_only=args.active_only,
                snapshot_date=args.snapshot_date, on_progress=_progress, on_snapshot_done=_snap_done)
            print(f"完成。本次新增 {n:,} 条 → clawsec_snapshots（最终快照 {sd} 共 {n_total:,} 条）")

        # pull 持续运营（前台、可 Ctrl-C）：先确认当前快照拉完——没拉完则断点续拉，
        # 已拉完则幂等跳过；随后进入轮询，平台出现更新日期即拉新批，如此循环。
        _pull_once()
        _watch_loop(args, _pull_once)

    elif args.cmd == "longlived":
        rows, incomplete = pullmod.longlived(
            args.db, min_days=args.min_days, china_only=not args.all_scope)
        if incomplete:
            print(f"（注意：{len(incomplete)} 个快照不完整，缺席不计入消失：{incomplete}）")
        print(f"长期有效实例（Active 快照数 ≥ {args.min_days}，共 {len(rows)} 个，优先枚举）：")
        print(f"  {'隐位IP':<20}{'Active天':<8}{'出现天':<8}{'首见':<12}{'末见':<12}{'平台版本'}")
        for r in rows[:args.limit]:
            print(f"  {r['masked_ip']:<20}{r['active_days']:<8}{r['seen_days']:<8}"
                  f"{r['first_snap']:<12}{r['last_snap']:<12}{r['their_version'] or '(无)'}")

    elif args.cmd == "overlap":
        res = pullmod.overlap_with_fofa(args.db, args.fofa_db)
        if res is None:
            print(f"（找不到 fofa 库 {args.fofa_db} 或 clawsec 无快照，先跑 fofa pull / clawsec pull）")
        else:
            total, hit = res
            pct = hit / total * 100 if total else 0
            print(f"clawsec 最新快照 {total:,} 条 → 在 fofa_candidates 找到隐位重叠 {hit:,} 条（{pct:.1f}%）")

    elif args.cmd == "versions":
        conn = sqlite3.connect(args.db)
        try:
            sd = conn.execute("SELECT MAX(snapshot_date) FROM clawsec_snapshots").fetchone()[0]
            rows = conn.execute(
                "SELECT COALESCE(their_version,'(无)') v, COUNT(*) n "
                "FROM clawsec_snapshots WHERE snapshot_date=? GROUP BY v ORDER BY n DESC",
                (sd,)).fetchall()
        except sqlite3.OperationalError:
            print("（还没有 clawsec_snapshots 表，先跑 clawsec pull）")
            return
        finally:
            conn.close()
        print(f"最新快照 {sd} 的版本分布：")
        for v, n in rows:
            print(f"  {v:<14} {n}")

    elif args.cmd == "info":
        ov = ClawSecClient().overview()
        print("ClawSec 平台汇总：")
        for k, val in ov.items():
            print(f"  {k}: {val}")


if __name__ == "__main__":
    main()
