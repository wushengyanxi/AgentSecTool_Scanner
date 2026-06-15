"""ClawSec 测绘平台拉取 CLI（与 fofa/ 平级的被动发现源）。

  python3 -m clawsec info                                  # 平台汇总计数
  python3 -m clawsec pull --db scan.sqlite                 # 拉境内 Active 入库（拉完为止，可续）
  python3 -m clawsec pull --scope all                      # 拉全部（境内+海外）
  python3 -m clawsec pull --scope overseas --include-inactive
  python3 -m clawsec overlap --db scan.sqlite              # 与 fofa_candidates 的隐位重叠统计
  python3 -m clawsec versions --db scan.sqlite             # 按平台标注版本统计

命令在项目根目录跑（python3 -m clawsec）。数据入 scan.sqlite 的 clawsec_instances 表。
"""
import argparse
import sqlite3

from . import pull as pullmod
from .client import ClawSecClient


def main(argv=None) -> None:
    ap = argparse.ArgumentParser("clawsec")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("pull", help="拉取暴露实例入库（拉完为止，可续）")
    p.add_argument("--db", default="scan.sqlite")
    p.add_argument("--scope", default="china", choices=["china", "overseas", "all"],
                   help="拉取范围（默认 china 境内）")
    p.add_argument("--include-inactive", action="store_true",
                   help="连同 Inactive 一起拉（默认只拉 Active）")

    o = sub.add_parser("overlap", help="与 fofa_candidates 的隐位重叠统计")
    o.add_argument("--db", default="scan.sqlite")

    v = sub.add_parser("versions", help="按平台标注版本统计")
    v.add_argument("--db", default="scan.sqlite")

    sub.add_parser("info", help="平台汇总计数")

    args = ap.parse_args(argv)

    if args.cmd == "pull":
        def _progress(cur, total, page, total_pages):
            print(f"\r  拉取中… 第 {page}/{total_pages} 页，库内 {cur:,}/{total:,} 条",
                  end="", flush=True)

        n, n_total = pullmod.pull(args.db, scope=args.scope,
                                  active_only=not args.include_inactive, on_progress=_progress)
        print()
        print(f"本次新增 {n} 条 → clawsec_instances（{args.scope} 共 {n_total} 条）")

    elif args.cmd == "overlap":
        res = pullmod.overlap_with_fofa(args.db)
        if res is None:
            print("（scan.sqlite 里没有 fofa_candidates 表，先跑 fofa pull）")
        else:
            total, hit = res
            pct = hit / total * 100 if total else 0
            print(f"clawsec {total} 条 → 在 fofa_candidates 找到隐位重叠 {hit} 条（{pct:.1f}%）")

    elif args.cmd == "versions":
        conn = sqlite3.connect(args.db)
        try:
            rows = conn.execute(
                "SELECT COALESCE(their_version,'(无)') v, COUNT(*) n "
                "FROM clawsec_instances GROUP BY v ORDER BY n DESC").fetchall()
        except sqlite3.OperationalError:
            print("（还没有 clawsec_instances 表，先跑 clawsec pull）")
            return
        finally:
            conn.close()
        for v, n in rows:
            print(f"  {v:<14} {n}")

    elif args.cmd == "info":
        ov = ClawSecClient().overview()
        print("ClawSec 平台汇总：")
        for k, val in ov.items():
            print(f"  {k}: {val}")


if __name__ == "__main__":
    main()
