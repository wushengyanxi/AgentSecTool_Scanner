"""FOFA 工作流 CLI。

  python3 -m fofa info                                            # 账号与剩余额度 + 默认候选查询
  python3 -m fofa pull --db scan.sqlite --full --before 2026-05-30  # 全量、时间窗（可续）
  python3 -m fofa pull --db scan.sqlite --delta                   # 增量（after=上次拉取日期）
  python3 -m fofa pull --db scan.sqlite --query '...' --before ...  # 自定义完整 FOFA 查询
  python3 -m fofa provinces --db scan.sqlite                      # 按省候选数量
"""

import argparse

from . import pull as pullmod
from .client import FofaClient, cn_query


def main(argv=None) -> None:
    ap = argparse.ArgumentParser("fofa")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("pull", help="拉取候选入库")
    p.add_argument("--db", default="scan.sqlite")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--full", action="store_true", help="全量（默认，可续）")
    g.add_argument("--delta", action="store_true", help="增量")
    p.add_argument("--query", default=None,
                   help='完整 FOFA 查询语句（覆盖默认）；不传则用内置 CN 候选查询')
    p.add_argument("--before", default=None, help='时间窗：只拉 lastupdatetime 早于该日，如 2026-05-30')
    p.add_argument("--after", default=None, help='时间窗：只拉 lastupdatetime 晚于该日')
    p.add_argument("--max-records", type=int, default=None, help="本次最多拉取条数（封顶，省额度）")
    p.add_argument("--page-size", type=int, default=2000)

    pr = sub.add_parser("provinces", help="按省候选数量")
    pr.add_argument("--db", default="scan.sqlite")

    e = sub.add_parser("export", help="导出候选为 candidates.csv（喂探测器）")
    e.add_argument("--db", default="scan.sqlite")
    e.add_argument("--out", default="candidates.csv")
    e.add_argument("--limit", type=int, default=None)

    pv = sub.add_parser("province-versions", help="按省 × 版本统计已探测资产")
    pv.add_argument("--db", default="scan.sqlite")

    sub.add_parser("info", help="账号与剩余额度")

    args = ap.parse_args(argv)

    if args.cmd == "pull":
        mode = "delta" if args.delta else "full"

        def _progress(pulled, total):
            if total:
                print(f"\r  拉取中… {pulled:,} / {total:,}（{pulled / total * 100:.0f}%）",
                      end="", flush=True)
            else:
                print(f"\r  拉取中… {pulled:,} 条", end="", flush=True)

        n, remaining = pullmod.pull(args.db, mode=mode, page_size=args.page_size,
                                    max_records=args.max_records, before=args.before,
                                    after=args.after, query=args.query, on_progress=_progress)
        print()  # 进度行收尾换行
        print(f"拉取 {n} 条 → fofa_candidates（库内共 {pullmod.candidate_count(args.db)} 条）")
        if remaining:
            print(f"FOFA 剩余：查询 {remaining.get('remain_api_query')} 次，"
                  f"数据 {remaining.get('remain_api_data')} 条")
    elif args.cmd == "provinces":
        for prov, n in pullmod.province_breakdown(args.db):
            print(f"  {prov:<18} {n}")
    elif args.cmd == "export":
        n = pullmod.export_candidates(args.db, args.out, limit=args.limit)
        print(f"导出 {n} 条候选 → {args.out}")
    elif args.cmd == "province-versions":
        rows = pullmod.province_versions(args.db)
        if not rows:
            print("（还没有探测数据；先 export → 探测 → 入库）")
        for prov, ver, n in rows:
            print(f"  {prov:<14} {ver:<16} {n}")
    elif args.cmd == "info":
        info = FofaClient().account_info()
        print("isvip=%s vip_level=%s remain_api_query=%s remain_api_data=%s" % (
            info.get("isvip"), info.get("vip_level"),
            info.get("remain_api_query"), info.get("remain_api_data")))
        print("候选查询:", cn_query())


if __name__ == "__main__":
    main()
