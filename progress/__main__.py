"""扫描进度 CLI。

  python3 -m progress seed --campaign cn-2026w24 --cidrs scope/cn-cidrs.txt --prefix 16
  python3 -m progress status --campaign cn-2026w24
  python3 -m progress claim  --campaign cn-2026w24 --worker dev-a   # 领一个块（打印 CIDR）
"""

import argparse

from . import blocks


def main(argv=None) -> None:
    ap = argparse.ArgumentParser("progress")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("seed", help="从 CIDR 文件切块登记一个战役")
    s.add_argument("--db", default="data/scanner/scan_results.sqlite")
    s.add_argument("--campaign", required=True)
    s.add_argument("--cidrs", required=True, help="CIDR 列表文件，如 scope/cn-cidrs.txt")
    s.add_argument("--prefix", type=int, default=16, help="块大小（/prefix），默认 /16")

    t = sub.add_parser("status", help="查看战役进度")
    t.add_argument("--db", default="data/scanner/scan_results.sqlite")
    t.add_argument("--campaign", required=True)

    c = sub.add_parser("claim", help="原子领取一个待扫块")
    c.add_argument("--db", default="data/scanner/scan_results.sqlite")
    c.add_argument("--campaign", required=True)
    c.add_argument("--worker", required=True)

    args = ap.parse_args(argv)

    if args.cmd == "seed":
        with open(args.cidrs) as f:
            cidrs = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        n = blocks.seed_campaign(args.db, args.campaign, cidrs, args.prefix)
        print(f"战役 {args.campaign}: 新增 {n} 个块（/{args.prefix}）")
        print("进度:", blocks.progress(args.db, args.campaign))
    elif args.cmd == "status":
        print("进度:", blocks.progress(args.db, args.campaign))
    elif args.cmd == "claim":
        blk = blocks.claim_block(args.db, args.campaign, args.worker)
        print(blk if blk else "（无待扫块）")


if __name__ == "__main__":
    main()
