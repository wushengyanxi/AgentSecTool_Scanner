"""扫描进度 CLI。

  python3 -m agentsectool_scanner.progress seed --campaign cn-2026w24 --cidrs tools/scope/output/cn-cidrs.txt --prefix 16
  python3 -m agentsectool_scanner.progress status --campaign cn-2026w24
  python3 -m agentsectool_scanner.progress claim  --campaign cn-2026w24 --worker dev-a
"""

import argparse

from . import blocks
from ..paths import SCANNER_DB, SCOPE_CN_CIDRS


def main(argv=None) -> None:
    ap = argparse.ArgumentParser("progress")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("seed", help="从 CIDR 文件切块登记一个扫描轮次")
    s.add_argument("--db", default=str(SCANNER_DB))
    s.add_argument("--campaign", required=True)
    s.add_argument("--cidrs", default=str(SCOPE_CN_CIDRS), help="CIDR 列表文件")
    s.add_argument("--prefix", type=int, default=16, help="块大小（/prefix），默认 /16")

    t = sub.add_parser("status", help="查看扫描轮次进度")
    t.add_argument("--db", default=str(SCANNER_DB))
    t.add_argument("--campaign", required=True)

    c = sub.add_parser("claim", help="原子领取一个待扫块")
    c.add_argument("--db", default=str(SCANNER_DB))
    c.add_argument("--campaign", required=True)
    c.add_argument("--worker", required=True)

    args = ap.parse_args(argv)

    if args.cmd == "seed":
        with open(args.cidrs) as f:
            cidrs = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        n = blocks.seed_campaign(args.db, args.campaign, cidrs, args.prefix)
        print(f"扫描轮次 {args.campaign}: 新增 {n} 个块（/{args.prefix}）")
        print("进度:", blocks.progress(args.db, args.campaign))
    elif args.cmd == "status":
        print("进度:", blocks.progress(args.db, args.campaign))
    elif args.cmd == "claim":
        blk = blocks.claim_block(args.db, args.campaign, args.worker)
        print(blk if blk else "（无待扫块）")


if __name__ == "__main__":
    main()
