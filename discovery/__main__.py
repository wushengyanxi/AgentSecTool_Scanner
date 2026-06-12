"""发现层 CLI：主动扫描 + FOFA 被动种子 → candidates.csv。

例：
  # 本地小范围（内置后端，无需 root）
  python3 -m discovery --cidr 127.0.0.0/30 --ports 18789 --backend internal --allow-reserved

  # 全网（masscan，需 sudo；务必带黑名单与合理限速）
  sudo python3 -m discovery --cidr 0.0.0.0/0 --backend masscan --rate 20000 --excludefile config/blocklist.txt

  # 叠加 FOFA 被动种子（凭据走环境变量）
  FOFA_EMAIL=... FOFA_KEY=... python3 -m discovery --cidr 0.0.0.0/0 --backend masscan --fofa
"""

import argparse
import os
import sys

from . import active, merge, passive
from . import blocklist as bl


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(
        "discovery",
        description="OpenClaw 发现层：主动扫描 + FOFA 被动种子 → candidates.csv",
    )
    ap.add_argument("--cidr", action="append", default=[], help="目标 CIDR（可多次）；全网用 0.0.0.0/0")
    ap.add_argument("--ports", default="18789,80,443,8080,8443,3000", help="端口集，逗号分隔")
    ap.add_argument("--backend", choices=["masscan", "zmap", "internal", "none"], default="internal")
    ap.add_argument("--rate", type=int, default=1000, help="主动扫描包速率")
    ap.add_argument("--excludefile", default=None, help="黑名单/保留网段文件（主动扫描排除）")
    ap.add_argument("--allow-reserved", action="store_true", help="不排除保留/私有网段（仅本地测试）")
    ap.add_argument("--fofa", action="store_true", help="启用 FOFA 种子（凭据取自 FOFA_EMAIL/FOFA_KEY）")
    ap.add_argument("--fofa-query", default='title="OpenClaw Control" || port="18789"')
    ap.add_argument("--fofa-max", type=int, default=10000)
    ap.add_argument("--shodan", action="store_true", help="启用 Shodan 种子（凭据取自 SHODAN_API_KEY）")
    ap.add_argument("--shodan-query", default='http.title:"OpenClaw Control"')
    ap.add_argument("--shodan-max", type=int, default=10000)
    ap.add_argument("--out", default="candidates.csv")
    args = ap.parse_args(argv)

    ports = [int(p) for p in args.ports.split(",") if p.strip()]

    active_pairs: list[tuple[str, int]] = []
    if args.backend != "none" and args.cidr:
        if args.backend == "internal":
            active_pairs = active.scan_internal(args.cidr, ports)
        elif args.backend == "masscan":
            active_pairs = active.scan_masscan(args.cidr, ports, rate=args.rate, excludefile=args.excludefile)
        elif args.backend == "zmap":
            active_pairs = active.scan_zmap(args.cidr, ports, rate=args.rate, blocklist=args.excludefile)
    print(f"[active/{args.backend}] {len(active_pairs)} open", file=sys.stderr)

    passive_pairs: list[tuple[str, int]] = []
    if args.fofa:
        email, key = os.environ.get("FOFA_EMAIL"), os.environ.get("FOFA_KEY")
        if not email or not key:
            sys.exit("启用了 --fofa 但缺少环境变量 FOFA_EMAIL / FOFA_KEY")
        fofa_pairs = passive.fofa_search(email, key, args.fofa_query, max_results=args.fofa_max)
        passive_pairs += fofa_pairs
        print(f"[passive/fofa] {len(fofa_pairs)} seeds", file=sys.stderr)
    if args.shodan:
        skey = os.environ.get("SHODAN_API_KEY")
        if not skey:
            sys.exit("启用了 --shodan 但缺少环境变量 SHODAN_API_KEY")
        shodan_pairs = passive.shodan_search(skey, args.shodan_query, max_results=args.shodan_max)
        passive_pairs += shodan_pairs
        print(f"[passive/shodan] {len(shodan_pairs)} seeds", file=sys.stderr)

    excl = bl.load_excludefile(args.excludefile) if args.excludefile else []
    blk = bl.Blocklist(extra_cidrs=excl, include_reserved=not args.allow_reserved)
    pairs = merge.merge_candidates(active_pairs, passive_pairs, blocklist=blk)
    merge.write_candidates(pairs, args.out)
    print(f"[merge] {len(pairs)} candidates → {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
