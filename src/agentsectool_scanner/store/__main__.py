"""落地 CLI（扫描结果库）：
  python3 -m agentsectool_scanner.store --in prober/output/results.jsonl
  python3 -m agentsectool_scanner.store --stats
  python3 -m agentsectool_scanner.store --report out.html
"""

import argparse
import os
import sys

from . import load as loader
from . import report as reporter
from ..paths import SCANNER_DB


def main(argv=None) -> None:
    ap = argparse.ArgumentParser("store", description="results.jsonl → SQLite（assets/observations/probe_records）")
    ap.add_argument("--db", default=str(SCANNER_DB))
    ap.add_argument("--in", dest="infile", default=None, help="results.jsonl；缺省读 stdin（仅在导入时）")
    ap.add_argument("--stats", action="store_true", help="只打印统计，不导入")
    ap.add_argument("--report", dest="report", default=None,
                    help="生成报告到该文件，格式按后缀：.html/.json/.csv/.txt")
    args = ap.parse_args(argv)
    d = os.path.dirname(args.db)
    if d and not args.report:
        os.makedirs(d, exist_ok=True)

    if args.report:
        n = reporter.generate(args.db, args.report)
        print(f"report: {n} 个目标 → {args.report}", file=sys.stderr)
        return

    if not args.stats:
        n = loader.load(args.db, args.infile or "-")
        print(f"loaded {n} results → {args.db}", file=sys.stderr)

    summary, rows = loader.stats(args.db)
    for k, v in summary.items():
        print(f"{k}: {v}")
    print("version_distribution:")
    for ver, count in rows:
        print(f"  {ver or '(unknown)'}: {count}")


if __name__ == "__main__":
    main()
