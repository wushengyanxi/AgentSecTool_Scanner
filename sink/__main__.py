"""落地 CLI：`python3 -m sink --db scan.sqlite --in results.jsonl` 或 `--stats`。"""

import argparse
import sys

from . import load as loader


def main(argv=None) -> None:
    ap = argparse.ArgumentParser("sink", description="results.jsonl → SQLite（assets/observations）")
    ap.add_argument("--db", default="scan.sqlite")
    ap.add_argument("--in", dest="infile", default="-", help="results.jsonl；缺省读 stdin")
    ap.add_argument("--stats", action="store_true", help="只打印统计，不导入")
    args = ap.parse_args(argv)

    if not args.stats:
        n = loader.load(args.db, args.infile)
        print(f"loaded {n} results → {args.db}", file=sys.stderr)

    summary, rows = loader.stats(args.db)
    for k, v in summary.items():
        print(f"{k}: {v}")
    print("version_distribution:")
    for ver, count in rows:
        print(f"  {ver or '(unknown)'}: {count}")


if __name__ == "__main__":
    main()
