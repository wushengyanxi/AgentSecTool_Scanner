"""给扫描库 assets 表里已有的资产回填/刷新城市归属（按 IP 用 GeoLite2 解析）。

新入库的资产由 store/load.py 自动富化；这个脚本用于一次性补齐存量，或在
GeoLite2 库更新后重刷全量。幂等，可反复运行。

用法（项目根目录，需 .venv 里的 geoip2）：
  .venv/bin/python3 -m geoip.backfill                  # 默认库，只填空缺
  .venv/bin/python3 -m geoip.backfill --all            # 重刷全部（库更新后用）
  .venv/bin/python3 -m geoip.backfill --db path.sqlite
"""

import argparse
import sqlite3
import sys

from .lookup import GeoResolver

DB_PATH = "data/scanner/scan_results.sqlite"


def _ensure_columns(conn: sqlite3.Connection):
    cols = {r[1] for r in conn.execute("PRAGMA table_info(assets)")}
    for col in ("country", "region", "city"):
        if col not in cols:
            conn.execute(f"ALTER TABLE assets ADD COLUMN {col} TEXT")
    for col in ("lat", "lng"):
        if col not in cols:
            conn.execute(f"ALTER TABLE assets ADD COLUMN {col} REAL")


def backfill(db_path: str = DB_PATH, refresh_all: bool = False) -> dict:
    geo = GeoResolver()
    if not geo.ok:
        raise SystemExit(f"GeoLite2 库不可用：{geo.error}")
    conn = sqlite3.connect(db_path)
    try:
        _ensure_columns(conn)
        where = "" if refresh_all else "WHERE city IS NULL AND region IS NULL AND country IS NULL"
        rows = conn.execute(f"SELECT asset_id, ip FROM assets {where}").fetchall()
        filled = located = 0
        for aid, ip in rows:
            country, region, city, lat, lng = geo.lookup(ip)
            conn.execute(
                "UPDATE assets SET country=?, region=?, city=?, lat=?, lng=? WHERE asset_id=?",
                (country, region, city, lat, lng, aid),
            )
            filled += 1
            if city or region or country:
                located += 1
        conn.commit()
        return {"processed": filled, "located": located, "total_assets":
                conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]}
    finally:
        geo.close()
        conn.close()


def main(argv=None):
    ap = argparse.ArgumentParser("geoip.backfill")
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--all", action="store_true", help="重刷全部资产（默认只填空缺）")
    args = ap.parse_args(argv)
    r = backfill(args.db, refresh_all=args.all)
    print(f"回填完成：处理 {r['processed']} 条，其中 {r['located']} 条解析到位置 "
          f"（库内资产共 {r['total_assets']} 条）", file=sys.stderr)


if __name__ == "__main__":
    main()
