"""results.jsonl → SQLite 的核心逻辑。"""

import hashlib
import json
import os
import sqlite3
import sys

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


def identity_key(r: dict) -> str:
    """资产身份按 ip:port —— 每台独特的暴露主机一条记录。

    目标是统计"全网有多少个 OpenClaw 服务器"，所以一台主机就是一个实例，不按内容指纹跨 IP
    合并（那会把不同主机当成同一资产）。资产名等内容指纹仍存在 observations/probe_records 里
    供版本反推，只是不作去重键。"""
    return f"ipport:{r.get('ip')}:{r.get('port')}"


def asset_id(key: str) -> str:
    return hashlib.sha1(key.encode()).hexdigest()


def _unwrap(r: dict):
    """兼容两种输入：ocprobe 的扁平 Result，或 ZGrab2 的信封
    {"ip":..., "data":{"openclaw":{"result":{...}, "port":...}}}。
    取出内层 Result；若是信封但无 result（如纯连接失败）则返回 None 以跳过。"""
    data = r.get("data")
    if isinstance(data, dict):
        for mod in data.values():
            if isinstance(mod, dict) and isinstance(mod.get("result"), dict):
                res = mod["result"]
                res.setdefault("ip", r.get("ip"))
                res.setdefault("port", mod.get("port"))
                return res
        return None
    return r


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    # 先迁移已存在的旧表（含快照化重建），再跑 schema 建缺失的表/索引——顺序很重要：
    # schema.sql 的 idx_assets_date 引用 snapshot_date，若旧表尚未迁移会建索引失败。
    _migrate(conn)
    with open(SCHEMA_PATH) as f:
        conn.executescript(f.read())
    return conn


def _migrate(conn: sqlite3.Connection):
    """对已存在的旧库补齐新列（CREATE TABLE IF NOT EXISTS 不会改已有表）。幂等。

    在 _connect 中先于 schema 执行。全新库此时 assets 表尚不存在（cols 为空），直接返回，
    由随后的 schema.sql 建表；只有已存在的旧表才需要在此补列 / 快照化重建。"""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(assets)")}
    if not cols:
        return  # 全新库，无旧表可迁移
    for col in ("country", "region", "city"):
        if col not in cols:
            conn.execute(f"ALTER TABLE assets ADD COLUMN {col} TEXT")
    for col in ("lat", "lng"):
        if col not in cols:
            conn.execute(f"ALTER TABLE assets ADD COLUMN {col} REAL")
    # 快照化迁移：旧库 assets 主键是 asset_id（无 snapshot_date）。改为 (snapshot_date, asset_id)。
    # SQLite 不能直接改主键，需重建表并把旧数据按其 last_seen 的日期归为一个快照。
    if "snapshot_date" not in cols and cols:
        _migrate_to_snapshots(conn)


def _migrate_to_snapshots(conn: sqlite3.Connection):
    """把旧的当前态 assets 表迁成按快照分行：现有每行的 snapshot_date 取其 last_seen 的日期。"""
    conn.execute("ALTER TABLE assets RENAME TO assets_old")
    with open(SCHEMA_PATH) as f:
        conn.executescript(f.read())  # 建新 assets（含 snapshot_date 主键）
    # 旧行的 snapshot_date = last_seen 的 YYYY-MM-DD；同 (date, asset_id) 理论上唯一
    conn.execute(
        """
        INSERT OR REPLACE INTO assets
          (snapshot_date, asset_id, identity_key, ip, port, is_openclaw, category,
           latest_version, version_source, first_seen, last_seen, observations,
           country, region, city, lat, lng)
        SELECT substr(last_seen,1,10), asset_id, identity_key, ip, port, is_openclaw, category,
               latest_version, version_source, first_seen, last_seen, observations,
               country, region, city, lat, lng
        FROM assets_old
        """
    )
    conn.execute("DROP TABLE assets_old")
    conn.commit()


# category 的可信级别排序（资产取历次观测中最强的一档）
_CATEGORY_RANK = {None: 0, "suspect": 1, "confirmed_no_version": 2, "confirmed": 3}


def classify(r: dict):
    """把一条探测结果分类为收录桶；探不到（无任何命中）返回 None（不收录）。

    confirmed            明确 OpenClaw（白名单判 True）且取到版本
    confirmed_no_version 明确 OpenClaw 但版本未取到
    suspect              中了部分特征但未达白名单——保留供复扫/优化，但不呈现为 OpenClaw
    None                 超时/探不到/纯无命中——无价值，不收录
    """
    if r.get("is_openclaw"):
        if r.get("version") or r.get("version_candidates"):
            return "confirmed"
        return "confirmed_no_version"
    if r.get("matched"):  # 中了某些测试项但未满足白名单
        return "suspect"
    return None  # error_type=timeout/down/... 或纯无命中 → 不收录


def _snapshot_date(jsonl_path) -> str:
    """第一遍扫描：取整个 jsonl 内所有记录 ts 的日期众数，作为本次快照的基准日期。

    跨天扫描时以出现最多的日期为准；整个 jsonl 的所有记录统一归到这个 snapshot_date。
    stdin 输入无法二次扫描，故 stdin 路径下由调用方在主循环里现算（见 load）。"""
    from collections import Counter
    c = Counter()
    with open(jsonl_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            r = _unwrap(r) or r
            ts = (r.get("ts") or "")[:10]  # YYYY-MM-DD
            if ts:
                c[ts] += 1
    return c.most_common(1)[0][0] if c else ""


def load(db_path: str, jsonl_path) -> int:
    """读 JSONL，按快照收录：snapshot_date 取该 jsonl 内 ts 日期众数；同一快照内同 ip:port
    以最新结果为准（REPLACE）；upsert 资产、追加观测、落库完整请求/响应。

    返回收录条数（不含被跳过的超时/探不到目标）。"""
    conn = _connect(db_path)
    is_stdin = jsonl_path in (None, "-")
    # 基准日期：文件输入先扫一遍取众数；stdin 不能二次读，逐条用各自 ts 的日期兜底。
    snap_date = "" if is_stdin else _snapshot_date(jsonl_path)
    src = sys.stdin if is_stdin else open(jsonl_path)
    # IP→城市富化（软依赖：库缺失时 geo.ok=False，lookup 返回空，不阻断入库）
    from geoip.lookup import GeoResolver
    geo = GeoResolver()
    n = 0
    try:
        for line in src:
            line = line.strip()
            if not line:
                continue
            r = _unwrap(json.loads(line))
            if r is None:
                continue
            category = classify(r)
            if category is None:
                continue  # 探不到/超时/纯无命中——不收录
            key = identity_key(r)
            aid = asset_id(key)
            ts = r.get("ts")
            sdate = snap_date or (ts or "")[:10]  # 文件用众数；stdin 用本条 ts 日期兜底
            isoc = 1 if r.get("is_openclaw") else 0
            ver = r.get("version") or None
            vsrc = r.get("version_source") or None
            # 物理位置：每次入库都按 IP 重新解析（库更新后能跟上变化）
            country, region, city, lat, lng = geo.lookup(r.get("ip"))
            # 同一快照内同 (snapshot_date, ip:port) 以【最新结果】为准：研判/版本/分类直接用本条
            # 覆盖（excluded.*），不再跨观测取最强档——快照存的是该版当时的判定，不是历史聚合。
            # first_seen 取该版内最早 ts，last_seen 取最近 ts，observations 累加（本版扫到几次）。
            conn.execute(
                """
                INSERT INTO assets
                  (snapshot_date, asset_id, identity_key, ip, port, is_openclaw, category, latest_version, version_source, first_seen, last_seen, observations, country, region, city, lat, lng)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?,?)
                ON CONFLICT(snapshot_date, asset_id) DO UPDATE SET
                  last_seen      = MAX(assets.last_seen, excluded.last_seen),
                  first_seen     = MIN(assets.first_seen, excluded.first_seen),
                  observations   = assets.observations + 1,
                  is_openclaw    = excluded.is_openclaw,
                  latest_version = excluded.latest_version,
                  version_source = excluded.version_source,
                  category       = excluded.category,
                  country        = COALESCE(excluded.country, assets.country),
                  region         = COALESCE(excluded.region, assets.region),
                  city           = COALESCE(excluded.city, assets.city),
                  lat            = COALESCE(excluded.lat, assets.lat),
                  lng            = COALESCE(excluded.lng, assets.lng)
                """,
                (sdate, aid, key, r.get("ip"), int(r.get("port")), isoc, category, ver, vsrc, ts, ts,
                 country, region, city, lat, lng),
            )
            cur = conn.execute(
                """
                INSERT INTO observations
                  (asset_id, ip, port, ts, is_openclaw, category, rule, version, version_source, matched, error_type, tls)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    aid, r.get("ip"), int(r.get("port")), ts, isoc, category,
                    r.get("rule") or None, ver, vsrc,
                    json.dumps(r.get("matched") or [], ensure_ascii=False),
                    r.get("error_type") or None,
                    1 if r.get("tls") else 0,
                ),
            )
            obs_id = cur.lastrowid
            ev = r.get("evidence") or {}
            for p in ev.get("probes") or []:
                conn.execute(
                    """
                    INSERT INTO probe_records (observation_id, test_id, request, response, hit)
                    VALUES (?,?,?,?,?)
                    """,
                    (obs_id, p.get("id"), p.get("request"), p.get("response"),
                     1 if p.get("hit") else 0),
                )
            n += 1
        conn.commit()
    finally:
        geo.close()
        if src is not sys.stdin:
            src.close()
        conn.close()
    return n


def stats(db_path: str):
    """返回 (汇总 dict, 版本分布 rows)。"""
    conn = sqlite3.connect(db_path)
    try:
        def one(sql: str):
            return conn.execute(sql).fetchone()[0]

        summary = {
            "assets_total": one("SELECT COUNT(*) FROM assets"),
            # 按可信级别分桶（实例收集平台口径）
            "confirmed": one("SELECT COUNT(*) FROM assets WHERE category='confirmed'"),
            "confirmed_no_version": one("SELECT COUNT(*) FROM assets WHERE category='confirmed_no_version'"),
            "suspect": one("SELECT COUNT(*) FROM assets WHERE category='suspect'"),
            "openclaw_total（confirmed+no_version）": one(
                "SELECT COUNT(*) FROM assets WHERE category IN ('confirmed','confirmed_no_version')"),
            "observations": one("SELECT COUNT(*) FROM observations"),
            "probe_records": one("SELECT COUNT(*) FROM probe_records"),
        }
        # 版本分布只统计明确 OpenClaw 实例
        rows = conn.execute(
            "SELECT latest_version, COUNT(*) FROM assets "
            "WHERE category IN ('confirmed','confirmed_no_version') "
            "GROUP BY latest_version ORDER BY 2 DESC"
        ).fetchall()
        return summary, rows
    finally:
        conn.close()
