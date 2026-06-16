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
    with open(SCHEMA_PATH) as f:
        conn.executescript(f.read())
    return conn


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


def load(db_path: str, jsonl_path) -> int:
    """读 JSONL，按可信级别分桶收录（探不到的跳过）：upsert 资产、追加观测、落库完整请求/响应。

    返回收录条数（不含被跳过的超时/探不到目标）。"""
    conn = _connect(db_path)
    src = sys.stdin if jsonl_path in (None, "-") else open(jsonl_path)
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
            isoc = 1 if r.get("is_openclaw") else 0
            ver = r.get("version") or None
            vsrc = r.get("version_source") or None
            rank = _CATEGORY_RANK[category]
            # 资产的 category 取历次观测中最强的一档（rank 高者胜）
            conn.execute(
                """
                INSERT INTO assets
                  (asset_id, identity_key, ip, port, is_openclaw, category, latest_version, version_source, first_seen, last_seen, observations)
                VALUES (?,?,?,?,?,?,?,?,?,?,1)
                ON CONFLICT(asset_id) DO UPDATE SET
                  last_seen      = excluded.last_seen,
                  observations   = assets.observations + 1,
                  is_openclaw    = MAX(assets.is_openclaw, excluded.is_openclaw),
                  latest_version = COALESCE(excluded.latest_version, assets.latest_version),
                  version_source = COALESCE(excluded.version_source, assets.version_source),
                  category       = CASE
                    WHEN ? > (CASE assets.category
                                WHEN 'confirmed' THEN 3 WHEN 'confirmed_no_version' THEN 2
                                WHEN 'suspect' THEN 1 ELSE 0 END)
                    THEN excluded.category ELSE assets.category END
                """,
                (aid, key, r.get("ip"), int(r.get("port")), isoc, category, ver, vsrc, ts, ts, rank),
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
