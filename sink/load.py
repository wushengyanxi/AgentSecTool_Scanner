"""results.jsonl → SQLite 的核心逻辑。"""

import hashlib
import json
import os
import sqlite3
import sys

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


def identity_key(r: dict) -> str:
    """资产身份：确认为 OpenClaw 且有内容指纹时用内容指纹（跨 IP 稳定），否则 ip:port。"""
    ev = r.get("evidence") or {}
    if r.get("is_openclaw"):
        parts = [
            ev.get("favicon_md5", ""),
            ",".join(sorted(ev.get("asset_hashes") or [])),
            ev.get("csp_sha256", ""),
        ]
        joined = "|".join(parts)
        if joined.strip("|"):
            return "content:" + joined
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


def load(db_path: str, jsonl_path) -> int:
    """读 JSONL，upsert 资产、追加观测、落库每个测试项的完整请求/响应。返回处理条数。"""
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
            key = identity_key(r)
            aid = asset_id(key)
            ts = r.get("ts")
            isoc = 1 if r.get("is_openclaw") else 0
            ver = r.get("version") or None
            vsrc = r.get("version_source") or None
            conn.execute(
                """
                INSERT INTO assets
                  (asset_id, identity_key, ip, port, is_openclaw, latest_version, version_source, first_seen, last_seen, observations)
                VALUES (?,?,?,?,?,?,?,?,?,1)
                ON CONFLICT(asset_id) DO UPDATE SET
                  last_seen      = excluded.last_seen,
                  observations   = assets.observations + 1,
                  is_openclaw    = MAX(assets.is_openclaw, excluded.is_openclaw),
                  latest_version = COALESCE(excluded.latest_version, assets.latest_version),
                  version_source = COALESCE(excluded.version_source, assets.version_source)
                """,
                (aid, key, r.get("ip"), int(r.get("port")), isoc, ver, vsrc, ts, ts),
            )
            cur = conn.execute(
                """
                INSERT INTO observations
                  (asset_id, ip, port, ts, is_openclaw, rule, version, version_source, matched, error_type, tls)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    aid, r.get("ip"), int(r.get("port")), ts, isoc,
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
            "assets_openclaw": one("SELECT COUNT(*) FROM assets WHERE is_openclaw=1"),
            "with_version": one("SELECT COUNT(*) FROM assets WHERE is_openclaw=1 AND latest_version IS NOT NULL"),
            "observations": one("SELECT COUNT(*) FROM observations"),
            "probe_records": one("SELECT COUNT(*) FROM probe_records"),
        }
        rows = conn.execute(
            "SELECT latest_version, COUNT(*) FROM assets WHERE is_openclaw=1 "
            "GROUP BY latest_version ORDER BY 2 DESC"
        ).fetchall()
        return summary, rows
    finally:
        conn.close()
