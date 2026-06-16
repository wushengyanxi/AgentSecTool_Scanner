"""FOFA 候选拉取与入库：富字段全量（首次）+ 增量（after=），受额度封顶、可续游标。

候选原样落盘（raw JSON），disk 充足；按 (ip,port) 去重；带 region/city 以便按省规划资产。
确认 + 取版本不在这里——交给本项目探测器复扫候选（不耗 FOFA 额度）。
"""

import datetime
import json
import sqlite3

from .client import FofaClient, cn_query

SCHEMA = """
CREATE TABLE IF NOT EXISTS fofa_candidates (
  ip               TEXT NOT NULL,
  port             INTEGER NOT NULL,
  host             TEXT,
  protocol         TEXT,
  region           TEXT,          -- 省（按省规划资产）
  city             TEXT,
  as_organization  TEXT,
  server           TEXT,
  title            TEXT,
  first_seen       TEXT NOT NULL,
  last_seen        TEXT NOT NULL,
  raw              TEXT,          -- 完整原始字段 JSON（原样落盘）
  PRIMARY KEY (ip, port)
);
CREATE INDEX IF NOT EXISTS idx_fofa_region ON fofa_candidates(region);

CREATE TABLE IF NOT EXISTS fofa_state (
  key   TEXT PRIMARY KEY,
  value TEXT
);
"""


def _conn(db: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def _get_state(conn, key, default=None):
    row = conn.execute("SELECT value FROM fofa_state WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def _set_state(conn, key, value):
    conn.execute(
        "INSERT INTO fofa_state (key, value) VALUES (?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value if value is not None else ""),
    )
    conn.commit()


def _upsert(conn, rows, fields, ts):
    for r in rows:
        rec = dict(zip(fields, r))
        ip = rec.get("ip")
        if not ip:
            continue
        try:
            port = int(rec.get("port") or 0)
        except ValueError:
            port = 0
        conn.execute(
            """INSERT INTO fofa_candidates
                 (ip,port,host,protocol,region,city,as_organization,server,title,first_seen,last_seen,raw)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(ip,port) DO UPDATE SET
                 last_seen=excluded.last_seen, host=excluded.host, protocol=excluded.protocol,
                 region=excluded.region, city=excluded.city, as_organization=excluded.as_organization,
                 server=excluded.server, title=excluded.title, raw=excluded.raw""",
            (ip, port, rec.get("host"), rec.get("protocol"), rec.get("region"), rec.get("city"),
             rec.get("as_organization"), rec.get("server"), rec.get("title"), ts, ts,
             json.dumps(rec, ensure_ascii=False)),
        )
    conn.commit()


def pull(db, mode="full", page_size=2000, max_records=None, min_interval=1.6,
         before=None, after=None, query=None, on_progress=None, client=None):
    """拉取候选入库。mode=full（全量，可续）| delta（增量 after=上次拉取日期）。

    query=None 时用内置 CN 默认查询；传入则为完整 FOFA 查询语句（before/after 仍会追加）。
    on_progress(已拉条数, 总数或None) 每批回调一次，供 CLI 打进度。
    返回 (本次拉取条数, FOFA 剩余额度 dict)。client 可注入（测试用）。"""
    conn = _conn(db)
    cli = client or FofaClient(min_interval=min_interval)
    # 只读 FOFA 的权威剩余（仅用于报告；额度由 FOFA 服务端强制，不在本地记账）
    remaining = {}
    try:
        info = cli.account_info()
        remaining = {"remain_api_query": info.get("remain_api_query"),
                     "remain_api_data": info.get("remain_api_data")}
    except Exception:  # noqa: BLE001
        pass

    today = datetime.date.today().strftime("%Y-%m-%d")
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # 查询：默认用内置 CN 候选查询；--query 可传完整 FOFA 语句覆盖。
    # before/after 是 FOFA 查询操作符（过滤 lastupdatetime），追加用于确定性时间窗切分。
    parts = [query if query else cn_query()]
    if after:
        parts.append(f'after="{after}"')
    if before:
        parts.append(f'before="{before}"')
    if mode == "delta" and not after:
        parts.append(f'after="{_get_state(conn, "last_pull_date") or "2026-01-01"}"')
    query = " && ".join(parts)
    cursor_key = "delta_next" if mode == "delta" else "full_pull_next"
    # 游标只在【同一条查询】上续；查询一变就从头（去重保证不会重复入库）
    start_next = _get_state(conn, cursor_key, "") if _get_state(conn, cursor_key + "_q", "") == query else ""
    _set_state(conn, cursor_key + "_q", query)

    # 进度总数（仅在需要进度时取，1 次便宜的 count；取不到不影响拉取）
    total = None
    if on_progress:
        try:
            total = cli.count(query)
            if max_records is not None:
                total = min(total, max_records) if total else max_records
        except Exception:  # noqa: BLE001
            total = None
    done = {"n": 0}

    def on_batch(rows, field_list, nxt):
        _upsert(conn, rows, field_list, ts)
        _set_state(conn, cursor_key, nxt)  # 保存游标，断点可续
        done["n"] += len(rows)
        if on_progress:
            on_progress(done["n"], total)

    pulled, last_next = cli.search_after(
        query, page_size=page_size, max_records=max_records, start_next=start_next, on_batch=on_batch)

    if mode == "full" and not last_next:
        _set_state(conn, "full_pull_done", today)
        _set_state(conn, "full_pull_next", "")
    _set_state(conn, "last_pull_date", today)
    conn.close()
    return pulled, remaining


def province_breakdown(db):
    """按省（region）统计本地候选数量——满足"按省份规划资产"。"""
    conn = _conn(db)
    rows = conn.execute(
        "SELECT COALESCE(NULLIF(region,''),'(unknown)') AS prov, COUNT(*) AS n "
        "FROM fofa_candidates GROUP BY prov ORDER BY n DESC"
    ).fetchall()
    conn.close()
    return rows


def candidate_count(db):
    conn = _conn(db)
    n = conn.execute("SELECT COUNT(*) FROM fofa_candidates").fetchone()[0]
    conn.close()
    return n


def export_candidates(db, out, limit=None) -> int:
    """把候选导出为 ip,port 的 candidates.csv（喂探测器）。返回导出条数。"""
    conn = _conn(db)
    sql = "SELECT ip, port FROM fofa_candidates ORDER BY ip"
    if limit:
        sql += f" LIMIT {int(limit)}"
    rows = conn.execute(sql).fetchall()
    conn.close()
    with open(out, "w") as f:
        for ip, port in rows:
            f.write(f"{ip},{port}\n")
    return len(rows)


def province_versions(db, scanner_db="data/scanner/scan_results.sqlite"):
    """按省 × 版本统计已探测确认的 OpenClaw（fofa_candidates.region join 扫描库的 observations）。
    满足"按省份规划资产"。observations 在独立的扫描结果库里，跨库 ATTACH 读。需先探测入库。"""
    import os
    if not os.path.exists(scanner_db):
        return []
    conn = _conn(db)
    conn.execute("ATTACH DATABASE ? AS scanner", (scanner_db,))
    has = conn.execute(
        "SELECT name FROM scanner.sqlite_master WHERE type='table' AND name='observations'").fetchone()
    if not has:
        conn.execute("DETACH DATABASE scanner")
        conn.close()
        return []
    rows = conn.execute(
        """
        SELECT COALESCE(NULLIF(c.region,''),'(unknown)') AS prov,
               COALESCE(NULLIF(o.version,''),'(unknown)') AS ver,
               COUNT(DISTINCT o.ip || ':' || o.port) AS n
        FROM fofa_candidates c
        JOIN scanner.observations o ON o.ip = c.ip AND o.port = c.port
        WHERE o.is_openclaw = 1
        GROUP BY prov, ver
        ORDER BY prov, n DESC
        """
    ).fetchall()
    conn.execute("DETACH DATABASE scanner")
    conn.close()
    return rows
