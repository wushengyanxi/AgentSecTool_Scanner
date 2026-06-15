"""ClawSec 候选拉取与入库：写入 scan.sqlite 的 clawsec_instances 表，与 FOFA 同库可交叉。

ClawSec 隐藏一位 IP（masked_ip），补全/枚举由下游探测处理——本模块只取候选并保留
平台自己的版本判定（their_version）与历史漏洞标注，供与本项目探测器做双源对比。

断点续传：按 id 去重 + 记住已完成页码（clawsec_state），中断重跑接着拉；
遇服务端限流（429）由 client 自动按 Retry-After 等待，无人值守。
"""
import datetime
import json
import sqlite3

from .client import ClawSecClient

SCHEMA = """
CREATE TABLE IF NOT EXISTS clawsec_instances (
  id              TEXT PRIMARY KEY,   -- 平台记录 id（去重键）
  masked_ip       TEXT NOT NULL,      -- 隐藏一位的 IP，如 1.12.*.76（补全由下游探测处理）
  port            INTEGER,
  service         TEXT,
  their_version   TEXT,               -- 平台自己的版本判定（可与本项目探测器对比）
  country         TEXT,
  province        TEXT,               -- 中国大陆省份
  cn_city         TEXT,
  asn             TEXT,
  organization    TEXT,
  runtime_status  TEXT,               -- Active / Inactive
  is_china        INTEGER,            -- 1=境内
  authenticated   INTEGER,            -- 是否已鉴权
  cred_leaked     INTEGER,            -- 凭据是否泄露
  has_mcp         INTEGER,
  vuln_count      INTEGER,            -- 历史漏洞匹配数
  vuln_severity   TEXT,               -- 最高严重级
  first_seen      TEXT,               -- 平台首次发现日
  last_seen       TEXT,               -- 平台最后探测日
  pulled_at       TEXT NOT NULL,      -- 本地拉取时间
  raw             TEXT,               -- 完整原始字段 JSON
  scope           TEXT                -- 拉取时的 scope（china/overseas/all）
);
CREATE INDEX IF NOT EXISTS idx_clawsec_masked ON clawsec_instances(masked_ip);
CREATE INDEX IF NOT EXISTS idx_clawsec_ver ON clawsec_instances(their_version);
CREATE INDEX IF NOT EXISTS idx_clawsec_province ON clawsec_instances(province);

CREATE TABLE IF NOT EXISTS clawsec_state (
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
    row = conn.execute("SELECT value FROM clawsec_state WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def _set_state(conn, key, value):
    conn.execute(
        "INSERT INTO clawsec_state (key, value) VALUES (?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value if value is not None else ""),
    )
    conn.commit()


def _b(v):
    """三态布尔 → 0/1/None。"""
    return None if v is None else (1 if v else 0)


def _upsert(conn, services, scope, ts):
    n = 0
    for s in services:
        sid = s.get("id")
        if not sid:
            continue
        conn.execute(
            """INSERT INTO clawsec_instances
                 (id,masked_ip,port,service,their_version,country,province,cn_city,asn,
                  organization,runtime_status,is_china,authenticated,cred_leaked,has_mcp,
                  vuln_count,vuln_severity,first_seen,last_seen,pulled_at,raw,scope)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 their_version=excluded.their_version, runtime_status=excluded.runtime_status,
                 last_seen=excluded.last_seen, vuln_count=excluded.vuln_count,
                 vuln_severity=excluded.vuln_severity, pulled_at=excluded.pulled_at,
                 raw=excluded.raw""",
            (sid, s.get("maskedIp"), s.get("port"), s.get("service"), s.get("serverVersion"),
             s.get("country"), s.get("province"), s.get("cnCity"), s.get("asn"),
             s.get("organization"), s.get("runtimeStatus"), _b(s.get("isChinaInstance")),
             _b(s.get("authenticated")), _b(s.get("credentialsLeaked")), _b(s.get("hasMcp")),
             s.get("historicalVulnCount"), s.get("historicalVulnMaxSeverity"),
             s.get("firstSeen"), s.get("lastSeen"), ts,
             json.dumps(s, ensure_ascii=False), scope),
        )
        n += 1
    conn.commit()
    return n


def pull(db, scope="china", active_only=True, on_progress=None, client=None):
    """拉取候选入库（拉完为止，可续）。scope=china（默认）/overseas/all。

    on_progress(已入库数, 总数, 当前页, 总页数) 每页回调一次。
    返回 (本次新增入库数, 库内该 scope 总数)。"""
    conn = _conn(db)
    cli = client or ClawSecClient()
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    page_key = f"done_pages:{scope}:{int(active_only)}"
    done = set(json.loads(_get_state(conn, page_key, "[]")))

    total, total_pages = cli.total_pages(scope, active_only)
    added = 0
    for page in range(1, total_pages + 1):
        if page in done:
            continue
        data = cli.page(page, scope, active_only)
        added += _upsert(conn, data["services"], scope, ts)
        done.add(page)
        _set_state(conn, page_key, json.dumps(sorted(done)))
        if on_progress:
            cur = conn.execute(
                "SELECT COUNT(*) FROM clawsec_instances WHERE scope=?", (scope,)).fetchone()[0]
            on_progress(cur, total, page, total_pages)

    n_total = conn.execute(
        "SELECT COUNT(*) FROM clawsec_instances WHERE scope=?", (scope,)).fetchone()[0]
    conn.close()
    return added, n_total


def instance_count(db, scope=None):
    conn = _conn(db)
    if scope:
        n = conn.execute(
            "SELECT COUNT(*) FROM clawsec_instances WHERE scope=?", (scope,)).fetchone()[0]
    else:
        n = conn.execute("SELECT COUNT(*) FROM clawsec_instances").fetchone()[0]
    conn.close()
    return n


def overlap_with_fofa(db):
    """clawsec 隐位 IP × fofa_candidates 的隐位重叠统计（两源交叉，纯 SQL 近似）。

    隐位匹配：clawsec masked_ip 形如 a.b.*.d，匹配 fofa ip 的第1/2/4段相同。
    返回 (clawsec总数, 能在fofa隐位补全到≥1个完整IP的条数)。"""
    conn = _conn(db)
    has_fofa = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='fofa_candidates'").fetchone()
    if not has_fofa:
        conn.close()
        return None
    # fofa 18789 端口 IP 的 (seg0,seg1,seg3) 集合
    fofa_keys = set()
    for (ip,) in conn.execute("SELECT ip FROM fofa_candidates WHERE port=18789"):
        p = ip.split(".")
        if len(p) == 4:
            fofa_keys.add((p[0], p[1], p[3]))
    total = hit = 0
    for (m,) in conn.execute("SELECT masked_ip FROM clawsec_instances"):
        total += 1
        p = m.split(".")
        if len(p) == 4 and p[2] == "*" and (p[0], p[1], p[3]) in fofa_keys:
            hit += 1
    conn.close()
    return total, hit
