"""ClawSec 每日全量快照拉取与入库：写入 tools/clawsec/data/clawsec.sqlite 的 clawsec_snapshots 表。

ClawSec 平台每日更新一次，页面给出"最近更新时间"（overview 的 lastScanTime）。每天按平台
限速全量存一轮，以 lastScanTime 为快照日期（snapshot_date）归档——同一实例每天一行，从而
可跨快照分析"哪些实例长期有效"（连续 Active），优先枚举这些更可能仍在线的实例找真实 IP。

ClawSec 隐藏一位 IP（masked_ip），补全/枚举由下游探测处理——本模块只取候选并保留平台自己
的版本判定（their_version）与历史漏洞标注，供与本项目探测器做双源对比。

断点续传：按 (snapshot_date, page) 记已完成页（clawsec_state），中断重跑接着拉；同一
snapshot_date 全量入库后再拉会跳过（幂等）。遇 429 由 client 自动按 Retry-After 等待。
"""
import datetime
import json
import os
import sqlite3

from .client import ClawSecClient

SCHEMA = """
CREATE TABLE IF NOT EXISTS clawsec_snapshots (
  snapshot_date   TEXT NOT NULL,      -- 快照日期（= 平台 lastScanTime），同实例每天一行
  id              TEXT NOT NULL,      -- 平台记录 id
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
  scope           TEXT,               -- 拉取时的 scope（china/overseas/all）
  PRIMARY KEY (snapshot_date, id)
);
CREATE INDEX IF NOT EXISTS idx_clawsec_masked ON clawsec_snapshots(masked_ip);
CREATE INDEX IF NOT EXISTS idx_clawsec_ver ON clawsec_snapshots(their_version);
CREATE INDEX IF NOT EXISTS idx_clawsec_date ON clawsec_snapshots(snapshot_date);
CREATE INDEX IF NOT EXISTS idx_clawsec_status ON clawsec_snapshots(runtime_status);

CREATE TABLE IF NOT EXISTS clawsec_state (
  key   TEXT PRIMARY KEY,
  value TEXT
);
"""


def _conn(db: str) -> sqlite3.Connection:
    d = os.path.dirname(db)
    if d:
        os.makedirs(d, exist_ok=True)
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


def _upsert(conn, services, snapshot_date, scope, ts):
    n = 0
    for s in services:
        sid = s.get("id")
        if not sid:
            continue
        conn.execute(
            """INSERT INTO clawsec_snapshots
                 (snapshot_date,id,masked_ip,port,service,their_version,country,province,cn_city,asn,
                  organization,runtime_status,is_china,authenticated,cred_leaked,has_mcp,
                  vuln_count,vuln_severity,first_seen,last_seen,pulled_at,raw,scope)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(snapshot_date,id) DO UPDATE SET
                 their_version=excluded.their_version, runtime_status=excluded.runtime_status,
                 last_seen=excluded.last_seen, vuln_count=excluded.vuln_count,
                 vuln_severity=excluded.vuln_severity, pulled_at=excluded.pulled_at,
                 raw=excluded.raw""",
            (snapshot_date, sid, s.get("maskedIp"), s.get("port"), s.get("service"),
             s.get("serverVersion"), s.get("country"), s.get("province"), s.get("cnCity"),
             s.get("asn"), s.get("organization"), s.get("runtimeStatus"),
             _b(s.get("isChinaInstance")), _b(s.get("authenticated")),
             _b(s.get("credentialsLeaked")), _b(s.get("hasMcp")),
             s.get("historicalVulnCount"), s.get("historicalVulnMaxSeverity"),
             s.get("firstSeen"), s.get("lastSeen"), ts,
             json.dumps(s, ensure_ascii=False), scope),
        )
        n += 1
    conn.commit()
    return n


# 每拉这么多页复查一次平台 lastScanTime，及时发现日期变更
RECHECK_EVERY = 20


def _mark_incomplete(conn, snapshot_date, done_pages, total_pages):
    """把某快照日标为 incomplete（拉到一半被日期变更打断）。"""
    inc = set(json.loads(_get_state(conn, "incomplete_snapshots", "[]")))
    inc.add(snapshot_date)
    _set_state(conn, "incomplete_snapshots", json.dumps(sorted(inc)))
    _set_state(conn, f"incomplete_detail:{snapshot_date}",
               f"{len(done_pages)}/{total_pages} pages（被日期变更中断）")


def pull(db, scope="all", active_only=False, snapshot_date=None,
         on_progress=None, on_snapshot_done=None, client=None):
    """拉取当日全量快照入库，自动处理"拉到一半平台更新日期"的情况。

    snapshot_date=None 时取平台 lastScanTime；拉取中每 RECHECK_EVERY 页复查一次，一旦平台
    日期变更（如 6-15→6-16）：停止当前快照、把它标 incomplete、改用新日期从头拉全量。
    scope 默认 all（含海外）、active_only 默认 False（含 Inactive）——作完整每日记录。
    断点续传：按 (snapshot_date, page) 记已完成页，中断重跑接着拉；该日全量已入库则幂等跳过。
    返回 (总新增入库数, 最终完整快照的总数, 最终 snapshot_date)。"""
    cli = client or ClawSecClient()
    target = snapshot_date
    total_added = 0
    # 外层循环：日期被打断就用新日期重来，直到拉完一个完整快照
    while True:
        added, n_total, sd, interrupted_to = _pull_one_snapshot(
            db, cli, scope, active_only, target, on_progress)
        total_added += added
        if on_snapshot_done:
            on_snapshot_done(sd, n_total, interrupted_to is not None)
        if interrupted_to is None:
            return total_added, n_total, sd
        target = interrupted_to  # 平台已更新到新日期，拉新的


def _pull_one_snapshot(db, cli, scope, active_only, snapshot_date, on_progress):
    """拉单个 snapshot_date 的全量。中途日期变更则返回 interrupted_to=新日期（已标 incomplete）。
    返回 (added, n_total, snapshot_date, interrupted_to)。"""
    conn = _conn(db)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if snapshot_date is None:
        snapshot_date = cli.last_scan_time() or datetime.date.today().isoformat()

    total, total_pages = cli.total_pages(scope, active_only)

    page_key = f"done_pages:{snapshot_date}:{scope}:{int(active_only)}"
    done = set(json.loads(_get_state(conn, page_key, "[]")))

    def count():
        return conn.execute(
            "SELECT COUNT(*) FROM clawsec_snapshots WHERE snapshot_date=?",
            (snapshot_date,)).fetchone()[0]

    # 幂等：该快照日全部页已完成则跳过
    if len(done) >= total_pages and total_pages > 0:
        n = count()
        conn.close()
        return 0, n, snapshot_date, None

    added = 0
    since_recheck = 0
    for page in range(1, total_pages + 1):
        if page in done:
            continue
        # 周期性复查平台日期，变了就停当前、标 incomplete、上交新日期
        if since_recheck >= RECHECK_EVERY:
            now_date = cli.last_scan_time()
            if now_date and now_date != snapshot_date:
                _mark_incomplete(conn, snapshot_date, done, total_pages)
                n = count()
                conn.close()
                return added, n, snapshot_date, now_date
            since_recheck = 0
        data = cli.page(page, scope, active_only)
        added += _upsert(conn, data["services"], snapshot_date, scope, ts)
        done.add(page)
        _set_state(conn, page_key, json.dumps(sorted(done)))
        since_recheck += 1
        if on_progress:
            on_progress(count(), total, page, total_pages)

    n = count()
    conn.close()
    return added, n, snapshot_date, None


def latest_snapshot(conn):
    """库内最新的 snapshot_date（无快照返回 None）。"""
    row = conn.execute("SELECT MAX(snapshot_date) FROM clawsec_snapshots").fetchone()
    return row[0] if row and row[0] else None


def snapshot_count(db, snapshot_date=None):
    """某快照日的实例数；snapshot_date=None 时取最新快照。"""
    conn = _conn(db)
    sd = snapshot_date or latest_snapshot(conn)
    n = conn.execute(
        "SELECT COUNT(*) FROM clawsec_snapshots WHERE snapshot_date=?", (sd,)).fetchone()[0] if sd else 0
    conn.close()
    return n, sd


def longlived(db, min_days=2, china_only=True):
    """跨快照分析长期有效实例：按 masked_ip 聚合出现的快照数、Active 快照数、首末见快照。

    长期有效（Active 快照数多）的实例更可能现在仍在线，枚举找真实 IP 的命中率高，优先探。
    incomplete 的快照参与统计但其缺席不计入"消失"（避免误判）。
    返回按 active_days 降序的列表，过滤 active_days >= min_days。"""
    conn = _conn(db)
    incomplete = set(json.loads(_get_state(conn, "incomplete_snapshots", "[]")))
    where = "WHERE is_china=1" if china_only else ""
    rows = conn.execute(
        f"""SELECT masked_ip,
                   COUNT(DISTINCT snapshot_date) AS seen_days,
                   COUNT(DISTINCT CASE WHEN runtime_status='Active' THEN snapshot_date END) AS active_days,
                   MIN(snapshot_date) AS first_snap,
                   MAX(snapshot_date) AS last_snap,
                   MAX(their_version) AS their_version
            FROM clawsec_snapshots {where}
            GROUP BY masked_ip
            HAVING active_days >= ?
            ORDER BY active_days DESC, masked_ip""",
        (min_days,),
    ).fetchall()
    conn.close()
    cols = ["masked_ip", "seen_days", "active_days", "first_snap", "last_snap", "their_version"]
    return [dict(zip(cols, r)) for r in rows], sorted(incomplete)


def overlap_with_fofa(db, fofa_db, snapshot_date=None):
    """clawsec 最新快照的隐位 IP × fofa_candidates 的隐位重叠统计（跨库 ATTACH）。

    隐位匹配：clawsec masked_ip 形如 a.b.*.d，匹配 fofa ip 的第1/2/4段相同。
    snapshot_date=None 时用最新快照。返回 (clawsec数, 能在fofa补全到≥1个完整IP的条数)。"""
    import os
    if not os.path.exists(fofa_db):
        return None
    conn = _conn(db)
    sd = snapshot_date or latest_snapshot(conn)
    if not sd:
        conn.close()
        return None
    # fofa 18789 端口 IP 的 (seg0,seg1,seg3) 集合
    conn.execute("ATTACH DATABASE ? AS fofa", (fofa_db,))
    fofa_keys = set()
    for (ip,) in conn.execute("SELECT ip FROM fofa.fofa_candidates WHERE port=18789"):
        p = ip.split(".")
        if len(p) == 4:
            fofa_keys.add((p[0], p[1], p[3]))
    total = hit = 0
    for (m,) in conn.execute(
            "SELECT DISTINCT masked_ip FROM clawsec_snapshots WHERE snapshot_date=?", (sd,)):
        total += 1
        p = m.split(".")
        if len(p) == 4 and p[2] == "*" and (p[0], p[1], p[3]) in fofa_keys:
            hit += 1
    conn.execute("DETACH DATABASE fofa")
    conn.close()
    return total, hit
