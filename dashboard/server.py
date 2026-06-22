#!/usr/bin/env python3
"""OpenClaw 实例收集看板的本地后端：实时查 scanner 库，给前端提供 JSON API。

纯标准库（http.server + sqlite3），零依赖。前端是同目录的 index.html（单页）。
只读查询 data/scanner/scan_results.sqlite，不修改任何数据。

用法（项目根目录跑）：
  python3 -m dashboard            # 默认 :8787，库 data/scanner/scan_results.sqlite
  python3 -m dashboard --port 9000 --db data/scanner/scan_results.sqlite
然后浏览器开 http://127.0.0.1:8787/
"""
import argparse
import hashlib
import json
import os
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# 复用 store 里现成的报告话术渲染（模板 prober/report_templates.toml）。
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from store.report import (load_templates, analysis_by_probe, verdict_summary,
                         version_note, TEST_MEANINGS)

# 探针 test_id → 测试项名称（前端展开列表显示名称而非 T2/home 这种 id）
PROBE_NAMES = {
    "T2": "WebSocket 协议挑战探测",
    "T4": "健康端点特征校验",
    "T5": "站点图标指纹校验",
    "home": "首页标题校验 · 安全响应头校验",
    "control-ui": "版本端点直读探测",
}

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = "data/scanner/scan_results.sqlite"
_TPL = load_templates()  # 报告话术模板，进程启动时加载一次

# 可信级别的展示口径
CATEGORY_LABELS = {
    "confirmed": "确认 OpenClaw（含版本）",
    "confirmed_no_version": "确认 OpenClaw（版本待定）",
    "suspect": "疑似（部分特征，待复核）",
}


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def api_overview():
    """顶部数字卡 + 分桶 + 版本/来源分布。"""
    conn = _conn()
    try:
        def one(sql, args=()):
            r = conn.execute(sql, args).fetchone()
            return r[0] if r else 0

        cats = {c: one("SELECT COUNT(*) FROM assets WHERE category=?", (c,))
                for c in CATEGORY_LABELS}
        versions = [{"version": r["v"] or "(未取到)", "count": r["n"]} for r in conn.execute(
            "SELECT latest_version v, COUNT(*) n FROM assets "
            "WHERE category IN ('confirmed','confirmed_no_version') "
            "GROUP BY v ORDER BY n DESC")]
        sources = [{"source": r["s"] or "(无)", "count": r["n"]} for r in conn.execute(
            "SELECT version_source s, COUNT(*) n FROM assets "
            "WHERE category IN ('confirmed','confirmed_no_version') GROUP BY s ORDER BY n DESC")]
        return {
            "assets_total": one("SELECT COUNT(*) FROM assets"),
            "openclaw_total": cats["confirmed"] + cats["confirmed_no_version"],
            "categories": [
                {"key": k, "label": v, "count": cats[k]} for k, v in CATEGORY_LABELS.items()
            ],
            "versions": versions,
            "version_sources": sources,
            "observations": one("SELECT COUNT(*) FROM observations"),
            "probe_records": one("SELECT COUNT(*) FROM probe_records"),
        }
    finally:
        conn.close()


def api_assets(category=None, q=None, limit=200, offset=0):
    """资产列表（分页、可按 category 过滤、可按 IP/版本搜）。"""
    conn = _conn()
    try:
        where, args = [], []
        if category and category in CATEGORY_LABELS:
            where.append("category=?"); args.append(category)
        if q:
            where.append("(ip LIKE ? OR latest_version LIKE ?)")
            args += [f"%{q}%", f"%{q}%"]
        wc = ("WHERE " + " AND ".join(where)) if where else ""
        total = conn.execute(f"SELECT COUNT(*) FROM assets {wc}", args).fetchone()[0]
        rows = conn.execute(
            f"""SELECT ip, port, category, latest_version, version_source, last_seen,
                       region, city
                FROM assets {wc}
                ORDER BY (category='confirmed') DESC, last_seen DESC
                LIMIT ? OFFSET ?""",
            (*args, int(limit), int(offset)),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            # 物理位置（GeoLite2 入库时富化）：优先城市，回退省，再回退占位
            d["province"] = d.get("city") or d.get("region") or "—"
            # 披露日期：以日期为单位（取 last_seen 的日期段），弃用 first_seen/observations
            d["disclosed"] = (d.pop("last_seen") or "")[:10]
            out.append(d)
        return {"total": total, "rows": out}
    finally:
        conn.close()


def api_geo(limit=20):
    """地理分布：按城市聚合实例数（明确 OpenClaw 优先口径）。城市缺失则归到省级。"""
    conn = _conn()
    try:
        rows = conn.execute(
            """SELECT COALESCE(city, region, '(未知)') AS place,
                      COUNT(*) AS n,
                      SUM(CASE WHEN category IN ('confirmed','confirmed_no_version')
                               THEN 1 ELSE 0 END) AS openclaw
               FROM assets
               GROUP BY place ORDER BY n DESC LIMIT ?""",
            (int(limit),),
        ).fetchall()
        located = conn.execute(
            "SELECT COUNT(*) FROM assets WHERE city IS NOT NULL OR region IS NOT NULL"
        ).fetchone()[0]
        total = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        return {
            "cities": [{"place": r["place"], "count": r["n"], "openclaw": r["openclaw"]}
                       for r in rows],
            "located": located, "total": total,
        }
    finally:
        conn.close()


def _nonprintable_ratio(s):
    if not s:
        return 0.0
    bad = sum(1 for ch in s if ord(ch) < 32 and ch not in "\t\n\r")
    bad += sum(1 for ch in s if 127 <= ord(ch) < 160)
    return bad / len(s)


def _safe_text(s, limit=8000):
    """请求/响应文本清洗：纯文本正常返回（截断超长）；含二进制体（如 favicon 图标）的，
    把 HTTP 头保留为文本、二进制体折成 [二进制 N 字节, MD5=…] 摘要，避免满屏乱码。"""
    if not s:
        return ""
    # 拆 HTTP 头与体（首个空行分隔）。头几乎总是文本，体可能是二进制。
    sep = "\r\n\r\n" if "\r\n\r\n" in s else ("\n\n" if "\n\n" in s else None)
    head, body = (s.split(sep, 1) if sep else (s, ""))
    if body and _nonprintable_ratio(body) > 0.30:
        raw = body.encode("utf-8", "surrogatepass") if any(ord(c) > 0xFFFF for c in body) \
            else body.encode("latin-1", "replace")
        digest = hashlib.md5(raw).hexdigest()
        return f"{head}\r\n\r\n[二进制内容，{len(body)} 字节，MD5={digest}]"
    # 文本：仅把零星控制字节转占位，整体可读
    text = "".join(ch if (ch in "\t\n\r" or ord(ch) >= 32) else "·" for ch in s[:limit])
    if len(s) > limit:
        text += f"\n…（已截断，完整 {len(s)} 字符）"
    return text


def api_report(ip=None, port=None):
    """单台主机的探测报告：最近一次观测的概况 + 该次全部 probe（命中/未命中都列）。"""
    if not ip:
        return {"error": "缺少 ip 参数"}
    conn = _conn()
    try:
        q = "SELECT * FROM observations WHERE ip=?"
        args = [ip]
        if port:
            q += " AND port=?"; args.append(int(port))
        q += " ORDER BY ts DESC LIMIT 1"  # 最近一次观测
        obs = conn.execute(q, args).fetchone()
        if not obs:
            return {"error": "无观测记录"}
        obs = dict(obs)
        raw_probes = [dict(p) for p in conn.execute(
            "SELECT test_id, request, response, hit FROM probe_records "
            "WHERE observation_id=? ORDER BY hit DESC, test_id", (obs["id"],))]

        # 用原始数据算「每个探针的观测」与「研判小结」（状态判定要读未清洗的 response 取状态码）
        desc = analysis_by_probe(_TPL, obs, raw_probes)
        summary = verdict_summary(_TPL, obs)
        ver_note = version_note(_TPL, obs)

        try:
            matched = json.loads(obs.get("matched") or "[]")
        except (ValueError, TypeError):
            matched = []
        probes = []
        for p in raw_probes:
            a = desc.get(p["test_id"]) or {}
            probes.append({
                "test_id": p["test_id"],
                "name": PROBE_NAMES.get(p["test_id"], p["test_id"]),  # 测试项名称
                "hit": bool(p["hit"]),
                "desc": a.get("desc", ""),                  # 观测文本
                "highlights": a.get("highlights", []),      # 三处统一染色的特征词
                "request": _safe_text(p["request"]),
                "response": _safe_text(p["response"]),
            })
        return {
            "ip": obs["ip"], "port": obs["port"], "ts": obs["ts"],
            "category": obs["category"], "rule": obs["rule"],
            "version": obs["version"], "version_source": obs["version_source"],
            "matched": matched, "error_type": obs["error_type"],
            "tls": bool(obs["tls"]), "summary": summary,
            "version_note": ver_note, "probes": probes,
            "test_meanings": TEST_MEANINGS,   # T1..T7 / C1 / C2 悬停含义
        }
    finally:
        conn.close()


class Handler(BaseHTTPRequestHandler):
    def _send(self, obj, code=200, ctype="application/json"):
        body = obj if isinstance(obj, bytes) else json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        try:
            if u.path == "/" or u.path == "/index.html":
                with open(os.path.join(HERE, "index.html"), "rb") as f:
                    self._send(f.read(), ctype="text/html")
            elif u.path.startswith("/assets/"):
                # 只 serve dashboard/assets 下的静态文件（logo 等），防目录穿越
                name = os.path.basename(u.path)
                fp = os.path.join(HERE, "assets", name)
                if os.path.isfile(fp):
                    ctype = ("image/png" if name.endswith(".png")
                             else "image/svg+xml" if name.endswith(".svg")
                             else "font/ttf" if name.endswith(".ttf")
                             else "application/octet-stream")
                    with open(fp, "rb") as f:
                        self._send(f.read(), ctype=ctype)
                else:
                    self._send({"error": "not found"}, 404)
            elif u.path == "/api/overview":
                self._send(api_overview())
            elif u.path == "/api/geo":
                self._send(api_geo(limit=qs.get("limit", ["20"])[0]))
            elif u.path == "/api/assets":
                self._send(api_assets(
                    category=qs.get("category", [None])[0],
                    q=qs.get("q", [None])[0],
                    limit=qs.get("limit", ["200"])[0],
                    offset=qs.get("offset", ["0"])[0]))
            elif u.path == "/api/report":
                self._send(api_report(
                    ip=qs.get("ip", [None])[0],
                    port=qs.get("port", [None])[0]))
            else:
                self._send({"error": "not found"}, 404)
        except FileNotFoundError:
            self._send({"error": f"找不到数据库 {DB_PATH}，先运行 store 入库"}, 500)
        except Exception as e:  # noqa: BLE001
            self._send({"error": str(e)}, 500)

    def log_message(self, *a):
        pass  # 静默


def main():
    global DB_PATH
    ap = argparse.ArgumentParser("dashboard")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--db", default=DB_PATH)
    args = ap.parse_args()
    DB_PATH = args.db
    if not os.path.exists(DB_PATH):
        print(f"警告：数据库 {DB_PATH} 不存在，先运行 store 入库再开看板")
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"OpenClaw 实例看板：http://127.0.0.1:{args.port}/  （库 {DB_PATH}）")
    print("Ctrl-C 停止")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
