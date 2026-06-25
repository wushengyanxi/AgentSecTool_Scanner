"""从扫描结果库 data/scanner/scan_results.sqlite 生成报告：测试项实际状态 → report_templates 话术 → 拼成分析段落。

格式由输出文件名后缀决定：.html（人读）/.json（机读，含完整请求响应）/.csv/.txt。
话术与判定解耦：is_openclaw/rule 是机判结果，本模块只负责把它解释成人话。
"""

import csv as _csv
import html as _html
import io
import json
import os
import re
import sqlite3

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11 兜底
    tomllib = None

# report_templates.toml 候选位置（prober/ 下，与 config.toml 平级）。
_TEMPLATE_CANDIDATES = [
    os.path.join(os.path.dirname(__file__), "..", "prober", "report_templates.toml"),
    "prober/report_templates.toml",
    "report_templates.toml",
]

# 找不到模板文件时的内置兜底话术（保证报告仍能出）。
_FALLBACK = {
    "T1": {"status_200_version": "control-ui 200 + serverVersion={version}（确证级）。",
           "status_200_noversion": "control-ui 200 但无 serverVersion。",
           "status_401": "control-ui 401（端点存在，已鉴权）。",
           "status_404": "control-ui 404。", "no_response": "control-ui 无响应。"},
    "T2": {"hit": "WS 命中 connect.challenge。", "miss": "WS 未命中。"},
    "T3": {"hit": "control-ui 401（路由存在）。", "miss": "control-ui 非 401。"},
    "T4": {"hit": "/healthz 命中特征体。", "miss": "/healthz 未命中。"},
    "T5": {"hit": "favicon 命中。", "miss": "favicon 未命中。"},
    "T6": {"openclaw": "title=OpenClaw Control。", "variant": "title={title}（变体）。", "none": "无 title。"},
    "T7": {"hit": "命中响应头三件套。", "miss": "未命中响应头三件套。"},
    "verdict": {"true_c1": "满足 C1 → True。", "true_c2": "满足 C2 → True。", "true_c3": "满足 C3 → True。",
                "false": "命中 {matched}，不满足白名单 → False。", "down": "探不到（{error_type}）→ False。"},
}


def load_templates():
    if tomllib is not None:
        for p in _TEMPLATE_CANDIDATES:
            if os.path.exists(p):
                with open(p, "rb") as f:
                    return tomllib.load(f)
    return _FALLBACK


def _t(tpl, section, key, default=""):
    return (tpl.get(section) or {}).get(key, _FALLBACK.get(section, {}).get(key, default))


def _status_of(resp):
    """从一条响应原文的状态行取 HTTP 状态码（'HTTP/1.1 200 …' → 200）；取不到返回 None。"""
    resp = resp or ""
    if resp.startswith("HTTP/1.1 "):
        try:
            return int(resp[9:12].strip())
        except ValueError:
            return None
    return None


def _probe_by_id(probes, test_id):
    for p in probes:
        if p["test_id"] == test_id:
            return p
    return None


def _control_ui_status(probes):
    """从 control-ui 探测记录的响应原文里取 HTTP 状态码。"""
    p = _probe_by_id(probes, "control-ui")
    return _status_of(p["response"]) if p else None


def _title_of(probes):
    """从 home 探针响应里取首页 <title> 文本（用于 T6 变体话术的 {title} 槽）。"""
    p = _probe_by_id(probes, "home")
    if not p:
        return ""
    m = re.search(r"<title>([^<]*)</title>", p["response"] or "", re.I)
    return m.group(1).strip() if m else ""


# 与探测器 prober/openclaw/http.go 的 assetRe 同口径：只取 index-*.js / index-*.css，
# 这些内容哈希文件名正是版本指纹反推的依据。
_ASSET_RE = re.compile(r"assets/(index-[A-Za-z0-9_.\-]+\.(?:js|css))")


def _assets_of(probes):
    """从 home 响应提取用于指纹反推的前端资产文件名（去重、保序）。"""
    p = _probe_by_id(probes, "home")
    if not p:
        return []
    seen, out = set(), []
    for a in _ASSET_RE.findall(p["response"] or ""):
        if a not in seen:
            seen.add(a)
            out.append(a)
    return out


def render_analysis(tpl, obs, probes):
    """对一个观测，按各测试项实际状态拼出分析段落 + 结论依据。"""
    matched = set(json.loads(obs["matched"] or "[]"))
    ev_status = _control_ui_status(probes)
    server_version = obs["version"] or ""
    # 从 probe_records 取 title（home 记录里没单独存，用 version_source/matched 推不出 title，
    # 故 title 文案在有 T6 变体时退化为通用提示；OpenClaw Control 命中 T6 时直接用 openclaw 话术）。
    has_t6 = "T6" in matched

    lines = []

    # T1/T3：由 control-ui 状态决定
    if "T1" in matched:
        lines.append(_t(tpl, "T1", "status_200_version").format(version=server_version or "?"))
    elif ev_status == 200:
        lines.append(_t(tpl, "T1", "status_200_noversion"))
    elif ev_status == 401:
        lines.append(_t(tpl, "T3", "hit"))
    elif ev_status == 404:
        lines.append(_t(tpl, "T1", "status_404"))
    elif ev_status is None:
        lines.append(_t(tpl, "T1", "no_response"))

    # T2
    lines.append(_t(tpl, "T2", "hit" if "T2" in matched else "miss"))
    # T4
    lines.append(_t(tpl, "T4", "hit" if "T4" in matched else "miss"))
    # T5
    lines.append(_t(tpl, "T5", "hit" if "T5" in matched else "miss"))
    # T6
    if has_t6:
        lines.append(_t(tpl, "T6", "openclaw"))
    # T7
    if "T7" in matched:
        lines.append(_t(tpl, "T7", "hit"))

    # 结论依据
    rule = obs["rule"]
    if obs["error_type"]:
        verdict_line = _t(tpl, "verdict", "down").format(error_type=obs["error_type"])
    elif rule == "C1":
        verdict_line = _t(tpl, "verdict", "true_c1")
    elif rule == "C2":
        verdict_line = _t(tpl, "verdict", "true_c2")
    elif rule == "C3":
        verdict_line = _t(tpl, "verdict", "true_c3")
    else:
        verdict_line = _t(tpl, "verdict", "false").format(matched="+".join(sorted(matched)) or "无")

    return " ".join(lines), verdict_line


def version_note(tpl, obs):
    """版本取证方式说明（放报告概况，不归属任何探针）。direct 直读 / implicit 资产指纹反推。"""
    ver = obs["version"] or ""
    src = obs["version_source"] or ""
    if not ver:
        return _t(tpl, "version", "none")
    if src == "direct":
        return _t(tpl, "version", "direct").format(version=ver)
    if src == "implicit":
        return _t(tpl, "version", "implicit").format(version=ver)
    if src == "implicit-range":
        return _t(tpl, "version", "implicit_range").format(version=ver, candidates="候选版本见下方列表")
    return ""


def analysis_by_probe(tpl, obs, probes):
    """生成每个探针的「观测」：返回 {探针test_id: {"desc":观测文本, "highlights":[特征词]}}。

    desc 只陈述该探针自身的观测事实，不提证据级别/C1/C2/C3/跨探针引用——达标逻辑由
    verdict_summary() 收口。highlights 是命中时该探针的「关键特征词」：这些子串同时出现在
    观测文案和该探针的请求/响应原文里，前端在三处统一染色，使读者一眼对应。
    占位符 {status}/{version}/{title} 由该探针真实响应提取后填入。
    """
    matched = set(json.loads(obs["matched"] or "[]"))
    ev_status = _control_ui_status(probes)
    server_version = obs["version"] or ""
    out = {}

    # control-ui 探针 → T1（200+serverVersion）/ T3（401）/ 其它，{status} 填真实状态码
    st = f"{ev_status}" if ev_status else "（无响应）"
    hl = []
    if "T1" in matched:
        d = _t(tpl, "T1", "status_200_version").format(status=st, version=server_version or "?")
        hl = ["serverVersion", server_version] if server_version else ["serverVersion"]
    elif ev_status == 401:
        d = _t(tpl, "T3", "hit").format(status=st)
        hl = ["401"]
    elif ev_status == 200:
        d = _t(tpl, "T1", "status_200_noversion").format(status=st)
    elif ev_status == 404:
        d = _t(tpl, "T1", "status_404").format(status=st)
    else:
        d = _t(tpl, "T1", "no_response")
    out["control-ui"] = {"desc": d, "highlights": hl}

    # home 探针 → T6（首页 title）+ T7（三个安全响应头）+ 指纹反推证据；T6 变体填 {title}
    hl = []
    if "T6" in matched:
        t6 = _t(tpl, "T6", "openclaw")
        hl.append("<title>OpenClaw Control</title>")
    else:
        title = _title_of(probes)
        t6 = _t(tpl, "T6", "variant").format(title=title) if title else _t(tpl, "T6", "miss")
    t7 = _t(tpl, "T7", "hit" if "T7" in matched else "miss")
    if "T7" in matched:
        hl += ["X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]

    # 指纹反推证据落地：列出本次反推用到的资产文件名（高亮，与响应原文对应）+ 反推结果
    src = obs["version_source"] or ""
    assets = _assets_of(probes)
    if assets and src in ("implicit", "implicit-range"):
        astr = "、".join(assets)
        key = "infer_range" if src == "implicit-range" else "infer"
        asset_clause = _t(tpl, "home_extra", key).format(assets=astr, version=server_version or "?")
        hl += assets
        if server_version:
            hl.append(server_version)
    elif assets and not src and "T6" in matched:
        # 提取到资产但未匹配指纹库（判真无版本时）
        asset_clause = _t(tpl, "home_extra", "infer_nomatch").format(assets="、".join(assets))
        hl += assets
    else:
        asset_clause = _t(tpl, "home_extra", "asset")

    home = " ".join(x for x in (t6, t7) if x)
    if home:
        home += " " + asset_clause
    out["home"] = {"desc": home.strip(), "highlights": hl}

    # T2
    if "T2" in matched:
        out["T2"] = {"desc": _t(tpl, "T2", "hit"),
                     "highlights": ["101 Switching Protocols", "connect.challenge"]}
    else:
        out["T2"] = {"desc": _t(tpl, "T2", "miss"), "highlights": []}

    # T4
    if "T4" in matched:
        p4 = _probe_by_id(probes, "T4")
        out["T4"] = {"desc": _t(tpl, "T4", "hit").format(status=_status_of(p4["response"]) if p4 else "200"),
                     "highlights": ['"status":"live"', '"ok":true']}
    else:
        out["T4"] = {"desc": _t(tpl, "T4", "miss"), "highlights": []}

    # T5（favicon 响应已折为二进制摘要，高亮 MD5 值）
    if "T5" in matched:
        p5 = _probe_by_id(probes, "T5")
        md5 = ""
        if p5:
            m = re.search(r"MD5=([0-9a-f]+)", p5["response"] or "")
            md5 = m.group(1) if m else ""
        out["T5"] = {"desc": _t(tpl, "T5", "hit"), "highlights": [md5] if md5 else []}
    else:
        out["T5"] = {"desc": _t(tpl, "T5", "miss"), "highlights": []}
    return out


# 每个测试项的研判标准与含义（前端横幅 T1..T7 / C1 / C2 / C3 悬停提示）。
TEST_MEANINGS = {
    "T1": "control-ui-config 端点返回 200 且自报 serverVersion。确证级：该响应由 OpenClaw 运行时实际实现并自报版本，为其独有，单条即可定论。",
    "T2": "WebSocket 升级后服务端首帧下发 connect.challenge 协议事件。强证据（WS 协议面）：此协议交互为 OpenClaw 运行时所特有。",
    "T3": "control-ui-config 端点返回 401，端点存在但已启用鉴权。强证据（HTTP 路由面）：该路由由 OpenClaw 运行时提供。",
    "T4": "GET /healthz 返回特征健康体（\"status\":\"live\" 与 \"ok\":true）。强证据（HTTP 路由面）：该健康体结构为 OpenClaw 运行时所特有。",
    "T5": "favicon.ico 的 MD5 命中 OpenClaw 品牌指纹。弱证据：favicon 属静态资源，非运行时独有，须与强证据合证以避免误判。",
    "T6": "首页 <title> 为「OpenClaw Control」。弱证据：标题属静态文本，非运行时独有，须与强证据合证以避免误判。",
    "T7": "响应同时带三项安全响应头。弱证据：安全响应头为通用配置、多类服务皆可呈现，非运行时独有，须与强证据合证以避免误判。",
    "C1": "白名单条件 C1：命中 T1 即判真——确证级特征为 OpenClaw 运行时独有，单条达标。",
    "C2": "白名单条件 C2：T2 且（T3 或 T4）——WebSocket 协议面叠加 HTTP 路由面，两类运行时独有特征跨表面互证。",
    "C3": "白名单条件 C3：T2 且首页资产指纹精确命中指纹库——WebSocket 协议面叠加 HTTP 静态构建产物面，跨表面互证。专为补救 control-ui 返 200 却无 serverVersion、又非 401、/healthz 未中的实例，这类真实例曾因仅靠 C1/C2 而被漏判。",
}


def verdict_summary(tpl, obs):
    """研判小结：收口达标逻辑（证据级别、C1/C2/C3、版本来源），每例讲一次。

    基于观测的全局结果（rule/matched/version_source/error_type）渲染，与单条探针无关。
    """
    rule = obs["rule"]
    matched = json.loads(obs["matched"] or "[]")
    if obs["error_type"]:
        return _t(tpl, "verdict_summary", "down").format(error_type=obs["error_type"])
    if rule == "C1":
        return _t(tpl, "verdict_summary", "c1")
    if rule == "C2":
        # 版本子句按来源拼接，嵌入 c2_t3 / c2_t4
        key = "c2_t3" if "T3" in matched else "c2_t4"
        return _t(tpl, "verdict_summary", key).format(version_clause=_version_clause(tpl, obs))
    if rule == "C3":
        # C3：T2（WS 协议面）× 资产指纹精确命中（HTTP 静态构建产物面）跨表面双强。
        # 版本同样由资产指纹反推带出，复用同一版本子句逻辑。
        return _t(tpl, "verdict_summary", "c3").format(version_clause=_version_clause(tpl, obs))
    # 判假
    return _t(tpl, "verdict_summary", "false").format(matched="、".join(matched) or "无")


def _version_clause(tpl, obs):
    """按版本来源拼出版本子句，供 C2 / C3 研判小结复用。"""
    ver = obs["version"] or ""
    src = obs["version_source"] or ""
    if not ver:
        return _t(tpl, "verdict_summary_version", "none")
    if src == "implicit-range":
        return _t(tpl, "verdict_summary_version", "implicit_range").format(version=ver)
    if src == "implicit":
        return _t(tpl, "verdict_summary_version", "implicit").format(version=ver)
    return _t(tpl, "verdict_summary_version", "direct")


def _fetch(db_path):
    """取每个观测 + 其 probe_records。返回 [(obs_row_dict, probes_list)]。"""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        obs_rows = conn.execute(
            "SELECT * FROM observations ORDER BY ip, port, ts"
        ).fetchall()
        out = []
        for o in obs_rows:
            probes = conn.execute(
                "SELECT test_id, request, response, hit FROM probe_records "
                "WHERE observation_id=? ORDER BY id", (o["id"],)
            ).fetchall()
            out.append((dict(o), [dict(p) for p in probes]))
        return out
    finally:
        conn.close()


def _verdict_word(o):
    return "True" if o["is_openclaw"] else "False"


def generate(db_path, out_path):
    """生成报告，格式由 out_path 后缀决定。"""
    tpl = load_templates()
    records = _fetch(db_path)
    ext = os.path.splitext(out_path)[1].lower()

    if ext == ".json":
        content = _gen_json(records)
    elif ext == ".csv":
        content = _gen_csv(records)
    elif ext == ".html":
        content = _gen_html(tpl, records)
    else:  # .txt 及未知后缀
        content = _gen_txt(tpl, records)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)
    return len(records)


def _gen_json(records):
    """机读，含完整请求/响应。"""
    out = []
    for o, probes in records:
        out.append({
            "target": f"{o['ip']}:{o['port']}",
            "verdict": bool(o["is_openclaw"]),
            "rule": o["rule"],
            "version": o["version"],
            "version_source": o["version_source"],
            "matched": json.loads(o["matched"] or "[]"),
            "error_type": o["error_type"],
            "ts": o["ts"],
            "probes": [{"test_id": p["test_id"], "request": p["request"],
                        "response": p["response"], "hit": bool(p["hit"])} for p in probes],
        })
    return json.dumps(out, ensure_ascii=False, indent=2)


def _gen_csv(records):
    buf = io.StringIO()
    w = _csv.writer(buf)
    w.writerow(["target", "verdict", "version", "matched", "rule", "error_type", "ts"])
    for o, _ in records:
        w.writerow([
            f"{o['ip']}:{o['port']}", _verdict_word(o), o["version"] or "",
            "|".join(json.loads(o["matched"] or "[]")),
            o["rule"] or "", o["error_type"] or "", o["ts"] or "",
        ])
    return buf.getvalue()


def _gen_txt(tpl, records):
    parts = ["OpenClaw 扫描报告\n" + "=" * 40 + "\n"]
    for o, probes in records:
        analysis, verdict_line = render_analysis(tpl, o, probes)
        parts.append(f"目标 {o['ip']}:{o['port']}　研判：{_verdict_word(o)}")
        if o["version"]:
            ver = o["version"]
            if o["version_source"] == "implicit-range":
                ver += "（区间，见候选）"
            parts.append(f"版本：{ver}  来源：{o['version_source'] or '-'}")
        parts.append(analysis)
        parts.append(verdict_line)
        parts.append("")
    return "\n".join(parts)


_HTML_HEAD = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0"><title>OpenClaw 扫描报告</title>
<style>
:root{--ivory:#FAF9F5;--slate:#141413;--clay:#D97757;--olive:#788C5D;--gray-300:#D1CFC5;--gray-500:#87867F;--white:#FFFFFF;}
body{margin:0;background:var(--ivory);color:#3D3D3A;font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;font-size:14.5px;line-height:1.75;}
.wrap{max-width:1000px;margin:0 auto;padding:48px 28px 100px;}
h1{font-family:Georgia,"Songti SC",serif;font-weight:500;font-size:30px;color:var(--slate);margin:0 0 8px;}
.sub{color:var(--gray-500);font-size:13px;margin:0 0 32px;}
.card{background:var(--white);border:1.5px solid var(--gray-300);border-radius:10px;padding:16px 20px;margin-bottom:16px;}
.card.t{border-left:4px solid var(--olive);}
.card.f{border-left:4px solid var(--clay);}
.tgt{font-family:ui-monospace,Menlo,monospace;font-size:13.5px;color:var(--slate);font-weight:600;}
.verdict{font-family:ui-monospace,Menlo,monospace;font-size:12px;padding:2px 8px;border-radius:5px;margin-left:8px;}
.verdict.t{background:#E4E9DC;color:#3F5128;}
.verdict.f{background:#F3D9CC;color:#8A3B1E;}
.ver{font-size:13px;color:var(--gray-500);margin:6px 0;}
.analysis{margin:8px 0;}
.basis{font-size:13px;color:var(--gray-500);border-top:1px dashed var(--gray-300);padding-top:8px;margin-top:8px;}
details{margin-top:8px;}
summary{font-size:12px;color:var(--clay);cursor:pointer;font-family:ui-monospace,monospace;}
pre.probe{background:var(--slate);color:#E8E6DF;border-radius:8px;padding:10px 12px;overflow-x:auto;font-family:ui-monospace,Menlo,monospace;font-size:11.5px;line-height:1.6;margin:6px 0;white-space:pre-wrap;word-break:break-all;}
</style></head><body><div class="wrap">
"""


def _gen_html(tpl, records):
    n_true = sum(1 for o, _ in records if o["is_openclaw"])
    out = [_HTML_HEAD]
    out.append("<h1>OpenClaw 扫描报告</h1>")
    out.append(f'<p class="sub">共 {len(records)} 个目标，其中研判为 OpenClaw（True）{n_true} 个。'
               f'结论由白名单 C1/C2/C3 机判，分析话术仅作解释。完整请求/响应可展开复查。</p>')
    for o, probes in records:
        analysis, verdict_line = render_analysis(tpl, o, probes)
        cls = "t" if o["is_openclaw"] else "f"
        vw = _verdict_word(o)
        out.append(f'<div class="card {cls}">')
        out.append(f'<span class="tgt">{_html.escape(o["ip"])}:{o["port"]}</span>'
                   f'<span class="verdict {cls}">{vw}</span>')
        if o["version"]:
            ver = _html.escape(o["version"])
            cand = ""
            if o["version_source"] == "implicit-range":
                cand = "（区间）"
            out.append(f'<div class="ver">版本 {ver}{cand} · 来源 {o["version_source"] or "-"}</div>')
        out.append(f'<div class="analysis">{_html.escape(analysis)}</div>')
        out.append(f'<div class="basis">{_html.escape(verdict_line)}</div>')
        if probes:
            out.append("<details><summary>完整请求 / 响应（入库原文）</summary>")
            for p in probes:
                hit = "HIT" if p["hit"] else "miss"
                req = _html.escape(p["request"] or "")
                resp = _html.escape(p["response"] or "")
                out.append(f'<pre class="probe">[{_html.escape(p["test_id"])}] {hit}\n'
                           f'--- 请求 ---\n{req}\n--- 响应 ---\n{resp}</pre>')
            out.append("</details>")
        out.append("</div>")
    out.append("</div></body></html>")
    return "\n".join(out)
