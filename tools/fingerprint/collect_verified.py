#!/usr/bin/env python3
"""流式采集 + 运行时验证指纹库补全。

与 collect_corpus.py 的区别：每个版本不仅静态 docker cp 提取指纹，还 docker run
真跑起容器、用 ocprobe 真发请求，比对「静态提取的资产名」与「运行时请求到的资产名」，
一致才入库并标 verified=true。

并发模型（流式 pipeline，非批处理）：
  - 最多 PULL_CONC 个 docker pull 同时进行
  - 任一镜像 pull 完成立刻进处理队列（create 提取 → run 验证 → 入库），同时下一个 pull 启动
  - 处理（含 docker run + ocprobe）串行，避免多个容器抢同一宿主端口

用法：
  python3 tools/fingerprint/collect_verified.py --versions-file missing.txt
  python3 tools/fingerprint/collect_verified.py --only 2026.6.9 2026.6.8
"""
import argparse
import concurrent.futures as cf
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentsectool_scanner.paths import OPENCLAW_FINGERPRINTS, PROBER_ROOT

DEFAULT_REGISTRY = "ghcr.io/openclaw/openclaw"
DB_PATH = str(OPENCLAW_FINGERPRINTS)
ASSET_RE = re.compile(r"index-[A-Za-z0-9_.\-]+\.(?:js|css)")
PULL_CONC = 20                 # 并发 docker pull 数
PROC_CONC = 8                  # 并发处理数（每个含 docker run + 探测，占 CPU/内存，故低于 pull）
OCPROBE = str(PROBER_ROOT / "bin" / "ocprobe")
LOG_LOCK = threading.Lock()


def log(msg):
    with LOG_LOCK:
        print(msg, flush=True)


def sh(cmd, timeout=None):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


# ---- 静态提取（与 collect_corpus 同口径）----
def static_csp_sha256():
    # control-ui-config 端点的 CSP 静态常量串（script-src 'self'，与 HTML 无关）
    csp = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
           "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' ws: wss:; "
           "frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    return hashlib.sha256(csp.encode()).hexdigest()


def extract_from_dist(dist_dir):
    assets_dir = os.path.join(dist_dir, "assets")
    asset_hashes = []
    if os.path.isdir(assets_dir):
        asset_hashes = sorted(f for f in os.listdir(assets_dir) if ASSET_RE.fullmatch(f))
    favicon_md5 = ""
    fav = os.path.join(dist_dir, "favicon.ico")
    if os.path.isfile(fav):
        with open(fav, "rb") as f:
            favicon_md5 = hashlib.md5(f.read()).hexdigest()
    return asset_hashes, favicon_md5


def static_extract(ref, workdir):
    """docker create（不 run）→ cp dist/control-ui → 提取静态指纹。"""
    cid = sh(["docker", "create", ref]).stdout.strip()
    if not cid:
        return None
    try:
        dest = os.path.join(workdir, "dist")
        if os.path.exists(dest):
            sh(["rm", "-rf", dest])
        if sh(["docker", "cp", f"{cid}:/app/dist/control-ui", dest]).returncode != 0:
            return None
        asset_hashes, favicon_md5 = extract_from_dist(dest)
        return {"asset_hashes": asset_hashes, "favicon_md5": favicon_md5}
    finally:
        sh(["docker", "rm", "-f", cid])


# ---- 运行时验证：docker run + host 直扫容器 IP ----
# 2026.5.20+ 的版本容器内 gateway 监听 0.0.0.0，host 经容器 IP 可直接请求（无端口映射、
# 不拷任何东西进容器）。验证内容：真请求首页 HTML，看静态提取的资产名是否就是首页实际
# 引用的 js/css 文件名。每容器独立子网 IP → 处理可真正并发，互不抢端口。
INNER_PORT = 19111


def runtime_assets(ref):
    """docker run 跑起 gateway，host 直接请求容器 IP 的首页，返回 HTML 实际引用的资产名集合或 None。"""
    cid = sh(["docker", "run", "-d",
              "-e", "OPENCLAW_GATEWAY_TOKEN=probeverify",
              "--entrypoint", "node", ref,
              "openclaw.mjs", "gateway", "--port", str(INNER_PORT),
              "--allow-unconfigured"]).stdout.strip()
    if not cid:
        return None
    try:
        # 等 gateway ready（轮询日志，最多 ~25s）
        ready = False
        for _ in range(25):
            time.sleep(1)
            logs = sh(["docker", "logs", cid]).stdout + sh(["docker", "logs", cid]).stderr
            if "[gateway] ready" in logs or "listening on" in logs or "http server listening" in logs:
                ready = True
                break
            if sh(["docker", "ps", "-q", "--filter", f"id={cid}"]).stdout.strip() == "":
                break
        if not ready:
            return None
        ip = sh(["docker", "inspect", "-f",
                 "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cid]).stdout.strip()
        if not ip:
            return None
        time.sleep(1)
        # host 直接请求容器 IP 的首页，抓 HTML 里引用的 index-*.js|css 文件名
        out = sh([OCPROBE, "-port", str(INNER_PORT), "-fingerprints", DB_PATH,
                  "-o", f"/tmp/rt_{cid[:12]}.jsonl", ip], timeout=40).stdout
        try:
            with open(f"/tmp/rt_{cid[:12]}.jsonl") as f:
                rec = json.loads(f.readline())
            ev = rec.get("evidence", {})
            os.remove(f"/tmp/rt_{cid[:12]}.jsonl")
            return {
                "asset_hashes": sorted(ev.get("asset_hashes") or []),
                "is_openclaw": rec.get("is_openclaw"),
                "rule": rec.get("rule"),
                "version": rec.get("version"),
            }
        except (OSError, json.JSONDecodeError):
            return None
    finally:
        sh(["docker", "rm", "-f", cid])


# ---- 流水线 ----
def pull_one(version, registry):
    ref = f"{registry}:{version}"
    r = sh(["docker", "pull", ref])
    ok = r.returncode == 0
    if not ok and ("manifest unknown" in r.stderr or "not found" in r.stderr):
        return version, ref, "no-image"
    return version, ref, ("pulled" if ok else "pull-failed")


# 运行时验证的版本分界：2026.5.20 起容器内 gateway 监听 0.0.0.0、host 可直扫；
# 更早的版本只监听容器内回环、或免配置起不来，不跑容器验证（仅静态提取）。
def can_runtime_verify(version):
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    if not m:
        return False
    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    return (y, mo, d) >= (2026, 5, 20)


def process_one(version, ref, workdir):
    """对一个已拉取的镜像：静态提取（所有版本）+ 运行时验证（仅 2026.5.20+）+ 组装 entry。"""
    vdir = os.path.join(workdir, re.sub(r"[^\w.\-]", "_", version))  # 版本专属目录，并发安全
    os.makedirs(vdir, exist_ok=True)
    static = static_extract(ref, vdir)
    if not static or not static["asset_hashes"]:
        log(f"  [{version}] 静态提取失败（无 dist/control-ui 或无资产名）")
        sh(["docker", "rmi", "-f", ref])
        return None

    verified = False
    if not can_runtime_verify(version):
        note = "static-only（早期版，容器不可直扫）"
    else:
        rt = runtime_assets(ref)
        if rt is None:
            note = "runtime-start-failed（仅静态入库）"
        elif sorted(rt["asset_hashes"]) == sorted(static["asset_hashes"]):
            verified = True
            note = f"runtime-match rule={rt['rule']} ver={rt['version']}"
        else:
            note = f"MISMATCH static={static['asset_hashes']} runtime={rt['asset_hashes']}"

    sh(["docker", "rmi", "-f", ref])  # 处理完即删镜像省空间
    sh(["rm", "-rf", vdir])

    entry = {
        "version": version,
        "asset_hashes": static["asset_hashes"],
        "csp_sha256": static_csp_sha256(),
        "favicon_md5": static["favicon_md5"],
        "source": "image",
        "verified": verified,
    }
    icon = "✓" if verified else ("·" if "static-only" in note else "⚠")
    log(f"  [{version}] {icon} {note}")
    return entry


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--versions-file", help="每行一个版本号的文件")
    ap.add_argument("--only", nargs="*", help="直接指定版本号")
    ap.add_argument("--registry", default=DEFAULT_REGISTRY)
    ap.add_argument("--workdir", default="/tmp/oc_verify")
    args = ap.parse_args()

    versions = []
    if args.versions_file:
        with open(args.versions_file) as f:
            versions = [l.strip() for l in f if l.strip()]
    if args.only:
        versions += args.only
    if not versions:
        sys.exit("需 --versions-file 或 --only")

    os.makedirs(args.workdir, exist_ok=True)
    db = json.load(open(DB_PATH))
    by_ver = {e["version"]: e for e in db["entries"]}
    log(f"待采集 {len(versions)} 个版本；并发 pull={PULL_CONC}，并发处理={PROC_CONC}（含 docker run 验证）")

    # 两级并发流水线：pull 池产出已拉取镜像 → 提交给处理池并发处理（每版独立容器/IP/目录，
    # 互不抢端口）。一个镜像下完立刻排队处理、同时下一个 pull 继续，不等整批。
    stats = {"pulled": 0, "no-image": 0, "pull-failed": 0,
             "verified": 0, "added": 0, "mismatch": 0, "static-only": 0, "start-failed": 0}
    stats_lock = threading.Lock()
    db_lock = threading.Lock()
    total = len(versions)
    counter = {"done": 0}

    proc_pool = cf.ThreadPoolExecutor(max_workers=PROC_CONC)

    def handle_pulled(ver, ref):
        entry = process_one(ver, ref, args.workdir)
        with db_lock:
            counter["done"] += 1
            n = counter["done"]
            if entry:
                by_ver[ver] = entry
                with stats_lock:
                    stats["added"] += 1
                    if entry["verified"]:
                        stats["verified"] += 1
                db["entries"] = sorted(by_ver.values(), key=lambda e: e["version"])
                os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
                json.dump(db, open(DB_PATH, "w"), ensure_ascii=False, indent=2)  # 落盘，断点安全
            log(f"[{n}/{total}] {ver} 完成")

    proc_futures = []

    def pull_worker(v):
        ver, ref, status = pull_one(v, args.registry)
        if status != "pulled":
            with stats_lock:
                stats[status] = stats.get(status, 0) + 1
            with db_lock:
                counter["done"] += 1
                log(f"[{counter['done']}/{total}] {ver}: {status}")
            return
        with stats_lock:
            stats["pulled"] += 1
        # 拉完立刻提交处理池
        proc_futures.append(proc_pool.submit(handle_pulled, ver, ref))

    pull_pool = cf.ThreadPoolExecutor(max_workers=PULL_CONC)
    pull_futures = [pull_pool.submit(pull_worker, v) for v in versions]
    cf.wait(pull_futures)          # 所有 pull 完成（含已提交处理）
    cf.wait(proc_futures)          # 所有处理完成
    pull_pool.shutdown(wait=True)
    proc_pool.shutdown(wait=True)

    log(f"\n完成。{json.dumps(stats, ensure_ascii=False)}")
    log(f"指纹库现有 {len(by_ver)} 个版本。")


if __name__ == "__main__":
    main()
