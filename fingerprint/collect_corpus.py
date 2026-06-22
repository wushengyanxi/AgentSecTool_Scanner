#!/usr/bin/env python3
"""全量指纹采集工具：遍历 OpenClaw 正式版 tag，逐版本采集外部可观测签名。

采集三字段（与 prober 的 FingerprintEntry 对齐）：
  asset_hashes  首页引用的内容哈希资产名（assets/index-<hash>.js|css），主要的版本区分信号
  csp_sha256    control-ui-config 端点那串 CSP 的 sha256（该端点的 CSP 不含内联脚本哈希，
                见 src/gateway/control-ui.ts:180 的 buildControlUiCspHeader() 无参调用，
                故几乎跨版本不变，区分力弱——如实记录，不当作主区分信号）
  favicon_md5   dist/control-ui/favicon.ico 的 md5（跨版本稳定，仅判定用）

两条提取路径，全程不起服务：
  主路径 image：docker pull <registry>:<ver> → docker create（不 run）→ docker cp dist/control-ui
                → 读资产名 / 算 favicon md5 / 对静态 CSP 串算 sha256。取的是官方分发产物本身，逐字节可靠。
  辅路径 build：镜像拉不到时，git -C <repo> checkout <tag> → cd ui && npm ci && vite build
                → 从构建产物提取。注意：资产名 hash 掺入了 buildId（含 git sha，见 ui/vite.config.ts），
                本机构建未必等同官方分发，故该来源的条目 source 记为 "local-build"，需独立核验。

CSP 串为源码静态常量（src/gateway/control-ui-csp.ts 的 buildControlUiCspHeader 无参分支）。
若某版本改了该函数，本脚本算出的 csp_sha256 会与运行时不符——属已知边界，输出里标注 csp_source。

仅用标准库，可直接 `python3 fingerprint/collect_corpus.py ...` 运行。

用法：
  # 全量（默认遍历 repo 里所有正式 vYYYY.M.D tag）
  python3 fingerprint/collect_corpus.py --repo /path/to/openclaw

  # 只采指定几个版本
  python3 fingerprint/collect_corpus.py --repo /path/to/openclaw --only 2026.1.8,2026.5.12

  # 断点续跑：已在 fingerprints.json 里的版本默认跳过；--force 重采
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(HERE, "..", "fingerprints", "fingerprints.json")
DEFAULT_REGISTRY = "ghcr.io/openclaw/openclaw"
REPORT_PATH = os.path.join(HERE, "collect_corpus_report.json")

# control-ui-config 端点的 CSP（src/gateway/control-ui-csp.ts，buildControlUiCspHeader() 无参分支）。
# script-src 恒为 'self'，整串与 HTML 内容无关。脚本对该常量算 sha256 作为 csp_sha256 的默认来源。
STATIC_CSP_DIRECTIVES = [
    "default-src 'self'",
    "base-uri 'none'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "img-src 'self' data: blob:",
    "media-src 'self' data: blob:",
    "font-src 'self' https://fonts.gstatic.com",
    "worker-src 'self'",
    "connect-src 'self' ws: wss: https://api.openai.com https://tweakcn.com",
]
ASSET_RE = re.compile(r"index-[A-Za-z0-9_.\-]+\.(?:js|css)")


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def static_csp_sha256():
    return hashlib.sha256("; ".join(STATIC_CSP_DIRECTIVES).encode()).hexdigest()


def list_release_tags(repo):
    """repo 里所有正式发布 tag，按版本升序，返回不带 v 的版本号。

    覆盖两种正式格式（排除 beta/rc/alpha 等预发布）：
      - 纯 CalVer：     vYYYY.M.D       （如 v2026.3.12）
      - hotfix 后缀：   vYYYY.M.D-N     （如 v2026.3.13-1，同日补丁版；旧正则曾漏掉这类）
    """
    out = sh(["git", "-C", repo, "tag"])
    if out.returncode != 0:
        sys.exit(f"git tag 失败：{out.stderr.strip()}")
    tags = [t for t in out.stdout.split() if re.fullmatch(r"v2026\.\d+\.\d+(?:-\d+)?", t)]

    def sortkey(t):
        m, _, suffix = t[1:].partition("-")  # "2026.3.13", "1"
        parts = [int(x) for x in m.split(".")]
        return parts + [int(suffix) if suffix else 0]

    tags.sort(key=sortkey)
    return [t[1:] for t in tags]


def extract_from_dist(dist_dir):
    """从一个 dist/control-ui 目录提取三字段。favicon/csp 缺失时返回空串，由调用方判处理。"""
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


def try_image(version, registry, workdir):
    """主路径：拉镜像 → create（不 run）→ cp dist/control-ui → 提取。成功返回 entry，失败返回 None。"""
    ref = f"{registry}:{version}"
    if sh(["docker", "manifest", "inspect", ref]).returncode != 0:
        return None  # 镜像不存在/不可达
    if sh(["docker", "pull", ref]).returncode != 0:
        return None
    cid = sh(["docker", "create", ref]).stdout.strip()
    if not cid:
        return None
    try:
        dest = os.path.join(workdir, f"dist-{version}")
        if sh(["docker", "cp", f"{cid}:/app/dist/control-ui", dest]).returncode != 0:
            return None
        asset_hashes, favicon_md5 = extract_from_dist(dest)
        if not asset_hashes:
            return None  # 没拿到资产名，视为提取失败，留给辅路径
        return {
            "version": version,
            "asset_hashes": asset_hashes,
            "csp_sha256": static_csp_sha256(),
            "favicon_md5": favicon_md5,
            "source": "image",
            "csp_source": "static-const",
        }
    finally:
        sh(["docker", "rm", "-f", cid])


# 容器内构建用的镜像与 pnpm 版本（与项目 packageManager 字段一致）。
# OpenClaw 是 pnpm monorepo（packageManager: pnpm@10.23.0），必须用 pnpm；用 npm 会在老版本失败。
BUILD_IMAGE = "node:22"
PNPM_VERSION = "10.23.0"
_CONTAINER_BUILD = r"""
set -e
cp -a /src/. /work/
corepack enable
corepack prepare pnpm@{pnpm} --activate
pnpm install --frozen-lockfile >/dev/null 2>&1 || pnpm install >/dev/null 2>&1
pnpm ui:build >/dev/null 2>&1 || node scripts/ui.js build >/dev/null 2>&1
cp -a dist/control-ui/. /out/
"""


def try_build(version, repo, workdir):
    """辅路径：在一次性 node 容器里用 pnpm 构建（host 零污染），cp 出产物后提取。

    源码 checkout 到对应 tag 后只读挂入容器，产物挂出。本机构建未必逐字节等同官方分发
    （buildId 含 git sha，见 ui/vite.config.ts），故 source 记为 local-build，需独立核验。"""
    if sh(["git", "-C", repo, "checkout", "-q", f"v{version}"]).returncode != 0:
        return None
    out = os.path.join(workdir, f"build-{version}")
    os.makedirs(out, exist_ok=True)
    script = _CONTAINER_BUILD.format(pnpm=PNPM_VERSION)
    r = sh([
        "docker", "run", "--rm",
        "-v", f"{repo}:/src:ro", "-v", f"{out}:/out", "-w", "/work",
        BUILD_IMAGE, "bash", "-c", script,
    ])
    if r.returncode != 0:
        return None
    asset_hashes, favicon_md5 = extract_from_dist(out)  # 产物直接在 out 根（cp 的是 control-ui/. 内容）
    if not asset_hashes:
        return None
    return {
        "version": version,
        "asset_hashes": asset_hashes,
        "csp_sha256": static_csp_sha256(),
        "favicon_md5": favicon_md5,
        "source": "local-build",
        "csp_source": "static-const",
    }


def load_db(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {"entries": []}


def save_db(path, db):
    db["entries"].sort(key=lambda e: [int(x) for x in re.findall(r"\d+", e.get("version", "0"))] or [0])
    with open(path, "w") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)
        f.write("\n")


def main():
    ap = argparse.ArgumentParser(description="OpenClaw 全量指纹采集（静态提取为主，本机构建为辅）")
    ap.add_argument("--repo", required=True, help="本地 openclaw git 仓库路径")
    ap.add_argument("--registry", default=DEFAULT_REGISTRY, help="镜像 registry/repo")
    ap.add_argument("--db", default=DEFAULT_DB, help="指纹库输出路径")
    ap.add_argument("--only", default=None, help="逗号分隔的版本号，只采这些（默认全部正式版）")
    ap.add_argument("--no-build", action="store_true", help="禁用本机构建辅路径（只走镜像）")
    ap.add_argument("--force", action="store_true", help="已采过的版本也重采")
    ap.add_argument("--workdir", default="/tmp/oc_corpus", help="临时提取目录")
    args = ap.parse_args()

    repo = os.path.abspath(args.repo)
    if not os.path.isdir(os.path.join(repo, ".git")):
        sys.exit(f"不是 git 仓库：{repo}")
    os.makedirs(args.workdir, exist_ok=True)

    if args.only:
        versions = [v.strip().lstrip("v") for v in args.only.split(",") if v.strip()]
    else:
        versions = list_release_tags(repo)
    print(f"目标版本数：{len(versions)}")

    db = load_db(args.db)
    have = {e["version"] for e in db["entries"]}
    report = {"image": [], "local_build": [], "failed": [], "skipped": []}

    for i, ver in enumerate(versions, 1):
        if ver in have and not args.force:
            report["skipped"].append(ver)
            print(f"[{i}/{len(versions)}] {ver}  跳过（已在库）")
            continue
        print(f"[{i}/{len(versions)}] {ver}  采集中…", flush=True)
        entry = try_image(ver, args.registry, args.workdir)
        if entry is None and not args.no_build:
            print(f"            镜像不可用，回退本机构建…", flush=True)
            entry = try_build(ver, repo, args.workdir)
        if entry is None:
            report["failed"].append(ver)
            print(f"            ✗ 失败（镜像与构建均未取到）")
            continue
        db["entries"] = [e for e in db["entries"] if e["version"] != ver] + [entry]
        save_db(args.db, db)  # 每版即时落盘，支持断点续跑
        bucket = "image" if entry["source"] == "image" else "local_build"
        report[bucket].append(ver)
        print(f"            ✓ {entry['source']}  assets={entry['asset_hashes']}")

    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print("\n=== 采集汇总 ===")
    print(f"  镜像静态提取：{len(report['image'])}")
    print(f"  本机构建回退：{len(report['local_build'])}  {report['local_build'] or ''}")
    print(f"  跳过（已在库）：{len(report['skipped'])}")
    print(f"  失败：{len(report['failed'])}  {report['failed'] or ''}")
    print(f"  报告：{REPORT_PATH}")
    print(f"  指纹库：{args.db}（共 {len(db['entries'])} 版）")


if __name__ == "__main__":
    main()
