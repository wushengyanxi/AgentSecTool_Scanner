#!/usr/bin/env python3
"""指纹库采集工具（M2）。

逐版本起一个 OpenClaw 容器（--allow-unconfigured，最小可指纹形态），用 ocprobe
记录其外部可观测签名（asset_hashes / csp_sha256 / favicon_md5），upsert 进
prober/fingerprints/openclaw.json。

仅用标准库，可直接 `python3 tools/fingerprint/build_corpus.py ...` 运行，无需 uv。

用法：
  # 用本机已构建的 openclaw:local（即 2026.5.17）记录一条
  python3 tools/fingerprint/build_corpus.py --image openclaw:local --version 2026.5.17

  # 拉取其它已发布镜像 tag 来扩充语料（验证跨版本可区分）
  python3 tools/fingerprint/build_corpus.py --image ghcr.io/openclaw/openclaw:2026.4.30 --version 2026.4.30
"""
import argparse
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentsectool_scanner.paths import OPENCLAW_FINGERPRINTS, PROBER_ROOT

DEFAULT_DB = str(OPENCLAW_FINGERPRINTS)
DEFAULT_OCPROBE = str(PROBER_ROOT / "bin" / "ocprobe")


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def wait_healthz(port, timeout=120):
    url = f"http://127.0.0.1:{port}/healthz"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(2)
    return False


def record_signature(image, version, port, ocprobe):
    name = f"oc-corpus-{version.replace('.', '-')}"
    sh(["docker", "rm", "-f", name])
    token = secrets.token_hex(32)
    run = sh([
        "docker", "run", "-d", "--name", name, "-p", f"{port}:18789",
        "-e", "HOME=/home/node", "-e", "OPENCLAW_HOME=/home/node",
        "-e", f"OPENCLAW_GATEWAY_TOKEN={token}",
        image, "node", "dist/index.js", "gateway",
        "--bind", "lan", "--port", "18789", "--allow-unconfigured",
    ])
    if run.returncode != 0:
        sys.exit(f"docker run failed: {run.stderr.strip()}")
    try:
        if not wait_healthz(port):
            logs = sh(["docker", "logs", "--tail", "20", name]).stdout
            sys.exit(f"gateway did not become healthy.\n{logs}")
        probe = sh([ocprobe, "--port", str(port), "--timeout", "8s"],
                   input=f"127.0.0.1,{port}\n")
        if probe.returncode != 0 or not probe.stdout.strip():
            sys.exit(f"ocprobe failed: {probe.stderr.strip()}")
        res = json.loads(probe.stdout.strip().splitlines()[0])
    finally:
        sh(["docker", "rm", "-f", name])

    if not res.get("is_openclaw"):
        sys.exit(f"probe did not confirm OpenClaw: {res}")
    ev = res.get("evidence", {})
    return {
        "version": version,
        "asset_hashes": ev.get("asset_hashes", []),
        "csp_sha256": ev.get("csp_sha256", ""),
        "favicon_md5": ev.get("favicon_md5", ""),
    }


def upsert(db_path, entry):
    db = {"entries": []}
    if os.path.exists(db_path):
        with open(db_path) as f:
            db = json.load(f)
    comment = db.get("_comment")
    entries = [e for e in db.get("entries", []) if e.get("version") != entry["version"]]
    entries.append(entry)
    entries.sort(key=lambda e: e.get("version", ""))
    out = {}
    if comment:
        out["_comment"] = comment
    out["entries"] = entries
    d = os.path.dirname(db_path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(db_path, "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
        f.write("\n")


def main():
    ap = argparse.ArgumentParser(description="OpenClaw 指纹库采集工具")
    ap.add_argument("--image", default="openclaw:local", help="OpenClaw 镜像")
    ap.add_argument("--version", required=True, help="版本标签，如 2026.5.17")
    ap.add_argument("--port", type=int, default=28789, help="宿主机临时端口（避开 18789）")
    ap.add_argument("--db", default=DEFAULT_DB, help="指纹库路径")
    ap.add_argument("--ocprobe", default=DEFAULT_OCPROBE, help="ocprobe 二进制路径")
    args = ap.parse_args()

    if not os.path.exists(args.ocprobe):
        sys.exit(f"ocprobe 不存在：{args.ocprobe}（先 `go -C prober build -o bin/ocprobe ./cmd/ocprobe`）")

    entry = record_signature(args.image, args.version, args.port, args.ocprobe)
    upsert(args.db, entry)
    print(f"recorded {entry['version']}: assets={entry['asset_hashes']} "
          f"csp_sha256={entry['csp_sha256'][:16]}… favicon_md5={entry['favicon_md5'][:8]}…")


if __name__ == "__main__":
    main()
