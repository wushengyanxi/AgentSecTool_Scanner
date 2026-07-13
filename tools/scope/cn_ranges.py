"""生成中国大陆 IPv4 CIDR 列表（"待扫描范围"的全集）。

来源：APNIC delegated 统计文件（权威、每日更新）。每行形如
  apnic|CN|ipv4|1.0.1.0|256|20110414|allocated
其中第 5 列是地址数（不一定是 2 的幂），用 summarize_address_range 转成最简 CIDR。

  python3 -m tools.scope.cn_ranges
分配会随时间变化，应定期重新生成。GeoIP 口径的"中国"可能与分配口径略有出入。
"""

import argparse
import ipaddress
import os
import sys
import urllib.request

from agentsectool_scanner.paths import SCOPE_CN_CIDRS

APNIC_URL = "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"


def fetch_cn_ranges(url: str = APNIC_URL) -> list[str]:
    """从 APNIC delegated 统计解析出 CN 的 IPv4 段，返回合并后的最简 CIDR 列表。"""
    nets: list[ipaddress.IPv4Network] = []
    with urllib.request.urlopen(url, timeout=120) as resp:
        for raw in resp:
            parts = raw.decode("utf-8", "replace").strip().split("|")
            if len(parts) < 5 or parts[1] != "CN" or parts[2] != "ipv4":
                continue
            try:
                first = int(ipaddress.IPv4Address(parts[3]))
                count = int(parts[4])
            except ValueError:
                continue
            last = ipaddress.IPv4Address(first + count - 1)
            nets.extend(ipaddress.summarize_address_range(ipaddress.IPv4Address(first), last))
    return [str(n) for n in ipaddress.collapse_addresses(nets)]


def main(argv=None) -> None:
    ap = argparse.ArgumentParser("scope.cn_ranges")
    ap.add_argument("--out", default=str(SCOPE_CN_CIDRS))
    ap.add_argument("--url", default=APNIC_URL)
    args = ap.parse_args(argv)

    cidrs = fetch_cn_ranges(args.url)
    total = sum(ipaddress.ip_network(c).num_addresses for c in cidrs)
    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w") as f:
        f.write("\n".join(cidrs) + "\n")
    print(f"CN IPv4: {len(cidrs)} 个 CIDR，约 {total:,} 个地址 → {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
