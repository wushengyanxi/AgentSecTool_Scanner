"""合并去重 + 黑名单过滤，产出 candidates.csv（ZGrab2/ocprobe 输入格式）。"""


def merge_candidates(*sources, blocklist=None) -> list[tuple[str, int]]:
    """对多路 (ip, port) 去重、剔除黑名单，保持首次出现顺序。"""
    seen: set[tuple[str, int]] = set()
    out: list[tuple[str, int]] = []
    for src in sources:
        for ip, port in src:
            if blocklist and blocklist.is_blocked(ip):
                continue
            key = (ip, int(port))
            if key in seen:
                continue
            seen.add(key)
            out.append(key)
    return out


def write_candidates(pairs, path) -> None:
    with open(path, "w") as f:
        for ip, port in pairs:
            f.write(f"{ip},{port}\n")
