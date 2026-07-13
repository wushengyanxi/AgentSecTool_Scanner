"""被动种子。FOFA 先行；接口留给 Censys/Shodan/Quake 扩展。

凭据从环境变量取（FOFA_EMAIL / FOFA_KEY），不硬编码（CLAUDE.md §6）。
查询直接复用 OpenClaw 指纹，如 title="OpenClaw Control" || port="18789"。
"""

import base64
import json
import urllib.parse
import urllib.request


def fofa_results_to_pairs(data) -> list[tuple[str, int]]:
    """把 FOFA 响应（fields=ip,port）解析为 (ip, port) 列表。纯函数，便于测试。"""
    pairs: list[tuple[str, int]] = []
    for row in data.get("results") or []:
        try:
            pairs.append((row[0], int(row[1])))
        except (IndexError, ValueError, TypeError):
            continue
    return pairs


def fofa_search(email, key, query, max_results=10000, page_size=1000, base="https://fofa.info"):
    """查询 FOFA，分页取 (ip, port)。缺凭据则返回空。"""
    if not email or not key:
        return []
    qb64 = base64.b64encode(query.encode()).decode()
    found: list[tuple[str, int]] = []
    page = 1
    while len(found) < max_results:
        size = min(page_size, max_results - len(found))
        params = urllib.parse.urlencode({
            "email": email, "key": key, "qbase64": qb64,
            "fields": "ip,port", "page": page, "size": size,
        })
        url = f"{base}/api/v1/search/all?{params}"
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                data = json.load(resp)
        except Exception as e:  # noqa: BLE001 — 网络/解析错误统一上抛
            raise RuntimeError(f"FOFA 查询失败: {e}") from e
        if data.get("error"):
            raise RuntimeError(f"FOFA 返回错误: {data.get('errmsg')}")
        results = data.get("results") or []
        if not results:
            break
        found.extend(fofa_results_to_pairs(data))
        if len(results) < size:
            break
        page += 1
    return found[:max_results]


def shodan_results_to_pairs(data) -> list[tuple[str, int]]:
    """把 Shodan host/search 响应解析为 (ip, port) 列表。纯函数，便于测试。"""
    pairs: list[tuple[str, int]] = []
    for m in data.get("matches") or []:
        ip = m.get("ip_str")
        port = m.get("port")
        if not ip or port is None:
            continue
        try:
            pairs.append((ip, int(port)))
        except (ValueError, TypeError):
            continue
    return pairs


def shodan_search(api_key, query, max_results=10000, base="https://api.shodan.io"):
    """查询 Shodan，分页取 (ip, port)。缺 key 则返回空。"""
    if not api_key:
        return []
    found: list[tuple[str, int]] = []
    page = 1
    while len(found) < max_results:
        params = urllib.parse.urlencode({"key": api_key, "query": query, "page": page})
        url = f"{base}/shodan/host/search?{params}"
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                data = json.load(resp)
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"Shodan 查询失败: {e}") from e
        matches = data.get("matches") or []
        if not matches:
            break
        found.extend(shodan_results_to_pairs(data))
        if len(matches) < 100:  # Shodan 每页 100 条
            break
        page += 1
    return found[:max_results]
