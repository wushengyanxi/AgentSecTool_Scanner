"""黑名单 / 保留网段过滤。全网扫描不应触碰保留与私有地址。"""

import ipaddress

# 默认排除的保留/特殊 IPv4 网段（RFC5735/6890 等）。
DEFAULT_RESERVED = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
]


class Blocklist:
    """判断 IP 是否落入需排除的网段（保留段 + 用户黑名单/opt-out）。"""

    def __init__(self, extra_cidrs=None, include_reserved=True):
        cidrs = []
        if include_reserved:
            cidrs += DEFAULT_RESERVED
        if extra_cidrs:
            cidrs += extra_cidrs
        self.nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]

    def is_blocked(self, ip) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True  # 非法 IP 一律排除
        return any(addr in net for net in self.nets)


def load_excludefile(path) -> list[str]:
    """从黑名单文件读 CIDR 列表（# 注释、空行忽略）。文件不存在则返回空。"""
    cidrs: list[str] = []
    try:
        with open(path) as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    cidrs.append(s)
    except FileNotFoundError:
        pass
    return cidrs
