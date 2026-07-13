"""主动发现：masscan / ZMap（全网级，需 root）+ 内置 async connect 扫描（无 root 兜底）。

三种后端都接受任意 CIDR；masscan/ZMap 用于真正的全网/大范围（在专用 Linux
扫描主机上以 sudo 运行），internal 仅供开发与小网段（有地址数上限）。
"""

import asyncio
import ipaddress
import os
import subprocess
import tempfile

# internal 后端地址数上限：更大的范围请用 masscan/ZMap。
INTERNAL_MAX_ADDRS = 1 << 16


def _expand(cidrs):
    for c in cidrs:
        net = ipaddress.ip_network(c, strict=False)
        it = net.hosts() if net.num_addresses > 2 else iter(net)
        for host in it:
            yield str(host)


def scan_internal(cidrs, ports, concurrency=512, timeout=2.0):
    """内置 async TCP connect 扫描，无需 root。仅用于小范围。"""
    total = sum(ipaddress.ip_network(c, strict=False).num_addresses for c in cidrs) * len(ports)
    if total > INTERNAL_MAX_ADDRS:
        raise ValueError(
            f"internal 后端目标数 {total} 超上限 {INTERNAL_MAX_ADDRS}；"
            f"全网/大范围请用 --backend masscan 或 zmap"
        )
    addrs = list(_expand(cidrs))
    return asyncio.run(_scan_internal_async(addrs, ports, concurrency, timeout))


async def _scan_internal_async(addrs, ports, concurrency, timeout):
    sem = asyncio.Semaphore(concurrency)
    found: list[tuple[str, int]] = []

    async def probe(ip, port):
        async with sem:
            try:
                conn = asyncio.open_connection(ip, port)
                _, writer = await asyncio.wait_for(conn, timeout=timeout)
            except (OSError, asyncio.TimeoutError):
                return
            found.append((ip, port))
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, asyncio.TimeoutError):
                pass

    await asyncio.gather(*(probe(ip, p) for ip in addrs for p in ports))
    return found


def scan_masscan(cidrs, ports, rate=1000, excludefile=None, binary="masscan"):
    """masscan 无状态 SYN 扫描（需 root）。接受任意 CIDR，含 0.0.0.0/0。"""
    portspec = ",".join(str(p) for p in ports)
    fd, out = tempfile.mkstemp(suffix=".lst")
    os.close(fd)
    cmd = [binary, *cidrs, "-p" + portspec, "--rate", str(rate), "-oL", out]
    if excludefile and os.path.exists(excludefile):
        cmd += ["--excludefile", excludefile]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    found = _parse_masscan_list(out)
    try:
        os.unlink(out)
    except OSError:
        pass
    if proc.returncode != 0 and not found:
        raise RuntimeError(f"masscan 失败（可能需 sudo）: {proc.stderr.strip()[:300]}")
    return found


def _parse_masscan_list(path) -> list[tuple[str, int]]:
    """解析 masscan -oL 输出：行形如 `open tcp 18789 1.2.3.4 <ts>`。"""
    found: list[tuple[str, int]] = []
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == "open" and parts[1] == "tcp":
                    try:
                        found.append((parts[3], int(parts[2])))
                    except ValueError:
                        continue
    except FileNotFoundError:
        pass
    return found


def scan_zmap(cidrs, ports, rate=10000, blocklist=None, binary="zmap"):
    """ZMap 单端口扫描，多端口循环。Linux 扫描主机用（需 root）。"""
    found: list[tuple[str, int]] = []
    for port in ports:
        cmd = [binary, "-p", str(port), "-r", str(rate), "-o", "-", *cidrs]
        if blocklist and os.path.exists(blocklist):
            cmd += ["-b", blocklist]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"zmap 失败（可能需 sudo）: {proc.stderr.strip()[:300]}")
        for line in proc.stdout.splitlines():
            ip = line.strip()
            if ip and not ip.startswith("#"):
                found.append((ip, port))
    return found
