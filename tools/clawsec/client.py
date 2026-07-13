"""ClawSec 暴露面平台 API 客户端。

ClawSec（clawsec.tcode.com.cn）是一所高校做的 OpenClaw 公网暴露测绘平台，公开展示
其收录的暴露实例，且频繁更新——作为与 FOFA 平级的被动发现/测绘种子源。

与 FOFA 的差异：
- 不需凭据（公开展示页的只读 API）；走固定请求头 X-Watchboard-Client。
- IP 隐藏一位（maskedIp，如 1.12.*.76）——补全/枚举由下游探测处理，本模块只取候选。
- 携带平台自己的版本判定 serverVersion——入库保留，可与本项目探测器做双源版本对比。

API（侦察自前端 bundle，2026-06）：
  GET /api/exposure/services?page=&limit=30&chinaScope=&runtimeStatus=  列表（分页）
  GET /api/exposure/overview                                           汇总计数
请求头：X-Watchboard-Client: web

限速：服务端 RateLimit-Policy 80;w=900（80 次 / 15 分钟），超限返回 429 + Retry-After。
"""
import json
import time
import urllib.error
import urllib.request

BASE = "http://clawsec.tcode.com.cn/api"
HEADERS = {"X-Watchboard-Client": "web", "User-Agent": "Mozilla/5.0"}
PAGE_SIZE = 30          # 服务端硬截断到 30，传更大无效
DEFAULT_PACE = 12.0     # 秒/请求，守 80次/15min（留余量）

# chinaScope 取值；None 表示不加该过滤（即全部）
SCOPES = {"china": "china", "overseas": "overseas", "all": None}


class ClawSecError(Exception):
    pass


class ClawSecClient:
    """只读 API 客户端。遇 429 自动按 Retry-After 等待重试，遇 502/503/504 无限退避重试，无人值守。"""

    def __init__(self, pace: float = DEFAULT_PACE, max_retries: int = 5):
        self.pace = pace
        self.max_retries = max_retries

    def _get(self, path: str, params: dict | None = None) -> dict:
        qs = ""
        if params:
            qs = "?" + "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
        url = f"{BASE}/{path}{qs}"
        req = urllib.request.Request(url, headers=HEADERS)
        attempt = 0
        server_err = 0
        while True:
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    d = json.loads(r.read())
                    if not d.get("success"):
                        raise ClawSecError(f"API success=false: {d.get('error')}")
                    return d["data"]
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    wait = int(e.headers.get("Retry-After", 60)) + 3
                    time.sleep(wait)
                    continue          # 限流不计入重试次数，等满即续
                if e.code in (502, 503, 504):
                    server_err += 1   # 服务端临时错误：无限重试，避免长时间拉取被一次 5xx 中断
                    time.sleep(min(5 * server_err, 60))  # 退避封顶 60s；不计入网络重试预算
                    continue
                raise ClawSecError(f"HTTP {e.code} on {path}") from e
            except (urllib.error.URLError, TimeoutError) as e:
                attempt += 1
                if attempt > self.max_retries:
                    raise ClawSecError(f"网络错误（重试耗尽）：{e}") from e
                time.sleep(5)

    def overview(self) -> dict:
        """汇总计数（境内/海外/Active 等）。"""
        return self._get("exposure/overview")

    def last_scan_time(self) -> str:
        """平台最近更新日期（overview 的 lastScanTime，如 "2026-06-15"），作为快照日期。"""
        return self.overview().get("lastScanTime", "")

    def page(self, page: int, scope: str = "china", active_only: bool = True) -> dict:
        """取一页。返回 {services: [...], pagination: {page,limit,total,totalPages}}。"""
        if scope not in SCOPES:
            raise ClawSecError(f"未知 scope: {scope}（可选 {list(SCOPES)}）")
        params = {"page": page, "limit": PAGE_SIZE, "chinaScope": SCOPES[scope]}
        if active_only:
            params["runtimeStatus"] = "Active"
        return self._get("exposure/services", params)

    def total_pages(self, scope: str = "china", active_only: bool = True) -> tuple[int, int]:
        """返回 (total, total_pages)。"""
        pg = self.page(1, scope, active_only)["pagination"]
        return pg["total"], pg["totalPages"]
