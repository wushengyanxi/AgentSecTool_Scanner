"""FOFA HTTP 客户端：账号信息、计数、Search After 续游标拉取。

- QPS 节流 + 429 指数退避（FOFA 限速）。
- 额度由 FOFA 服务端强制（超了直接返回错误）；本客户端不在本地记账。拉取过程中
  若 FOFA 中途拒绝（多半额度耗尽），search_after 会优雅停下、返回已拉部分与游标。
- 凭据自动从 fofa/fofa.ini（[fofa] email/key）或环境变量 FOFA_EMAIL/FOFA_KEY 取，不硬编码、不入库。

候选指纹（实测 country=CN）：title="OpenClaw Control" 命中 90,070；
icon_hash（favicon.ico 的 mmh3）命中 8,139；二者并集 98,134（icon_hash 多为 title 漏网）。
"""

import base64
import configparser
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = "https://fofa.info"

# 凭据配置文件：与本包同目录的 fofa.ini（已 gitignore）。用 __file__ 定位，故在哪个目录跑都能找到。
_CONFIG_PATH = Path(__file__).resolve().parent / "fofa.ini"


def _config_credentials():
    """从 fofa/fofa.ini 读 [fofa] email/key；文件不存在或缺字段则返回 (None, None)。"""
    if not _CONFIG_PATH.exists():
        return None, None
    cp = configparser.ConfigParser()
    try:
        cp.read(_CONFIG_PATH, encoding="utf-8")
    except configparser.Error:
        return None, None
    if not cp.has_section("fofa"):
        return None, None
    return cp.get("fofa", "email", fallback=None), cp.get("fofa", "key", fallback=None)

# OpenClaw favicon.ico 的 mmh3（base64 后 mmh3，FOFA/Shodan 约定）。
OPENCLAW_FAVICON_ICON_HASH = "-805544463"
# title 用宽匹配 "OpenClaw"（FOFA 的 = 即"包含"）以多召回改名/汉化的实例；
# 误报由后续逐台探测过滤。相比精确短语 "OpenClaw Control" 在 CN 约多 3 千条。
OPENCLAW_FINGERPRINT = f'(title="OpenClaw" || icon_hash="{OPENCLAW_FAVICON_ICON_HASH}")'

# 一次性富拉取的小字段集（数据按记录计、不按字段计，故多拉字段不额外耗额度）。
# 注意：此 key 无权检索 lastupdatetime/header/body 等高级字段；增量改用查询里的
# after="YYYY-MM-DD" 操作符 + 本地自记的 first_seen，不依赖该字段。
DEFAULT_FIELDS = "ip,port,host,protocol,region,city,as_organization,server,title"


def cn_query(extra: str | None = None) -> str:
    """中国大陆 OpenClaw 候选查询；extra 可叠加如 region="Guangdong" 或 after="2026-06-01"。"""
    q = f'{OPENCLAW_FINGERPRINT} && country="CN"'
    return f"{q} && {extra}" if extra else q


class FofaError(RuntimeError):
    pass


class FofaClient:
    def __init__(self, email=None, key=None, base=BASE, min_interval=1.1):
        cfg_email, cfg_key = _config_credentials()
        # 优先级：显式入参 > 环境变量 > 配置文件 fofa/fofa.ini
        self.email = email or os.environ.get("FOFA_EMAIL") or cfg_email
        self.key = key or os.environ.get("FOFA_KEY") or cfg_key
        if not self.email or not self.key:
            raise FofaError(
                "缺少 FOFA 凭据：请在 fofa/fofa.ini 的 [fofa] 段填 email/key"
                "（参照 fofa/fofa.example.ini），或设环境变量 FOFA_EMAIL / FOFA_KEY")
        self.base = base
        self.min_interval = min_interval  # 两次调用的最小间隔（秒），节流防 429
        self._last = 0.0

    def _throttle(self):
        dt = time.time() - self._last
        if dt < self.min_interval:
            time.sleep(self.min_interval - dt)
        self._last = time.time()

    def _get(self, path, params, retries=4):
        last_err = None
        for attempt in range(retries):
            self._throttle()
            url = f"{self.base}/api/v1/{path}?" + urllib.parse.urlencode(params)
            try:
                with urllib.request.urlopen(url, timeout=60) as r:
                    data = json.load(r)
            except urllib.error.HTTPError as e:
                last_err = FofaError(f"HTTP {e.code}: {e.read()[:200]!r}")
                if e.code == 429 and attempt < retries - 1:
                    time.sleep((2 ** attempt) * 2)  # 429 退避
                    continue
                raise last_err from e
            except Exception as e:  # noqa: BLE001
                last_err = FofaError(f"请求失败: {e}")
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                raise last_err from e
            if data.get("error"):
                raise FofaError(f"FOFA 错误: {data.get('errmsg')}")
            return data
        raise last_err or FofaError("重试耗尽")

    def account_info(self) -> dict:
        return self._get("info/my", {"email": self.email, "key": self.key})

    def count(self, query: str) -> int:
        """某查询命中总数（size=1，便宜：1 次查询 / 1 条数据）。"""
        d = self._get("search/all", {
            "email": self.email, "key": self.key,
            "qbase64": base64.b64encode(query.encode()).decode(),
            "fields": "ip", "size": 1,
        })
        return d.get("size")

    def search_after(self, query, fields=DEFAULT_FIELDS, page_size=2000, full=False,
                     start_next="", on_batch=None, max_records=None):
        """Search After（/api/v1/search/next，next 游标）逐批拉取。

        可从 start_next 续拉；max_records 给单次封顶。on_batch(rows, field_list, next_id) 处理每批。
        若 FOFA 中途拒绝（额度耗尽等），优雅停下返回已拉部分（游标已由 on_batch 逐批保存可续）；
        但若首次调用就失败（查询/权限问题），则向上抛。返回 (拉取记录数, 最后 next 游标)。"""
        field_list = fields.split(",")
        next_id = start_next or ""
        pulled = 0
        while True:
            if max_records is not None and pulled >= max_records:
                break
            size = page_size
            if max_records is not None:
                size = min(size, max_records - pulled)
            params = {
                "email": self.email, "key": self.key,
                "qbase64": base64.b64encode(query.encode()).decode(),
                "fields": fields, "size": size, "full": str(bool(full)).lower(),
            }
            if next_id:
                params["next"] = next_id
            try:
                d = self._get("search/next", params)
            except FofaError:
                if pulled == 0:
                    raise   # 首次就失败 → 查询/权限/额度问题，向上抛
                break       # 拉到一半 FOFA 拒绝（多半额度耗尽）→ 优雅停，游标已存
            rows = d.get("results") or []
            n = len(rows)
            next_id = d.get("next") or ""
            if n and on_batch:
                on_batch(rows, field_list, next_id)
            pulled += n
            if n == 0 or not next_id or n < size:
                break
        return pulled, next_id
