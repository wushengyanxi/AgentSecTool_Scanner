"""IP → 物理城市的离线解析（MaxMind GeoLite2-City）。

入库时按 IP 富化城市归属。设计为"软依赖"：库文件或 geoip2 缺失时不报错、不阻断
入库，lookup() 返回三个 None——geo 只是富化字段，不该让扫描入库失败。

地名口径：只取 GeoLite2 的「标准英文」名（其中文名不可信，见 geoip/cn_names.py），
再经本地映射表 cn_names 转成简体中文；映射表未收录的英文名原样保留。

配置见 geoip/geoip.ini（[geoip] city_db 指向 .mmdb 路径）；凭据与库均不入库。
"""

import configparser
import os

from .cn_names import CITY_ZH, REGION_ZH

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_CONFIG = os.path.join(_HERE, "geoip.ini")
_DEFAULT_DB = "data/geoip/GeoLite2-City.mmdb"


def _db_path() -> str:
    """从 geoip.ini 读库路径（相对项目根解析为绝对路径）；无配置时用默认路径。"""
    path = _DEFAULT_DB
    cfg = configparser.ConfigParser()
    if os.path.exists(_CONFIG):
        cfg.read(_CONFIG)
        path = cfg.get("geoip", "city_db", fallback=_DEFAULT_DB)
    return path if os.path.isabs(path) else os.path.join(_ROOT, path)


def _en(node) -> str:
    """从 geoip2 的 names 字典取标准英文名。"""
    names = getattr(node, "names", None) or {}
    return names.get("en") or getattr(node, "name", None) or ""


class GeoResolver:
    """持有 mmdb reader 的解析器。库不可用时 .ok 为 False，lookup 始终返回空。

    用法（批量入库时复用一个实例，避免反复打开库）：
        geo = GeoResolver()
        country, region, city = geo.lookup("1.2.3.4")
        geo.close()
    """

    def __init__(self, db_path: str | None = None):
        self.reader = None
        self.error = None
        path = db_path or _db_path()
        try:
            import geoip2.database
            self.reader = geoip2.database.Reader(path)
        except ImportError:
            self.error = "未安装 geoip2（pip install geoip2）"
        except FileNotFoundError:
            self.error = f"GeoLite2 库不存在：{path}"
        except Exception as e:  # noqa: BLE001 — 库损坏等，降级即可
            self.error = f"打开 GeoLite2 库失败：{e}"

    @property
    def ok(self) -> bool:
        return self.reader is not None

    def lookup(self, ip: str):
        """返回 (country, region, city, lat, lng)，任一解析不到的位置为 None。

        city/region 取库的英文名后经本地映射表转简体中文；未收录的英文名原样保留。
        country 取库的中文名（国家名简体可靠，无需自建映射）。
        lat/lng 是该 IP 的经纬度（GeoLite2 给的城市级近似坐标），供地图打点。
        """
        if not self.reader or not ip:
            return (None, None, None, None, None)
        try:
            import geoip2.errors
            r = self.reader.city(ip)
            cn = (r.country.names or {}).get("zh-CN") or _en(r.country)
            country = cn or None
            region_en = _en(r.subdivisions.most_specific)
            city_en = _en(r.city)
            region = (REGION_ZH.get(region_en) or region_en) or None
            city = (CITY_ZH.get(city_en) or city_en) or None
            lat = r.location.latitude
            lng = r.location.longitude
            return (country, region, city, lat, lng)
        except geoip2.errors.AddressNotFoundError:
            return (None, None, None, None, None)
        except Exception:  # noqa: BLE001 — 非法 IP 等，降级
            return (None, None, None, None, None)

    def close(self):
        if self.reader:
            self.reader.close()
            self.reader = None
