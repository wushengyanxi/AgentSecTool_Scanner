"""IP → 物理城市的离线解析（MaxMind GeoLite2-City）。

入库时按 IP 富化城市归属。设计为"软依赖"：库文件或 geoip2 缺失时不报错、不阻断
入库，lookup() 返回三个 None——geo 只是富化字段，不该让扫描入库失败。

配置见 geoip/geoip.ini（[geoip] city_db 指向 .mmdb 路径）；凭据与库均不入库。
"""

import configparser
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_CONFIG = os.path.join(_HERE, "geoip.ini")
_DEFAULT_DB = "data/geoip/GeoLite2-City.mmdb"

# 中文优先，回退英文，再回退空串
_LANGS = ("zh-CN", "en")


def _db_path() -> str:
    """从 geoip.ini 读库路径（相对项目根解析为绝对路径）；无配置时用默认路径。"""
    path = _DEFAULT_DB
    cfg = configparser.ConfigParser()
    if os.path.exists(_CONFIG):
        cfg.read(_CONFIG)
        path = cfg.get("geoip", "city_db", fallback=_DEFAULT_DB)
    return path if os.path.isabs(path) else os.path.join(_ROOT, path)


def _name(node) -> str:
    """从 geoip2 的 names 字典按语言优先级取名字。"""
    names = getattr(node, "names", None) or {}
    for lang in _LANGS:
        if names.get(lang):
            return names[lang]
    return getattr(node, "name", None) or ""


# GeoLite2 的中文城市名后缀不统一（"北京" vs "北京市"），归一时去掉，避免同城拆成两行。
_CITY_SUFFIX = ("特别行政区", "自治州", "地区", "盟", "市")


def _normalize_city(city: str) -> str:
    """城市名归一：去掉行政区后缀。仅对纯中文名生效（英文名如 Hong Kong 不动）。"""
    if not city:
        return city
    for suf in _CITY_SUFFIX:
        if city.endswith(suf) and len(city) > len(suf):
            return city[: -len(suf)]
    return city


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
        """返回 (country, region, city)，任一解析不到的位置为 None。"""
        if not self.reader or not ip:
            return (None, None, None)
        try:
            import geoip2.errors
            r = self.reader.city(ip)
            country = _name(r.country) or None
            region = _name(r.subdivisions.most_specific) or None
            city = _normalize_city(_name(r.city)) or None
            return (country, region, city)
        except geoip2.errors.AddressNotFoundError:
            return (None, None, None)
        except Exception:  # noqa: BLE001 — 非法 IP 等，降级
            return (None, None, None)

    def close(self):
        if self.reader:
            self.reader.close()
            self.reader = None
