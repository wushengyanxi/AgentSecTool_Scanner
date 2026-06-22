# GeoIP 富化：IP → 物理城市

把扫描到的目标 IP 映射到物理城市（以城市为单位），数据写入扫描库 `assets` 表的
`country` / `region` / `city` 列。

来源是 **MaxMind GeoLite2-City 离线库**（业界城市级 geolocation 基准，免费、离线、
可复现）。城市归属是第三方按 IP 推断的近似值，**城市级有误差**（云/IDC 段尤甚），
不是权威或长期固定的事实——仅作富化展示。

## 一次性准备

1. **凭据**：复制模板填入 MaxMind 账号信息（GeoLite2 免费，需注册账号生成 license key）：
   ```
   cp geoip/geoip.example.ini geoip/geoip.ini
   # 编辑 geoip/geoip.ini，填 account_id 与 license_key
   ```
   `geoip/geoip.ini` 已在 `.gitignore` 中，绝不入库。

2. **依赖**（引入了 `geoip2`，项目其余部分仍为纯标准库；Homebrew Python 受 PEP 668
   限制，用项目 venv 安装）：
   ```
   python3 -m venv .venv
   .venv/bin/python3 -m pip install -r geoip/requirements.txt
   ```

3. **下载库**到 `data/geoip/GeoLite2-City.mmdb`（约 66MB，`*.mmdb` 已 gitignore）：
   ```
   curl -sL -o /tmp/city.tar.gz \
     "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=<KEY>&suffix=tar.gz"
   tar -xzf /tmp/city.tar.gz -C /tmp/
   cp /tmp/GeoLite2-City_*/GeoLite2-City.mmdb data/geoip/
   ```
   GeoLite2 每周更新，可用同一 key 重新下载刷新。

4. **回填存量**（给库里已有资产补城市；新入库的由 sink 自动富化）：
   ```
   .venv/bin/python3 -m geoip.backfill          # 只填空缺
   .venv/bin/python3 -m geoip.backfill --all     # 库更新后重刷全部
   ```

## 日常使用

新扫描入库时自动富化——但因依赖 `geoip2`，入库需走 venv：

```
.venv/bin/python3 -m sink --in results.jsonl
```

库文件或 geoip2 缺失时，`geoip.lookup` 优雅降级（city 留空），**不会阻断入库**。

## 文件

- `lookup.py` — `GeoResolver.lookup(ip) → (country, region, city)`，软依赖、可降级
- `backfill.py` — 给存量资产回填/刷新城市（`python3 -m geoip.backfill`）
- `geoip.example.ini` — 凭据与库路径模板
