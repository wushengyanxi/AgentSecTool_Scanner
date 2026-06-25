-- 资产登记：按【快照日期 × ip:port】分行。一个 jsonl = 一个快照（snapshot_date = jsonl
-- 内所有记录 ts 的日期众数）。同一快照内同 ip:port 只保留最新扫描结果（入库 REPLACE）；
-- 不同快照各存各的，旧快照作为镜像留存。前端按时间窗口加载，窗口内同 ip:port 取最新快照那条。
-- category（本快照的研判分档）：
--   confirmed            明确 OpenClaw 实例（二元白名单判 True），取到版本
--   confirmed_no_version 明确 OpenClaw 实例，版本未取到（如未采集的新版本）
--   suspect              中了部分特征但未达白名单——不呈现为 OpenClaw，但有复扫/优化价值，保留
-- 探不到（timeout/down/refused/unreachable）的目标不收录（无价值，由 load 跳过）。
CREATE TABLE IF NOT EXISTS assets (
  snapshot_date  TEXT NOT NULL,    -- 快照日期 YYYY-MM-DD（= 该 jsonl 内 ts 日期众数）
  asset_id       TEXT NOT NULL,
  identity_key   TEXT NOT NULL,
  ip             TEXT NOT NULL,
  port           INTEGER NOT NULL,
  is_openclaw    INTEGER NOT NULL DEFAULT 0,
  category       TEXT,            -- confirmed | confirmed_no_version | suspect
  latest_version TEXT,
  version_source TEXT,
  first_seen     TEXT NOT NULL,   -- 该 ip:port 在本快照内最早 ts
  last_seen      TEXT NOT NULL,   -- 该 ip:port 在本快照内最近 ts
  observations   INTEGER NOT NULL DEFAULT 0,
  -- 物理位置（GeoLite2 离线库按 IP 解析，入库时富化；解析不到留空）
  country        TEXT,
  region         TEXT,            -- 省/区域
  city           TEXT,
  lat            REAL,            -- 纬度（城市级近似坐标，供地图打点）
  lng            REAL,            -- 经度
  PRIMARY KEY (snapshot_date, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_assets_date ON assets(snapshot_date);

-- 时序观测：每次扫描一行，append-only。
-- 二元研判：is_openclaw + rule（触发的白名单条件 C1/C2/C3，False 时空）+ matched（命中的测试项 JSON 数组）。
-- error_type：探不到时的失败原因（timeout/connection_refused/unreachable/down）。
CREATE TABLE IF NOT EXISTS observations (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id       TEXT NOT NULL,
  ip             TEXT NOT NULL,
  port           INTEGER NOT NULL,
  ts             TEXT NOT NULL,
  is_openclaw    INTEGER NOT NULL,
  category       TEXT,            -- confirmed | confirmed_no_version | suspect（本次观测的分类）
  rule           TEXT,
  version        TEXT,
  version_source TEXT,
  matched        TEXT,
  error_type     TEXT,
  tls            INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);
CREATE INDEX IF NOT EXISTS idx_obs_category ON observations(category);

-- 测试项记录：每个观测的每一项测试项的完整请求与响应原文（供报告复查、争议追溯）。
CREATE TABLE IF NOT EXISTS probe_records (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  observation_id INTEGER NOT NULL,
  test_id        TEXT NOT NULL,
  request        TEXT,
  response       TEXT,
  hit            INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (observation_id) REFERENCES observations(id)
);

CREATE INDEX IF NOT EXISTS idx_obs_asset ON observations(asset_id);
CREATE INDEX IF NOT EXISTS idx_obs_ts ON observations(ts);
CREATE INDEX IF NOT EXISTS idx_probe_obs ON probe_records(observation_id);
