-- 资产登记：按身份去重（内容指纹或 ip:port）。
CREATE TABLE IF NOT EXISTS assets (
  asset_id       TEXT PRIMARY KEY,
  identity_key   TEXT NOT NULL,
  ip             TEXT NOT NULL,
  port           INTEGER NOT NULL,
  is_openclaw    INTEGER NOT NULL DEFAULT 0,
  latest_version TEXT,
  version_source TEXT,
  first_seen     TEXT NOT NULL,
  last_seen      TEXT NOT NULL,
  observations   INTEGER NOT NULL DEFAULT 0
);

-- 时序观测：每次扫描一行，append-only。
-- 二元研判：is_openclaw + rule（触发的白名单条件 C1/C2，False 时空）+ matched（命中的测试项 JSON 数组）。
-- error_type：探不到时的失败原因（timeout/connection_refused/unreachable/down）。
CREATE TABLE IF NOT EXISTS observations (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id       TEXT NOT NULL,
  ip             TEXT NOT NULL,
  port           INTEGER NOT NULL,
  ts             TEXT NOT NULL,
  is_openclaw    INTEGER NOT NULL,
  rule           TEXT,
  version        TEXT,
  version_source TEXT,
  matched        TEXT,
  error_type     TEXT,
  tls            INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);

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
