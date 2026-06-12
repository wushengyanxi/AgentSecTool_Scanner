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
CREATE TABLE IF NOT EXISTS observations (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id       TEXT NOT NULL,
  ip             TEXT NOT NULL,
  port           INTEGER NOT NULL,
  ts             TEXT NOT NULL,
  is_openclaw    INTEGER NOT NULL,
  confidence     REAL,
  version        TEXT,
  version_source TEXT,
  signals        TEXT,
  tls            INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);

CREATE INDEX IF NOT EXISTS idx_obs_asset ON observations(asset_id);
CREATE INDEX IF NOT EXISTS idx_obs_ts ON observations(ts);
