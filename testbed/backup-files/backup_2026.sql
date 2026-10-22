CREATE TABLE assets (
  id BIGSERIAL PRIMARY KEY,
  url TEXT UNIQUE NOT NULL,
  host TEXT NOT NULL,
  fingerprint JSONB DEFAULT '{}',
  status_code INT,
  page_hash TEXT,
  title TEXT,
  discovered_at TIMESTAMPTZ DEFAULT now(),
  last_seen TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE risks (
  id BIGSERIAL PRIMARY KEY,
  asset_url TEXT NOT NULL REFERENCES assets(url),
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  evidence JSONB DEFAULT '{}',
  raw_output TEXT,
  tool TEXT,
  template TEXT,
  signature TEXT UNIQUE NOT NULL,
  status TEXT DEFAULT 'active',
  ai_explanation JSONB DEFAULT '{}',
  first_seen TIMESTAMPTZ DEFAULT now(),
  last_seen TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE baselines (
  id BIGSERIAL PRIMARY KEY,
  asset_url TEXT NOT NULL REFERENCES assets(url),
  page_hash TEXT NOT NULL,
  snapshot_ref TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  is_current BOOLEAN DEFAULT true
);