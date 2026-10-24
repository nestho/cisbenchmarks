CREATE TABLE IF NOT EXISTS organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id),
  email TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL DEFAULT 'viewer',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS benchmarks (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  version TEXT,
  technology TEXT,
  os TEXT,
  source_path TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS controls (
  id TEXT NOT NULL,
  benchmark_id TEXT NOT NULL REFERENCES benchmarks(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT,
  rationale TEXT,
  remediation TEXT,
  scoring TEXT,
  profile TEXT[],
  PRIMARY KEY (benchmark_id, id)
);

CREATE TABLE IF NOT EXISTS checks (
  id SERIAL PRIMARY KEY,
  benchmark_id TEXT NOT NULL,
  control_id TEXT NOT NULL,
  type TEXT NOT NULL,
  raw_type TEXT,
  command TEXT,
  expected TEXT,
  regex TEXT,
  path TEXT,
  contains TEXT,
  severity TEXT,
  FOREIGN KEY (benchmark_id, control_id) REFERENCES controls(benchmark_id, id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS assets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id),
  name TEXT NOT NULL,
  type TEXT,
  host TEXT,
  port INT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id),
  benchmark_id TEXT NOT NULL REFERENCES benchmarks(id),
  profile TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS scan_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  asset_id UUID REFERENCES assets(id),
  control_id TEXT,
  check_type TEXT,
  status TEXT NOT NULL,
  actual TEXT,
  expected TEXT,
  evidence TEXT,
  error TEXT,
  duration_ms BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
EOF