# System Design

## Components

### Control Plane (Go)
- `api/` — HTTP handlers (Gin), OpenAPI spec, auth middleware.
- `orchestrator/` — job scheduling, queue (Redis/NATS), worker dispatch.
- `registry/` — benchmarks, controls, checks, assets, users.
- `compliance/` — scoring engine, drift, exceptions.
- `reporting/` — template engine (HTML/PDF), export.

### Data Plane
- `connectors/` — SSH, WinRM, SNMP, NETCONF, cloud SDK wrappers.
- `agent/` — optional Go binary deployed on target.
- `parsers/` — PDF metadata, Nessus .audit, native YAML, XCCDF/OVAL.

### Storage
- PostgreSQL: all relational data.
- Redis: job queue, cache, sessions.
- MinIO/S3: evidence blobs, PDFs, generated reports.
- Vault: credentials, SSH keys, API tokens.

## Concurrency & reliability
- Workers pull jobs from queue; idempotent checks; retry with backoff.
- Per-target timeout; partial results saved.
- Horizontal scaling of workers.

## Observability
- OpenTelemetry traces/metrics; structured logs; health endpoints.
