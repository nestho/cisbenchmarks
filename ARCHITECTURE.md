# OpenCompliance — Architecture (v0.1 draft)

Open-source, community-driven compliance scanning platform inspired by commercial
tools (Nessus / CIS-CAT / ScoutSuite). Runs CIS, DISA STIG, NIST, PCI-DSS and
custom audit definitions against real targets, collects evidence, scores
compliance, and produces Nessus-style HTML/PDF reports.

## 1. Goals

- Multi-standard: CIS Benchmarks, DISA STIG, NIST 800-53/CSF, PCI-DSS, ISO 27001, custom.
- Multi-target: Linux/Unix (SSH), Windows (WinRM), network devices (SSH/NETCONF/SNMP/API),
  cloud (AWS/Azure/GCP APIs), containers/Kubernetes.
- Agentless first, optional lightweight agent for deep checks.
- Audit-file native: parse Tenable Nessus `.audit` and a native YAML/JSON format.
- Evidence-based results with raw command output and remediation guidance.
- Modern web UI + REST API + CLI.
- Plugin SDK for custom checks, connectors, and report templates.

## 2. Non-goals (v1)

- No modification of scanned targets (read-only checks only, except optional remediation mode later).
- No proprietary benchmark redistribution: PDFs stay as reference; checks come from audit files.

## 3. High-level components

```
┌──────────────────────────────────────────────────────────────┐
│  Web UI (React)  │  CLI (ocli)  │  REST/GraphQL API          │
├──────────────────────────────────────────────────────────────┤
│  Control Plane (Go)                                          │
│   ├─ Auth/RBAC/SSO   ├─ Asset & Benchmark Registry           │
│   ├─ Scan Orchestrator (job queue, scheduler)                │
│   ├─ Compliance Engine (scoring, drift, exceptions)          │
│   ├─ Report Generator (HTML/PDF/CSV/JSON/XCCDF)              │
│   └─ Plugin Host (checks, connectors, reports)               │
├──────────────────────────────────────────────────────────────┤
│  Data Plane                                                  │
│   ├─ Connectors: SSH, WinRM, SNMP, NETCONF, cloud SDKs       │
│   ├─ Optional Agent (Go, cross-compiled)                     │
│   └─ Evidence Store (object storage)                         │
├──────────────────────────────────────────────────────────────┤
│  Storage: PostgreSQL (metadata/results) │ Redis (queue/cache) │
│           MinIO/S3 (evidence/PDFs) │ Vault (secrets)          │
└──────────────────────────────────────────────────────────────┘
```

## 4. Benchmark corpus (this repo)

- `Operating Systems/`, `Server Software/`, etc. hold CIS PDFs (reference only, not redistributed).
- A `Benchmark Parser` extracts metadata (title, version, technology, profile, section tree)
  into a catalog DB. PDFs are never modified.
- Derived metadata lives in `platform/data/derived/` (gitignored) or the DB.
- Actual check definitions come from `.audit` files / native audit files / XCCDF.

## 5. Canonical audit model

All input formats convert to one internal model (see `docs/audit-format.md`):

- Benchmark → Sections → Recommendations → Checks
- Check types: command, file, registry, service, package, api, cloud, script
- Each check: id, title, description, rationale, remediation, scoring, profile, commands,
  expected result (regex/value), severity, references (CIS ID, NIST, STIG).

## 6. Scan lifecycle

1. User picks benchmark(s) + target group + profile (Level 1/2).
2. Orchestrator creates a scan job and enqueues per-target tasks.
3. Connector/agent runs checks in parallel, captures stdout/stderr/exit code + evidence.
4. Compliance engine evaluates each check, applies scoring weights, exceptions, waivers.
5. Results stored; report generated on demand or on schedule.
6. UI shows dashboard + drill-down; reports downloadable.

## 7. Security

- Read-only checks by default; remediation mode opt-in and audited.
- Secrets in Vault; short-lived SSH keys; RBAC; SSO (OIDC/SAML); MFA.
- Tenant isolation at DB row level + separate credential scopes.
- Full audit log of who scanned what and when.

## 8. Extensibility

- Plugin SDK (Go) for: custom connectors, check types, report templates, parsers.
- Webhook + event bus for SIEM/ticketing integration.
- Import/export of audit files and results (Nessus-compatible where possible).

## 9. Roadmap

See `docs/roadmap.md`. Phase 0: architecture + repo. Phase 1: parser + native audit format + SSH connector + CLI. Phase 2: web UI + DB + reporting. Phase 3: WinRM/network/cloud + .audit parser. Phase 4: multi-tenancy, plugins, community.
