# Reporting

## Formats
- HTML (Nessus-style): executive summary, score, failed checks, evidence, remediation.
- PDF (via headless Chrome or wkhtmltopdf).
- CSV/JSON for SIEM/ticketing.
- XCCDF results for SCAP consumers.

## Templates
- Go html/template with embedded CSS; pluggable themes.
- Per-benchmark remediation text included.
- Branding/custom logo support.

## Nessus parity
- Compliance %, pass/fail per control, severity, evidence, fix text.
- Export compatible with Nessus .audit result style where feasible.
