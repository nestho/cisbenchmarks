# FIRST Exploit Prediction Scoring System (EPSS) v3

- **Governing Body**: Forum of Incident Response and Security Teams (FIRST)
- **Model Version**: EPSS v3.0 (Machine learning model estimating 30-day exploitation probability)
- **Metrics**:
  1. **EPSS Probability Score ($0.00000 - 1.00000$)**: Direct probability that a vulnerability will be observed exploited in the next 30 days.
  2. **EPSS Percentile ($0.0% - 100.0%$)**: Relative severity compared to all other scored CVEs.

## HardenX Risk Thresholds
- **Urgent Priority**: In CISA KEV OR (EPSS > 0.50 and CVSS >= 7.0).
- **High Exploitability**: EPSS Percentile >= 95.0% (Top 5% most weaponizable CVEs).
- **Elevated Exploitability**: EPSS Percentile between 80.0% and 94.9%.
- **Baseline / Low**: EPSS Percentile < 80.0%.

## Live API Contract
`GET https://api.first.org/data/v1/epss?cve={CVE-ID}`
