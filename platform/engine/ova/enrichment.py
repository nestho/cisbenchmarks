from __future__ import annotations

import csv
import gzip
import json
from pathlib import Path
from typing import Any

try:
    import ijson  # type: ignore
except Exception:  # pragma: no cover
    ijson = None


def _metric(record: dict[str, Any]) -> tuple[str, str, str]:
    metrics = ((record.get("cve") or {}).get("metrics") or {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if not rows:
            continue
        chosen = next((x for x in rows if x.get("type") == "Primary"), rows[0])
        data = chosen.get("cvssData") or {}
        score = data.get("baseScore", "")
        severity = data.get("baseSeverity") or chosen.get("baseSeverity") or ""
        vector = data.get("vectorString", "")
        return str(score), str(severity), str(vector)
    return "", "", ""


def _parse_nvd_record(wrapper: dict[str, Any]) -> dict[str, Any]:
    cve = wrapper.get("cve") or wrapper
    cve_id = str(cve.get("id") or "").upper()
    descriptions = cve.get("descriptions") or []
    description = next((x.get("value", "") for x in descriptions if x.get("lang") == "en"), descriptions[0].get("value", "") if descriptions else "")
    score, severity, vector = _metric({"cve": cve})
    weaknesses: list[str] = []
    for item in cve.get("weaknesses") or []:
        for desc in item.get("description") or []:
            value = desc.get("value")
            if value:
                weaknesses.append(value)
    refs = [x.get("url", "") for x in cve.get("references") or [] if x.get("url")]
    return {
        "cve": cve_id,
        "description": description,
        "cvss": score,
        "severity": severity,
        "vector": vector,
        "cwe": ", ".join(dict.fromkeys(weaknesses)),
        "references": list(dict.fromkeys(refs)),
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
    }


def load_nvd_for_cves(feeds_root: str | Path, cves: set[str], log=print) -> dict[str, dict[str, Any]]:
    wanted = {x.upper() for x in cves if x}
    if not wanted:
        return {}
    found: dict[str, dict[str, Any]] = {}
    # Updates can supersede annual records. Read all available snapshots for
    # the requested CVEs and retain the newest revision, not the first hit.
    paths = sorted((Path(feeds_root) / "nvd").glob("nvdcve-2.0-*.json.gz"), reverse=True)
    for path in paths:
        log(f"[+] Enriching CVEs from NVD feed: {path.name}")
        try:
            with gzip.open(path, "rb") as fh:
                if ijson is not None:
                    iterator = ijson.items(fh, "vulnerabilities.item")
                    for wrapper in iterator:
                        cve_id = str(((wrapper.get("cve") or {}).get("id") or "")).upper()
                        if cve_id in wanted:
                            record = _parse_nvd_record(wrapper)
                            if cve_id not in found or record['last_modified'] > found[cve_id]['last_modified']:
                                found[cve_id] = record
                else:
                    data = json.load(fh)
                    for wrapper in data.get("vulnerabilities") or []:
                        cve_id = str(((wrapper.get("cve") or {}).get("id") or "")).upper()
                        if cve_id in wanted:
                            record = _parse_nvd_record(wrapper)
                            if cve_id not in found or record['last_modified'] > found[cve_id]['last_modified']:
                                found[cve_id] = record
        except Exception as exc:
            log(f"[WARN] Could not parse {path.name}: {exc}")
    return found


def load_kev(feeds_root: str | Path) -> dict[str, dict[str, Any]]:
    path = Path(feeds_root) / "enrichment" / "cisa" / "known_exploited_vulnerabilities.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        return {
            str(x.get("cveID") or "").upper(): x
            for x in data.get("vulnerabilities") or []
            if x.get("cveID")
        }
    except Exception:
        return {}


def load_epss(feeds_root: str | Path) -> dict[str, dict[str, str]]:
    path = Path(feeds_root) / "enrichment" / "epss" / "epss_scores-current.csv.gz"
    if not path.exists():
        return {}
    out: dict[str, dict[str, str]] = {}
    try:
        with gzip.open(path, "rt", encoding="utf-8-sig", errors="replace", newline="") as fh:
            lines = (line for line in fh if not line.startswith("#"))
            for row in csv.DictReader(lines):
                cve = (row.get("cve") or "").upper()
                if cve:
                    out[cve] = {"epss": row.get("epss", ""), "percentile": row.get("percentile", "")}
    except Exception:
        return {}
    return out


def enrich_findings(findings, feeds_root: str | Path, log=print):
    cves = {x.cve for x in findings if x.cve}
    nvd = load_nvd_for_cves(feeds_root, cves, log=log)
    kev = load_kev(feeds_root)
    epss = load_epss(feeds_root)
    for finding in findings:
        if not finding.cve:
            continue
        info = nvd.get(finding.cve, {})
        if not finding.description:
            finding.description = info.get("description", "")
        if not finding.cvss:
            finding.cvss = info.get("cvss", "")
        if info.get("severity"):
            finding.evidence.raw.setdefault("vendor_severity", finding.severity or "Info")
            sev = str(info["severity"]).title()
            finding.severity = "High" if sev == "Important" else ("Medium" if sev == "Moderate" else sev)
        if not finding.cwe:
            finding.cwe = info.get("cwe", "")
        finding.references = list(dict.fromkeys(finding.references + info.get("references", [])))
        if finding.cve in kev:
            finding.kev = True
            finding.kev_date_added = str(kev[finding.cve].get("dateAdded", ""))
        if finding.cve in epss:
            finding.epss_score = epss[finding.cve].get("epss", "")
            finding.epss_percentile = epss[finding.cve].get("percentile", "")
    return findings
