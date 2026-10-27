from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from ..debver import compare_versions
from ..models import Evidence, Finding, FindingStatus, Inventory


def parse_advisories(path: Path) -> list[dict]:
    """Read Debian's official DSA/DLA list; keep exact suite/source scopes."""
    records: list[dict] = []
    current: dict = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        header = re.match(r"^\[(\d{1,2} [A-Za-z]{3} \d{4})\]\s+((?:DSA|DLA|ELA)-\d+(?:-\d+)?)\s+(.+)$", line)
        if header:
            current = {
                "date": datetime.strptime(header[1], "%d %b %Y").date().isoformat(),
                "advisory": header[2], "title": header[3], "cves": [],
            }
            continue
        if not current:
            continue
        if "{" in line:
            current["cves"].extend(re.findall(r"CVE-\d{4}-\d{4,}", line))
        release = re.match(r"^\s+\[([^]]+)\]\s+-\s+(\S+)\s+(\S+)", line)
        if release and re.match(r"^\d", release[3]):
            records.append({**current, "suite": release[1], "source": release[2], "fixed": release[3], "feed": str(path)})
    return records


def evaluate_advisory_history(inventory: Inventory, feeds_root: Path) -> list[Finding]:
    records: list[dict] = []
    for filename in ("dsa-list", "dla-list", "ela-list"):
        path = feeds_root / "vendor" / "debian" / filename
        if path.exists():
            records.extend(parse_advisories(path))
    records = [record for record in records if record["suite"] == inventory.os.codename and record["cves"]]
    if not records:
        inventory.assessment.update(mode="unavailable", reason=f"No tracker or DSA/DLA/ELA records are available for {inventory.os.codename}.")
        return []
    index = inventory.source_package_index()
    matched_sources = {record["source"] for record in records if record["source"] in index}
    has_elts = any(record["advisory"].startswith("ELA-") for record in records)
    inventory.assessment.update(
        mode="advisories" if has_elts else "historical", source="Debian DSA/DLA and Freexian ELA" if has_elts else "Debian DSA/DLA advisory history",
        latest_advisory=max(record["date"] for record in records),
        matched_source_packages=len(matched_sources),
        matched_sources=sorted(matched_sources),
        evaluated_packages=sum(len(index[name]) for name in matched_sources),
        reason="Published advisory fixes only. Open/untriaged issues and unlisted/custom vendor packages are not fully assessed. ELTS remediation requires a provider/vendor-approved update path." if has_elts else "Historical published fixes only. This is not a complete current CVE assessment; open issues, later ELTS fixes and custom vendor builds need separate data.",
    )
    output: dict[tuple, Finding] = {}
    for record in sorted(records, key=lambda record: (record["date"], record["advisory"]), reverse=True):
        source = record["source"]
        versions: dict[str, list] = {}
        for pkg in index.get(source, []):
            if pkg.metadata_complete and pkg.package_manager in {"dpkg", "deb"}:
                versions.setdefault(pkg.source_installed_version, []).append(pkg)
        for installed, packages in versions.items():
            if compare_versions(installed, record["fixed"]) >= 0:
                continue
            custom = any(re.search(r"onl|opennetworklinux|sinos|sina|accton|~bpo", f"{pkg.name} {pkg.vendor} {pkg.maintainer} {pkg.origin} {pkg.installed_version}", re.I) for pkg in packages)
            binaries = {f"{pkg.name}:{pkg.arch}": pkg.installed_version for pkg in packages}
            arch = ", ".join(sorted({pkg.arch for pkg in packages}))
            advisory = record["advisory"]
            elts = advisory.startswith("ELA-")
            reference = f"https://www.freexian.com/lts/extended/updates/{advisory.lower()}-{source}/" if elts else f"https://security-tracker.debian.org/tracker/{advisory}"
            custom = custom or (elts and source == "linux")
            note = f"Debian {inventory.os.codename}; {advisory} published {record['date']}; published source-package fixed-version evidence. Binary runtime exploitability, open issues and custom vendor builds require separate assessment."
            if custom:
                note += " This package has custom/backports provenance and requires vendor validation."
            for cve in dict.fromkeys(record["cves"]):
                key = (source, installed, arch, cve)
                if key in output:
                    continue
                output[key] = Finding(
                    host=inventory.hostname, os=inventory.os.pretty_name,
                    package_name=source, installed_evr=installed, package_arch=arch,
                    cve=cve, status=FindingStatus.NEEDS_VALIDATION if custom else FindingStatus.CONFIRMED_VULNERABLE,
                    confidence="Medium; custom build" if custom else "High; published Debian advisory and source version matched",
                    severity="Info", fixed_evr=record["fixed"],
                    description=f"{advisory}: {record['title']}. {cve} is listed for Debian {inventory.os.codename} with fixed source version {record['fixed']}.",
                    reason=f"Installed source version {installed} is below {record['fixed']}. {note}",
                    solution=f"Update binaries built from {source} to Debian source version {record['fixed']} or later approved for {inventory.os.codename}. For SiNOS/ONL builds, obtain vendor-approved firmware/packages before updating.",
                    evidence=Evidence(
                        source="Freexian ELTS Advisory" if elts else "Debian DSA/DLA Advisory", advisory=advisory, feed_file=record["feed"], reference=reference,
                        evaluated_expression=f"source={source}; suite={inventory.os.codename}; {installed} < {record['fixed']}",
                        raw={"source_package": source, "matched_binary_packages": list(binaries), "installed_binary_versions": binaries,
                             "scope_note": note, "advisory_date": record["date"], "historical": not elts,
                             "affected_platforms": [f"Debian {inventory.os.codename}"], "vendor_severity": "Not rated"},
                    ),
                    references=[reference, f"https://security-tracker.debian.org/tracker/{cve}"],
                    source_package=source, package_manager="dpkg", package_vendor="Freexian ELTS" if elts else "Debian",
                    running_kernel=inventory.running_kernel, review_required=custom,
                )
    return list(output.values())
