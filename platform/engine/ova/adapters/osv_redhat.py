"""Offline OSV (Open Source Vulnerabilities) adapter for Red Hat ecosystem.

OSV aggregates Red Hat RHSA/RHBA data with explicit introduced/fixed EVR ranges.
This is the same family of evidence used by Grype, Trivy, and OSV-Scanner for
RPM matching — complementary to native OVAL evaluation.

Feed layout (offline):
  feeds/vendor/osv/redhat/all.zip   — Google OSV Red Hat ecosystem dump
  or extracted JSON files under feeds/vendor/osv/redhat/*.json
"""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path

from ..models import Evidence, Finding, FindingStatus, Inventory
from ..rpmver import compare_evr
from .base import VendorAdapter
from .common import normalize_severity


def _host_majors(inventory: Inventory) -> set[str]:
    majors: set[str] = set()
    if inventory.os.major:
        majors.add(str(inventory.os.major))
    # CPE / release evidence
    for path, text in (inventory.os.release_files or {}).items():
        for m in re.finditer(r"enterprise_linux:(\d+)", text or "", re.I):
            majors.add(m.group(1))
        for m in re.finditer(r"release\s+(\d+)\.", text or "", re.I):
            majors.add(m.group(1))
    return majors or ({str(inventory.os.major)} if inventory.os.major else set())


def _ecosystem_matches(ecosystem: str, majors: set[str]) -> bool:
    """True when OSV ecosystem string targets this host major (RHEL 7/8/9…)."""
    eco = (ecosystem or "").lower()
    if "enterprise_linux" not in eco and "red hat" not in eco and "rhel" not in eco:
        return False
    for major in majors:
        if re.search(rf"enterprise_linux:{re.escape(major)}(?:[:\s]|$)", eco):
            return True
        if re.search(rf"\brhel\s*{re.escape(major)}\b", eco):
            return True
    # Generic Red Hat without version — too broad; skip
    return False


def _fixed_from_range(range_obj: dict) -> str:
    events = range_obj.get("events") or []
    fixed = ""
    for event in events:
        if "fixed" in event and event["fixed"]:
            fixed = str(event["fixed"]).strip()
    return fixed


def _same_rpm_stream(installed_evr: str, fixed_evr: str, host_major: str) -> bool:
    """Reject cross-stream false positives (kernel 3.10.el7 vs 4.11.el7a)."""
    inst = installed_evr.split(":", 1)[-1]
    fix = fixed_evr.split(":", 1)[-1]
    inst_ver = inst.split("-", 1)[0]
    fix_ver = fix.split("-", 1)[0]
    inst_rel = inst.split("-", 1)[1] if "-" in inst else ""
    fix_rel = fix.split("-", 1)[1] if "-" in fix else ""
    if host_major:
        el_host = f"el{host_major}"
        if el_host in inst_rel.lower() and re.search(r"el\d+", fix_rel.lower()):
            if el_host not in fix_rel.lower():
                return False
        if re.search(rf"el{re.escape(host_major)}[a-z]", fix_rel.lower()):
            return False
    im = re.match(r"^(\d+)\.", inst_ver)
    fm = re.match(r"^(\d+)\.", fix_ver)
    if im and fm and im.group(1) != fm.group(1):
        if int(im.group(1)) >= 2 and int(fm.group(1)) >= 2:
            return False
    return True


def _cves_from_record(record: dict) -> list[str]:
    out: list[str] = []
    rid = str(record.get("id") or "")
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", rid, re.I):
        out.append(rid.upper())
    for alias in record.get("aliases") or []:
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", str(alias), re.I):
            out.append(str(alias).upper())
    # refs
    for ref in record.get("references") or []:
        url = str(ref.get("url") or "")
        out.extend(re.findall(r"CVE-\d{4}-\d{4,}", url, re.I))
    summary = str(record.get("summary") or "")
    out.extend(re.findall(r"CVE-\d{4}-\d{4,}", summary, re.I))
    return list(dict.fromkeys(x.upper() for x in out))


def _iter_osv_records(root: Path):
    """Yield OSV JSON records from zip or directory."""
    zip_path = root / "all.zip"
    if zip_path.is_file():
        with zipfile.ZipFile(zip_path) as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    yield json.loads(zf.read(name))
                except Exception:
                    continue
        return
    if root.is_dir():
        for path in sorted(root.glob("*.json")):
            try:
                yield json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue


class OsvRedHatAdapter(VendorAdapter):
    name = "OSV Red Hat"

    def applicable(self, inventory: Inventory) -> bool:
        return (
            inventory.os.family in {"redhat", "redhat-compatible"}
            and any((pkg.package_manager or "rpm").lower() == "rpm" for pkg in inventory.packages)
        )

    def _feed_root(self, feeds_root: Path) -> Path:
        return Path(feeds_root) / "vendor" / "osv" / "redhat"

    def evaluate(self, inventory: Inventory, feeds_root: Path) -> list[Finding]:
        root = self._feed_root(feeds_root)
        if not root.exists() and not (root / "all.zip").exists():
            inventory.warnings.append(
                "OSV Red Hat: feed missing. Place all.zip under feeds/vendor/osv/redhat/ "
                "(download from https://osv-vulnerabilities.storage.googleapis.com/Red%20Hat/all.zip) "
                "or run Feeds update."
            )
            return []

        majors = _host_majors(inventory)
        index = inventory.package_index()
        findings: list[Finding] = []
        seen: set[tuple[str, str, str, str]] = set()
        scanned = 0
        matched_records = 0

        for record in _iter_osv_records(root if root.is_dir() else root.parent):
            scanned += 1
            affected = record.get("affected") or []
            if not affected:
                continue
            cves = _cves_from_record(record)
            advisory = str(record.get("id") or "")
            summary = str(record.get("summary") or record.get("details") or "")[:500]
            severity = ""
            db = record.get("database_specific") or {}
            if isinstance(db, dict):
                severity = str(db.get("severity") or db.get("cvss_v3") or "")

            hit = False
            for item in affected:
                pkg_meta = item.get("package") or {}
                name = str(pkg_meta.get("name") or "").strip()
                ecosystem = str(pkg_meta.get("ecosystem") or "")
                if not name or not _ecosystem_matches(ecosystem, majors):
                    continue
                pkgs = index.get(name.lower(), [])
                if not pkgs:
                    continue
                for range_obj in item.get("ranges") or []:
                    rtype = str(range_obj.get("type") or "ECOSYSTEM").upper()
                    if rtype not in {"ECOSYSTEM", "RPM", "SEMVER"}:
                        continue
                    fixed = _fixed_from_range(range_obj)
                    if not fixed:
                        continue
                    # Normalize fixed to EVR if missing epoch
                    fixed_evr = fixed if ":" in fixed else f"0:{fixed}"
                    host_major = next(iter(majors), "")
                    for pkg in pkgs:
                        if not _same_rpm_stream(pkg.evr, fixed_evr, host_major):
                            continue
                        if compare_evr(pkg.evr, fixed_evr) >= 0:
                            continue
                        hit = True
                        for cve in cves or [advisory]:
                            key = (pkg.name, pkg.evr, cve, fixed_evr)
                            if key in seen:
                                continue
                            seen.add(key)
                            findings.append(
                                Finding(
                                    host=inventory.hostname,
                                    os=inventory.os.pretty_name,
                                    package_name=pkg.name,
                                    installed_evr=pkg.evr,
                                    package_arch=pkg.arch,
                                    cve=cve if cve.startswith("CVE-") else "",
                                    status=FindingStatus.CONFIRMED_VULNERABLE,
                                    confidence="High; OSV Red Hat ecosystem fixed-EVR range",
                                    severity=normalize_severity(severity) if severity else "",
                                    description=summary or f"OSV advisory {advisory}",
                                    fixed_evr=fixed_evr,
                                    reason=(
                                        f"OSV Red Hat record {advisory}: installed {pkg.name} {pkg.evr} "
                                        f"is lower than fixed {fixed_evr} for ecosystem {ecosystem}."
                                    ),
                                    solution=f"Update {pkg.name} to {fixed_evr} or later per {advisory}.",
                                    evidence=Evidence(
                                        source=self.name,
                                        advisory=advisory,
                                        definition_id=advisory,
                                        feed_file=str(root / "all.zip"),
                                        reference="",
                                        evaluated_expression=f"{pkg.evr} < {fixed_evr}",
                                        raw={
                                            "ecosystem": ecosystem,
                                            "osv_id": advisory,
                                            "host_majors": sorted(majors),
                                        },
                                    ),
                                    references=[],
                                    source_rpm=pkg.source_rpm,
                                    package_vendor=pkg.vendor,
                                    package_packager=pkg.packager,
                                    install_time=pkg.install_time,
                                    running_kernel=inventory.running_kernel,
                                    review_required=False,
                                )
                            )
            if hit:
                matched_records += 1

        inventory.warnings.append(
            f"OSV Red Hat: scanned {scanned} records for majors={sorted(majors)}; "
            f"matched_records={matched_records}; findings={len(findings)}"
        )
        return findings
