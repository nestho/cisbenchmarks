from __future__ import annotations

import json
import re
from pathlib import Path

from .base import VendorAdapter
from .common import normalize_severity
from .debian_advisories import evaluate_advisory_history
from ..debver import compare_versions
from ..models import Evidence, Finding, FindingStatus, Inventory, Package


TRACKER_SOURCE = "Debian Security Tracker"
TRACKER_URL = "https://security-tracker.debian.org/tracker"


def _urgency(value: object) -> str:
    text = re.sub(r"[^a-z]", "", str(value or "").lower())
    if text == "unimportant":
        return "Low"
    return normalize_severity(text)


def _source_version(pkg: Package) -> str:
    return (pkg.source_version or pkg.native_version or pkg.version or "").strip()


def _binary_version(pkg: Package) -> str:
    return (pkg.native_version or pkg.version or "").strip()


def _release_note(inventory: Inventory, source: str, state: str) -> str:
    return (
        f"Debian Security Tracker source-package scope matched {source!r} for "
        f"Debian {inventory.os.version} ({inventory.os.codename}); tracker status={state}."
    )


class DebianSecurityTrackerAdapter(VendorAdapter):
    name = TRACKER_SOURCE

    def applicable(self, inventory: Inventory) -> bool:
        return (
            inventory.os.family == "debian"
            and inventory.os.product == "debian"
            and any((pkg.package_manager or "").lower() in {"deb", "dpkg"} for pkg in inventory.packages)
        )

    def evaluate(self, inventory: Inventory, feeds_root: Path) -> list[Finding]:
        path = feeds_root / "vendor" / "debian" / "security-tracker.json"
        if not inventory.os.codename:
            inventory.assessment.update(mode="unavailable", reason="Debian release codename is missing.")
            return []
        if not path.exists():
            return evaluate_advisory_history(inventory, feeds_root)
        with path.open("r", encoding="utf-8-sig") as handle:
            tracker = json.load(handle)
        if not isinstance(tracker, dict) or not tracker:
            raise ValueError("Debian Security Tracker root must be a nonempty object")

        findings: list[Finding] = []
        index = inventory.source_package_index()
        codename = inventory.os.codename.lower()
        if not any(
            isinstance(issue, dict) and isinstance(issue.get("releases"), dict) and codename in issue["releases"]
            for issues in tracker.values() if isinstance(issues, dict) for issue in issues.values()
        ):
            inventory.warnings.append(f"Debian tracker coverage: release {codename!r} is absent from the main JSON feed. Checking release-matched DSA/DLA/ELA advisories; full open-issue coverage is unavailable.")
            return evaluate_advisory_history(inventory, feeds_root)
        inventory.assessment.update(mode="tracker", source=self.name)
        for source_name, packages in index.items():
            issues = tracker.get(source_name)
            if not isinstance(issues, dict):
                continue
            by_source_version: dict[str, list[Package]] = {}
            for package in packages:
                if not package.metadata_complete or package.package_manager.lower() not in {"deb", "dpkg"}:
                    continue
                source_version = _source_version(package)
                if source_version:
                    by_source_version.setdefault(source_version, []).append(package)
            for cve, issue in issues.items():
                if not re.fullmatch(r"CVE-\d{4}-\d{4,}", str(cve), re.I) or not isinstance(issue, dict):
                    continue
                releases = issue.get("releases") or {}
                release = releases.get(codename) if isinstance(releases, dict) else None
                if not isinstance(release, dict):
                    continue
                tracker_status = str(release.get("status") or "").strip().lower()
                fixed_version = str(release.get("fixed_version") or "").strip()
                if tracker_status == "resolved" and fixed_version == "0":
                    continue

                for installed_source_version, matched in by_source_version.items():
                    status: FindingStatus
                    review = False
                    fixed = ""
                    if tracker_status == "resolved" and fixed_version:
                        fixed = fixed_version
                        if compare_versions(installed_source_version, fixed_version) >= 0:
                            continue
                        status = FindingStatus.CONFIRMED_VULNERABLE
                    elif tracker_status == "open":
                        if fixed_version and fixed_version != "0":
                            fixed = fixed_version
                            if compare_versions(installed_source_version, fixed_version) >= 0:
                                status = FindingStatus.NEEDS_VALIDATION
                                review = True
                            else:
                                status = FindingStatus.CONFIRMED_VULNERABLE
                        else:
                            status = FindingStatus.VENDOR_AFFECTED_NO_FIX
                    else:
                        status = FindingStatus.NEEDS_VALIDATION
                        review = True

                    binaries = list(dict.fromkeys(pkg.name for pkg in matched))
                    binary_versions = {pkg.name: _binary_version(pkg) for pkg in matched}
                    architectures = list(dict.fromkeys(pkg.arch for pkg in matched if pkg.arch))
                    tracker_reference = f"{TRACKER_URL}/{str(cve).upper()}"
                    references = [tracker_reference]
                    debian_bug = issue.get("debianbug")
                    if debian_bug:
                        references.append(f"https://bugs.debian.org/{debian_bug}")
                    scope_note = _release_note(inventory, source_name, tracker_status or "unknown")
                    custom = any(
                        re.search(r"onl|opennetworklinux|sinos|sina|accton|~bpo", f"{p.name} {p.vendor} {p.maintainer} {p.origin} {p.native_version}", re.I)
                        for p in matched
                    )
                    if custom:
                        status, review = FindingStatus.NEEDS_VALIDATION, True
                        scope_note += " Custom vendor build/backports provenance requires validation against its own vendor feed."
                    if inventory.os.codename in {"buster", "bullseye"}:
                        scope_note += " Public support lifecycle may have ended; absence of a tracker entry must not be interpreted as a clean result, and ELTS requires separate evidence."

                    if status == FindingStatus.CONFIRMED_VULNERABLE and fixed:
                        solution = f"Update all installed binaries built from Debian source package {source_name} to source version {fixed} or later for {codename}."
                    elif status == FindingStatus.VENDOR_AFFECTED_NO_FIX:
                        solution = f"Debian marks {source_name} open for {codename} without a fixed version. Apply vendor mitigation or an approved release update when available."
                    else:
                        solution = f"Validate the Debian tracker status and lifecycle scope for source package {source_name} before remediation."

                    findings.append(Finding(
                        host=inventory.hostname,
                        os=inventory.os.pretty_name,
                        package_name=source_name,
                        installed_evr=installed_source_version,
                        package_arch=", ".join(architectures),
                        cve=str(cve).upper(),
                        status=status,
                        confidence="High; Debian source package, release and version matched" if not review else "Medium; Debian tracker state requires validation",
                        severity=_urgency(release.get("urgency")),
                        description=str(issue.get("description") or ""),
                        fixed_evr=fixed,
                        reason=(
                            f"{scope_note} Installed source version {installed_source_version}; "
                            f"fixed version {fixed or 'not published'}."
                        ),
                        solution=solution,
                        evidence=Evidence(
                            source=self.name,
                            advisory="",
                            definition_id=str(cve).upper(),
                            feed_file=str(path),
                            reference=tracker_reference,
                            evaluated_expression=f"Debian source version {installed_source_version} vs fixed {fixed or 'none'}; release={codename}; status={tracker_status or 'unknown'}",
                            raw={
                                "package_manager": "dpkg",
                                "source_package": source_name,
                                "source_version": installed_source_version,
                                "release_codename": codename,
                                "tracker_status": tracker_status or "unknown",
                                "urgency": release.get("urgency", ""),
                                "repositories": release.get("repositories") or {},
                                "nodsa": release.get("nodsa") or "",
                                "nodsa_reason": release.get("nodsa_reason") or "",
                                "scope": issue.get("scope") or "",
                                "scope_note": scope_note,
                                "affected_platforms": [f"Debian GNU/Linux {inventory.os.version} ({codename})"],
                                "matched_binary_packages": binaries,
                                "installed_binary_versions": binary_versions,
                                "fixed_binary_versions": {name: fixed for name in binaries} if fixed else {},
                            },
                        ),
                        references=references,
                        source_rpm="",
                        package_vendor="Debian",
                        package_packager="",
                        install_time="",
                        running_kernel=inventory.running_kernel,
                        review_required=review,
                        package_manager="dpkg",
                        source_package=source_name,
                    ))
        return findings
