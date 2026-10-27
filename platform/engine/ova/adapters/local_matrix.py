from __future__ import annotations

import csv
from pathlib import Path

from .base import VendorAdapter
from .common import normalize_severity
from ..debver import compare_versions as compare_debian_versions
from ..models import Evidence, Finding, FindingStatus, Inventory
from ..rpmver import compare_evr


class LocalMatrixAdapter(VendorAdapter):
    name = "Approved Patch Matrix"

    def applicable(self, inventory: Inventory) -> bool:
        return True

    @staticmethod
    def _scope(value: str, actual: str) -> bool:
        value = (value or "").strip().lower()
        return not value or value == "*" or value == (actual or "").strip().lower()

    def evaluate(self, inventory: Inventory, feeds_root: Path) -> list[Finding]:
        path = feeds_root / "local_rules" / "approved_patch_matrix.csv"
        if not path.exists():
            return []
        index = inventory.package_index()
        source_index = inventory.source_package_index()
        findings: list[Finding] = []
        with path.open("r", encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh):
                if not self._scope(row.get("os_family", ""), inventory.os.family):
                    continue
                if not self._scope(row.get("os_product", ""), inventory.os.product):
                    continue
                if not self._scope(row.get("os_version", ""), inventory.os.version):
                    continue
                package_name = (row.get("package_name") or "").strip().lower()
                source_package_rule = (row.get("source_package") or "").strip().lower()
                if not package_name and not source_package_rule:
                    continue
                candidates = source_index.get(source_package_rule, []) if source_package_rule else index.get(package_name, [])
                for pkg in candidates:
                    if not pkg.metadata_complete or (package_name and pkg.name.lower() != package_name):
                        continue
                    manager = (pkg.package_manager or "rpm").strip().lower()
                    if manager not in {"rpm", "deb", "dpkg"}:
                        continue
                    manager_scope = (row.get("package_manager") or "").strip().lower()
                    allowed_managers = {"deb", "dpkg"} if manager in {"deb", "dpkg"} else {manager}
                    if manager_scope and manager_scope != "*" and manager_scope not in allowed_managers:
                        continue
                    arch = (row.get("arch") or "").strip()
                    if arch and arch != "*" and arch != pkg.arch:
                        continue
                    source_rule = (row.get("source_rpm") or "").strip().lower()
                    if source_rule and source_rule != "*":
                        actual_full = (pkg.source_rpm or "").strip().lower()
                        actual_base = actual_full.removesuffix(".src.rpm").removesuffix(".nosrc.rpm")
                        expected_base = source_rule.removesuffix(".src.rpm").removesuffix(".nosrc.rpm")
                        if source_rule != actual_full and expected_base != actual_base:
                            continue
                    is_debian = manager in {"deb", "dpkg"}
                    version_scheme = (row.get("version_scheme") or "").strip().lower()
                    installed = pkg.source_installed_version if source_package_rule else pkg.installed_version
                    fixed = ""
                    unsafe_version_rule = False
                    if is_debian:
                        candidate_fixed = (row.get("fixed_package_version") or "").strip()
                        if not candidate_fixed and version_scheme in {"debian", "dpkg"}:
                            candidate_fixed = (row.get("fixed_version") or "").strip()
                        if candidate_fixed and version_scheme in {"debian", "dpkg"}:
                            fixed = candidate_fixed
                        elif candidate_fixed or row.get("fixed_version") or row.get("fixed_epoch") or row.get("fixed_release"):
                            unsafe_version_rule = True
                    elif row.get("fixed_version"):
                        fixed = f"{row.get('fixed_epoch') or '0'}:{row['fixed_version']}"
                        if row.get("fixed_release"):
                            fixed += f"-{row['fixed_release']}"
                    declared = (row.get("status") or "affected").strip().lower()
                    if declared in {"not_affected", "not affected"}:
                        status = FindingStatus.FIXED_NOT_VULNERABLE
                        reason = "Approved matrix explicitly marks this package/product as not affected."
                    elif unsafe_version_rule:
                        status = FindingStatus.NEEDS_VALIDATION
                        reason = "The approved matrix contains a fixed-version rule but does not explicitly declare the Debian/dpkg version scheme; it was not compared as RPM or SemVer."
                    elif fixed:
                        cmpv = compare_debian_versions(installed, fixed) if is_debian else compare_evr(installed, fixed)
                        status = FindingStatus.CONFIRMED_VULNERABLE if cmpv < 0 else FindingStatus.FIXED_NOT_VULNERABLE
                        version_label = "Debian version" if is_debian else "EVR"
                        reason = f"Installed {version_label} {installed} is {'older than' if cmpv < 0 else 'equal to or newer than'} approved fixed {version_label} {fixed}."
                    else:
                        status = FindingStatus.VENDOR_AFFECTED_NO_FIX
                        reason = "Approved matrix marks the package affected but does not provide a fixed package version."
                    findings.append(Finding(
                        host=inventory.hostname,
                        os=inventory.os.pretty_name,
                        package_name=pkg.name,
                        installed_evr=installed,
                        package_arch=pkg.arch,
                        cve=(row.get("cve") or "").strip().upper(),
                        status=status,
                        confidence=(row.get("confidence") or "High").title(),
                        severity=normalize_severity(row.get("severity", "")),
                        cvss=(row.get("cvss") or "").strip(),
                        fixed_evr=fixed,
                        reason=reason,
                        solution=(f"Update to approved fixed package version {fixed} or later." if status == FindingStatus.CONFIRMED_VULNERABLE and fixed else "Follow the approved vendor/project remediation decision."),
                        evidence=Evidence(
                            source=self.name,
                            advisory=(row.get("advisory") or "").strip(),
                            feed_file=str(path),
                            reference=(row.get("reference") or "").strip(),
                            raw={
                                "package_manager": manager,
                                "version_scheme": version_scheme or ("rpm" if not is_debian else "unspecified"),
                                "source_package": pkg.source_name,
                            },
                        ),
                        references=[x for x in [(row.get("reference") or "").strip()] if x],
                        source_rpm=pkg.source_rpm,
                        package_vendor=pkg.vendor,
                        package_packager=pkg.packager,
                        install_time=pkg.install_time,
                        running_kernel=inventory.running_kernel,
                        review_required=status == FindingStatus.NEEDS_VALIDATION,
                        package_manager=manager,
                        source_package=pkg.source_name,
                    ))
        return findings
