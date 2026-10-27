from __future__ import annotations

import csv
import re
from pathlib import Path

from .base import VendorAdapter
from ..models import Evidence, Finding, FindingStatus, Inventory


def _version_tuple(value: str) -> tuple[int, ...]:
    nums = [int(x) for x in re.findall(r"\d+", value or "")]
    return tuple(nums or [0])


def _lt(left: str, right: str) -> bool:
    a, b = list(_version_tuple(left)), list(_version_tuple(right))
    n = max(len(a), len(b))
    a += [0] * (n - len(a))
    b += [0] * (n - len(b))
    return tuple(a) < tuple(b)


class OracleJavaAdapter(VendorAdapter):
    name = "Oracle Java CPU Rules"

    def applicable(self, inventory: Inventory) -> bool:
        return any(x.product.lower().startswith("java") for x in inventory.software)

    def evaluate(self, inventory: Inventory, feeds_root: Path) -> list[Finding]:
        path = feeds_root / "vendor" / "oracle" / "java_cpu_rules.csv"
        if not path.exists():
            return []
        rules: list[dict[str, str]] = []
        with path.open("r", encoding="utf-8-sig", newline="") as fh:
            rules = list(csv.DictReader(fh))
        findings: list[Finding] = []
        for sw in inventory.software:
            if not sw.product.lower().startswith("java"):
                continue
            if "oracle" not in (sw.vendor or "").lower():
                continue
            major = str(_version_tuple(sw.version)[0])
            for rule in rules:
                if (rule.get("major") or "").strip() != major:
                    continue
                fixed = (rule.get("fixed_version") or "").strip()
                if not fixed or not _lt(sw.version, fixed):
                    continue
                cves = [x.strip().upper() for x in (rule.get("cves") or "").split(";") if x.strip()]
                for cve in cves or [""]:
                    findings.append(Finding(
                        host=inventory.hostname,
                        os=inventory.os.pretty_name,
                        package_name=f"Oracle Java SE ({sw.path})",
                        installed_evr=sw.version,
                        package_arch=sw.architecture,
                        cve=cve,
                        status=FindingStatus.CONFIRMED_VULNERABLE,
                        confidence="High",
                        severity=(rule.get("severity") or "Critical").strip().title(),
                        description=(rule.get("description") or rule.get("advisory") or "Oracle Java SE security update required").strip(),
                        fixed_evr=fixed,
                        reason=f"Standalone/bundled Oracle Java detected at {sw.path}; installed version {sw.version} is below Oracle CPU fixed version {fixed} for Java {major}.",
                        solution=f"Update the bundled Oracle Java runtime at {sw.path} to {fixed} or later, following the vendor/application compatibility guidance.",
                        evidence=Evidence(
                            source=self.name,
                            advisory=(rule.get("advisory") or "").strip(),
                            feed_file=str(path),
                            reference=(rule.get("reference") or "").strip(),
                            evaluated_expression=f"Oracle Java {sw.version} < {fixed}; path={sw.path}",
                        ),
                        references=[(rule.get("reference") or "").strip()] if (rule.get("reference") or "").strip() else [],
                        running_kernel=inventory.running_kernel,
                    ))
        return findings
