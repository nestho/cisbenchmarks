from __future__ import annotations

from pathlib import Path

from ..models import Evidence, Finding, FindingStatus, Inventory
from ..oval import OvalDocument


def normalize_severity(value: str) -> str:
    text = (value or "").strip().lower()
    if text in {"critical", "crit"}:
        return "Critical"
    if text in {"important", "high", "major"}:
        return "High"
    if text in {"moderate", "medium"}:
        return "Medium"
    if text in {"low", "minor"}:
        return "Low"
    return "Info"


def oval_findings(inventory: Inventory, path: Path, source: str) -> list[Finding]:
    document = OvalDocument(path)
    findings: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()
    evaluated = document.evaluate_all(inventory)
    stats = document.last_stats
    if stats.get("unknown") or stats.get("error"):
        inventory.warnings.append(
            f"{source} conservative evaluation for {path.name}: "
            f"TRUE={stats.get('true', 0)}, FALSE={stats.get('false', 0)}, "
            f"UNKNOWN={stats.get('unknown', 0)}, ERROR={stats.get('error', 0)}. "
            "The strict evaluator never converts UNKNOWN/ERROR to Confirmed; a vendor-specific adapter may separately report explicit fixed-package thresholds with its own evidence and review flag."
        )
    for definition in evaluated:
        cves = definition.cves or [""]
        for trace in definition.traces:
            if trace.result.value != "true" or trace.test_type not in {"rpminfo_test", "dpkginfo_test"}:
                continue
            # A fixed threshold is required before claiming a vendor-fixed package.
            # Product applicability tests usually have no less-than threshold and
            # therefore do not become package findings.
            if not trace.fixed_evr:
                continue
            for pkg in trace.matched_packages:
                for cve in cves:
                    key = (pkg.name, pkg.evr, cve, definition.definition_id)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(Finding(
                        host=inventory.hostname,
                        os=inventory.os.pretty_name,
                        package_name=pkg.name,
                        installed_evr=pkg.evr,
                        package_arch=pkg.arch,
                        cve=cve,
                        status=FindingStatus.CONFIRMED_VULNERABLE,
                        confidence="High",
                        severity=normalize_severity(definition.severity),
                        description=definition.description or definition.title,
                        fixed_evr=trace.fixed_evr,
                        reason=f"The complete vendor OVAL criteria tree evaluated TRUE. Installed {pkg.evr} satisfies '{trace.operation} {trace.fixed_evr}'.",
                        solution=f"Update {pkg.name} to vendor release {trace.fixed_evr} or a later release approved for {inventory.os.pretty_name}.",
                        evidence=Evidence(
                            source=source,
                            advisory=definition.advisory,
                            definition_id=definition.definition_id,
                            feed_file=str(path),
                            reference=definition.references[0] if definition.references else "",
                            evaluated_expression=definition.expression,
                        ),
                        references=definition.references,
                        source_rpm=pkg.source_rpm,
                        package_vendor=pkg.vendor,
                        package_packager=pkg.packager,
                        install_time=pkg.install_time,
                        running_kernel=inventory.running_kernel,
                        review_required=False,
                    ))
    return findings
