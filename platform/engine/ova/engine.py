from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field, replace
from pathlib import Path

from .adapters.debian import DebianSecurityTrackerAdapter
from .adapters.huawei import HuaweiAdapter
from .adapters.local_matrix import LocalMatrixAdapter
from .adapters.redhat import RedHatOvalAdapter
from .adapters.redhat_csaf import RedHatCsafAdapter
from .adapters.osv_redhat import OsvRedHatAdapter
from .adapters.oracle_java import OracleJavaAdapter
from .adapters.suse import SuseOvalAdapter
from .adapters.ubuntu import UbuntuOvalAdapter
from .coverage_registry import IMPLEMENTED
from .enrichment import enrich_findings
from .inventory import attach_inventory_context, parse_inventory
from .models import Evidence, Finding, FindingStatus, Inventory


@dataclass(slots=True)
class AnalysisResult:
    inventory: Inventory
    findings: list[Finding]
    coverage: list[dict]
    feed_status: list[dict] = field(default_factory=list)
    requested_os_family: str = "auto"
    detected_os_family: str = "unknown"
    detected_os_product: str = "unknown"
    assessment_state: str = "complete"
    assessment_reason: str = ""


OS_TARGETS: dict[str, tuple[str, str, str] | None] = {
    "auto": None,
    "redhat": ("redhat", "rhel", "Red Hat Enterprise Linux"),
    "rhel": ("redhat", "rhel", "Red Hat Enterprise Linux"),
    "suse": ("suse", "sles", "SUSE Linux Enterprise"),
    "sles": ("suse", "sles", "SUSE Linux Enterprise"),
    "debian": ("debian", "debian", "Debian GNU/Linux"),
    "huawei": ("huawei", "unknown", "Huawei EulerOS / HCE"),
    "ubuntu": ("ubuntu", "ubuntu", "Ubuntu"),
    "oracle": ("oracle", "oraclelinux", "Oracle Linux"),
    "oracle-linux": ("oracle", "oraclelinux", "Oracle Linux"),
    "rocky": ("redhat-compatible", "rocky", "Rocky Linux"),
    "alma": ("redhat-compatible", "almalinux", "AlmaLinux"),
    "almalinux": ("redhat-compatible", "almalinux", "AlmaLinux"),
    "centos": ("redhat-compatible", "centos", "CentOS"),
    "amazon": ("amazon-linux", "amazon-linux", "Amazon Linux"),
    "amazon-linux": ("amazon-linux", "amazon-linux", "Amazon Linux"),
    "fedora": ("fedora", "fedora", "Fedora"),
    "opensuse": ("opensuse", "opensuse", "openSUSE"),
    "alpine": ("alpine", "alpine", "Alpine Linux"),
    "arch": ("arch", "arch", "Arch Linux"),
    "mint": ("mint", "linuxmint", "Linux Mint"),
    "kali": ("kali", "kali", "Kali Linux"),
    "openeuler": ("openeuler", "openeuler", "openEuler"),
}


def normalize_os_target(value: str | None) -> str:
    target = (value or "auto").strip().lower()
    if target not in OS_TARGETS:
        choices = ", ".join(sorted(OS_TARGETS))
        raise ValueError(f"Unsupported OS selection {value!r}. Choose one of: {choices}")
    aliases = {"rhel": "redhat", "sles": "suse", "oracle-linux": "oracle", "almalinux": "alma", "amazon-linux": "amazon"}
    return aliases.get(target, target)


def _apply_os_target(inventory: Inventory, target: str) -> tuple[str, str]:
    """Apply an explicit analysis scope while retaining collected OS evidence."""
    detected_family = inventory.os.family
    detected_product = inventory.os.product
    selected = OS_TARGETS[target]
    if selected is None:
        return detected_family, detected_product
    family, product, label = selected
    if target == "huawei" and detected_family == "huawei" and detected_product in {"hce", "euleros"}:
        product = detected_product
    inventory.os.family = family
    inventory.os.product = product
    if (detected_family, detected_product) != (family, product):
        inventory.warnings.append(
            f"Manual OS scope {label} overrides collector detection "
            f"{detected_family}/{detected_product}. Vendor findings use the manual selection; "
            "the mismatch remains a coverage limitation."
        )
    return detected_family, detected_product


def _coverage(
    inventory: Inventory,
    feeds_root: Path,
    *,
    requested_os_family: str = "auto",
    detected_os_family: str = "unknown",
    detected_os_product: str = "unknown",
) -> list[dict]:
    rows: list[dict] = []
    family = inventory.os.family
    product = inventory.os.product
    major = inventory.os.major
    selected = OS_TARGETS.get(requested_os_family)
    selected_label = selected[2] if selected else "Automatic detection"
    selected_scope = f"{family}/{product}"
    detected_scope = f"{detected_os_family}/{detected_os_product}"
    selection_status = "Auto-detected" if requested_os_family == "auto" else "Manually selected"
    selection_detail = f"Mode={selected_label}; analysis scope={selected_scope}; collector detection={detected_scope}."
    if requested_os_family != "auto" and selected_scope != detected_scope:
        selection_status = "Manual override - mismatch"
        selection_detail += " Only the manually selected vendor adapter was evaluated; verify that this choice matches the host."
    rows.append({"Area": "Operating system selection", "Status": selection_status, "Detail": selection_detail})
    if not inventory.packages and not inventory.software:
        rows.append({"Area": "Inventory", "Status": "Analysis incomplete", "Detail": "No valid installed packages or standalone software were collected; vulnerability assessment could not be performed."})
    package_managers = sorted({(pkg.package_manager or "rpm").lower() for pkg in inventory.packages})
    expected_manager = "dpkg" if family == "debian" else "rpm" if family in {"redhat", "suse", "huawei"} else ""
    if expected_manager:
        compatible = expected_manager in package_managers or (expected_manager == "dpkg" and "deb" in package_managers)
        rows.append({
            "Area": "Package manager scope",
            "Status": "Compatible" if compatible else "Mismatch / no eligible packages",
            "Detail": f"Selected OS family requires {expected_manager}; collected package managers={package_managers or ['none']}. Incompatible packages are never compared with the selected vendor's version algorithm.",
        })
    if family == "suse":
        paths = [
            feeds_root / "vendor" / "suse" / f"suse.linux.enterprise.server.{major}.xml.gz",
            feeds_root / "vendor" / "suse" / f"suse.linux.enterprise.{major}.xml.gz",
        ]
        present = [str(x) for x in paths if x.exists()]
        rows.append({"Area": "Vendor vulnerability source", "Status": "Feed present" if present else "Missing", "Detail": "SUSE OVAL: " + (", ".join(present) if present else "no matching major-version feed") + ". Confirmation occurs only when the full supported criteria path evaluates TRUE; unsupported tests remain UNKNOWN."})
    elif family == "redhat" and product == "rhel":
        folder = feeds_root / "vendor" / "redhat" / f"RHEL{major}"
        base = folder / f"rhel-{major}.oval.xml.bz2"
        minor = inventory.os.minor
        stream_paths = [folder / f"rhel-{major}.{minor}-{x}.oval.xml.bz2" for x in ("aus", "e4s", "eus", "tus")] if minor else []
        present_streams = [x.name for x in stream_paths if x.exists()]
        selected_paths = RedHatOvalAdapter()._select(inventory, feeds_root)
        rows.append({"Area": "Vendor vulnerability source", "Status": "Feed present" if selected_paths else "Missing", "Detail": f"Red Hat OVAL base={base.exists()}; exact minor stream feeds={present_streams or 'none'}; applicable feeds={[p.name for p in selected_paths] or 'none'}. Strict OVAL is preferred; an explicit RPM fixed-threshold fallback is used when product/signature/repository criteria are UNKNOWN."})
        rows.append({"Area": "Red Hat repository stream", "Status": "Configuration collected" if inventory.repository_evidence else "Not collected", "Detail": "AUS/E4S/EUS/TUS feed selection uses explicit enabled=true repository configuration or its repository-to-CPE mapping. Effective runtime state and entitlement were not queried. Missing or conflicting enabled values are unknown, not disabled."})
        csaf_dir = feeds_root / "vendor" / "redhat" / "csaf"
        csaf_json = list(csaf_dir.rglob("*.json")) if csaf_dir.exists() else []
        index_present = (csaf_dir / "index.txt").exists()
        major_i = int(major) if major and major.isdigit() else 0
        if major_i >= 10:
            csaf_status = "Feed present" if csaf_json else "Missing"
            csaf_detail = (
                f"RHEL {major} requires CSAF. Local CSAF JSON files={len(csaf_json)}; "
                f"index.txt={'yes' if index_present else 'no'}. Place advisory JSON under vendor/redhat/csaf/."
            )
        else:
            csaf_status = "Optional supplement" if csaf_json else ("Index present" if index_present else "Index missing")
            csaf_detail = (
                f"OVAL remains primary for RHEL {major or '?'}. CSAF JSON files={len(csaf_json)} "
                "(used when present for explicit fixed RPM remediations)."
            )
        rows.append({"Area": "Red Hat CSAF", "Status": csaf_status, "Detail": csaf_detail})
    elif family == "debian" and product == "debian":
        path = feeds_root / "vendor" / "debian" / "security-tracker.json"
        codename = (inventory.os.codename or "").strip().lower()
        mapped = sum(1 for pkg in inventory.packages if pkg.metadata_complete and pkg.source_package)
        rows.append({
            "Area": "Vendor vulnerability source",
            "Status": "Feed present" if path.exists() else "Missing",
            "Detail": (
                f"Debian Security Tracker JSON: {path}. Matching is by Debian release codename and "
                "source-package/source-version; binary package names alone are not treated as proof."
            ),
        })
        rows.append({
            "Area": "Debian release scope",
            "Status": "Collected" if codename else "Missing codename",
            "Detail": f"Release codename={codename or 'not collected'}; source mappings={mapped}/{len(inventory.packages)} installed packages.",
        })
        if codename in {"buster", "bullseye"}:
            rows.append({
                "Area": "Debian lifecycle",
                "Status": "Public support ended / ELTS evidence required",
                "Detail": (
                    f"Debian {codename} is outside the public security lifecycle used by this feed snapshot. "
                    "Known tracker issues may still be reported, but absence of a finding is not a clean bill of health; ELTS requires separate entitlement evidence."
                ),
            })
        elif codename:
            rows.append({
                "Area": "Debian lifecycle",
                "Status": "Release identified",
                "Detail": f"The report is scoped to the tracker release key {codename!r}; package-level LTS support exclusions may still apply.",
            })
        custom_tokens = ("opennetworklinux", "onl", "sinos", "sina", "accton")
        custom_packages = [
            pkg for pkg in inventory.packages
            if any(token in f"{pkg.name} {pkg.vendor} {pkg.maintainer} {pkg.origin}".lower() for token in custom_tokens)
        ]
        custom_kernel = any(token in (inventory.running_kernel or "").lower() for token in custom_tokens)
        if custom_packages or custom_kernel:
            rows.append({
                "Area": "Derivative / custom components",
                "Status": "Coverage gap",
                "Detail": (
                    f"Detected {len(custom_packages)} likely SiNOS/ONL/vendor package(s)"
                    f"{' and a custom running kernel' if custom_kernel else ''}. Debian tracker data cannot prove coverage for vendor-rebuilt packages, hardware SDKs, or custom kernels; obtain their vendor advisories/SBOM."
                ),
            })
        rows.append({
            "Area": "Debian repository/support evidence",
            "Status": "Collected" if inventory.repository_evidence else "Not collected",
            "Detail": "APT source configuration and debian-security-support/check-support-status evidence are needed to validate archive, backports, LTS and unsupported-package scope.",
        })
    elif family == "huawei":
        if product == "hce":
            path = feeds_root / "vendor" / "huawei" / "hce" / f"{major or '2'}.0" / f"HCE{major or '2'}-SA.xml"
            rows.append({"Area": "Vendor vulnerability source", "Status": "Feed present" if path.exists() else "Missing", "Detail": f"Huawei HCE advisory XML: {path}. Package exposure is confirmed only from an applicable advisory with an explicit fixed/minimum EVR."})
        else:
            sources = feeds_root / "vendor" / "huawei" / "euleros" / "sources.csv"
            scoped = 0
            if sources.exists():
                actual = re.sub(r"[^a-z0-9]+", "", (inventory.os.version or "").lower())
                try:
                    with sources.open("r", encoding="utf-8-sig", newline="") as fh:
                        for row in csv.DictReader(fh):
                            target = re.sub(r"[^a-z0-9]+", "", (row.get("os_version") or "").lower())
                            if row.get("advisory") and row.get("version") and target and target == actual:
                                scoped += 1
                except Exception:
                    scoped = 0
            rows.append({"Area": "Vendor vulnerability source", "Status": "Configured" if scoped else "Missing scope", "Detail": f"EulerOS matching source rows={scoped}. sources.csv must contain advisory, API version, and exact collector os_version. Only matching scoped CVRF/CSAF documents and explicit fixed/minimum package EVRs are actionable: {sources}"})
    elif family == "ubuntu":
        code = (inventory.os.codename or "").split("-")[0].lower()
        usn = feeds_root / "vendor" / "ubuntu" / f"com.ubuntu.{code}.usn.oval.xml.bz2"
        cve = feeds_root / "vendor" / "ubuntu" / f"com.ubuntu.{code}.cve.oval.xml.bz2"
        present = (usn.exists() and usn.stat().st_size > 0) or (cve.exists() and cve.stat().st_size > 0)
        rows.append({
            "Area": "Vendor vulnerability source",
            "Status": "Feed present" if present else "Missing",
            "Detail": (
                f"Ubuntu OVAL codename={code or 'unknown'}; USN={usn.name} exists={usn.exists()}; "
                f"CVE={cve.name} exists={cve.exists()}. Only dpkginfo fixed-threshold TRUE results become Confirmed findings."
            ),
        })
    else:
        rows.append({
            "Area": "Vendor vulnerability source",
            "Status": "Unsupported / feed required",
            "Detail": (
                f"No confirmed vendor adapter is enabled for {inventory.os.pretty_name or inventory.os.family} "
                f"(selected scope {family}/{product}). Local approved rules may still produce findings, but zero vendor findings must not be interpreted as clean."
            ),
        })
    if inventory.software:
        rows.append({"Area": "Standalone software inventory", "Status": "Collected", "Detail": f"Detected {len(inventory.software)} standalone/bundled software component(s), including Java release metadata when supplied by the optional extended collector."})
    else:
        rows.append({"Area": "Standalone software inventory", "Status": "Not collected", "Detail": "Package inventory does not include every bundled runtime. Use COLLECTOR_COMMANDS_EXTENDED_SOFTWARE_OPTIONAL.txt when standalone Java/application discovery is required."})
    rows.extend([
        {"Area": "Evaluation safety", "Status": "Conservative", "Detail": "Vendor product scope and package-manager-native versions are evaluated. Unsupported criteria, version schemes, signatures, or lifecycle evidence return UNKNOWN/review and cannot create a Confirmed finding."},
        {"Area": "NVD", "Status": "Enrichment only", "Detail": "NVD is used for description/CVSS/CWE/references after a vendor/local finding. It is not used for fuzzy package-to-CVE confirmation."},
        {"Area": "CISA KEV", "Status": "Prioritization only", "Detail": "KEV does not prove package exposure."},
        {"Area": "EPSS", "Status": "Prioritization only", "Detail": "EPSS does not prove package exposure."},
    ])
    return rows


def _dedupe(findings: list[Finding]) -> list[Finding]:
    precedence = {
        "Approved Patch Matrix": 100,
        "Huawei CSAF": 90,
        "Huawei CVRF": 90,
        "Huawei HCE Security Advisory": 90,
        "Huawei OVAL": 90,
        "SUSE OVAL": 90,
        "Red Hat OVAL": 95,
        "Red Hat OVAL Package Threshold": 92,
        "Red Hat CSAF": 93,
        "Ubuntu OVAL": 95,
        "Debian Security Tracker": 95,
        "Debian DSA/DLA Advisory": 94,
        "Freexian ELTS Advisory": 94,
        "Oracle Java CPU Rules": 92,
    }
    out: dict[tuple[str, str, str, str, str], Finding] = {}
    for finding in findings:
        key = (finding.host, finding.package_name, finding.installed_evr, finding.package_arch, finding.cve)
        old = out.get(key)
        if old is None:
            out[key] = finding
            continue
        new_rank = precedence.get(finding.evidence.source, 0)
        old_rank = precedence.get(old.evidence.source, 0)
        if new_rank > old_rank:
            out[key] = finding
            continue
        if new_rank < old_rank:
            continue
        if old.fixed_evr == finding.fixed_evr and old.status == finding.status:
            old.references = list(dict.fromkeys(old.references + finding.references))
            for raw_key, value in (finding.evidence.raw or {}).items():
                existing = old.evidence.raw.get(raw_key)
                if isinstance(existing, list) and isinstance(value, list):
                    old.evidence.raw[raw_key] = list(dict.fromkeys(existing + value))
                elif isinstance(existing, dict) and isinstance(value, dict):
                    old.evidence.raw[raw_key] = {**existing, **value}
                elif existing is None or existing == "" or existing is False:
                    old.evidence.raw[raw_key] = value
            if finding.review_required:
                old.review_required = True
                old.confidence = finding.confidence
            continue
        sources = [
            f"{old.evidence.source} [{old.evidence.advisory or old.evidence.definition_id}] fixed={old.fixed_evr or 'unspecified'}",
            f"{finding.evidence.source} [{finding.evidence.advisory or finding.evidence.definition_id}] fixed={finding.fixed_evr or 'unspecified'}",
        ]
        out[key] = replace(
            old,
            status=FindingStatus.NEEDS_VALIDATION,
            confidence="Low",
            fixed_evr="",
            reason="Conflicting equal-priority vendor decisions were found: " + " | ".join(sources),
            solution="Resolve product/repository applicability and select the authoritative vendor advisory before remediation.",
            evidence=Evidence(
                source="Conflicting vendor evidence",
                advisory="; ".join(x for x in [old.evidence.advisory, finding.evidence.advisory] if x),
                feed_file="; ".join(x for x in [old.evidence.feed_file, finding.evidence.feed_file] if x),
                evaluated_expression="CONFLICT: " + " | ".join(sources),
            ),
            references=list(dict.fromkeys(old.references + finding.references)),
            review_required=True,
        )
    return sorted(out.values(), key=lambda x: (x.status.value, x.severity, x.package_name, x.cve))


def analyze_inventory(
    input_path: str | Path,
    feeds_root: str | Path,
    *,
    enrich: bool = True,
    target_os_family: str = "auto",
    inventory_context: str | Path | None = None,
    log=print,
) -> AnalysisResult:
    inventory = parse_inventory(input_path)
    if inventory_context:
        inventory = attach_inventory_context(inventory, inventory_context)
    target = normalize_os_target(target_os_family)
    detected_family, detected_product = _apply_os_target(inventory, target)
    feeds = Path(feeds_root)
    log(
        f"[HOST] {inventory.hostname} | detected={detected_family}/{detected_product} "
        f"| analysis={inventory.os.family}/{inventory.os.product} "
        f"| version={inventory.os.version or inventory.os.major or '?'} "
        f"| arch={inventory.os.architecture or '?'} "
        f"| packages={len(inventory.packages)} software={len(inventory.software)}"
    )
    if inventory.packages:
        sample = inventory.packages[0]
        log(
            f"[PKG0] name={sample.name} manager={sample.package_manager} "
            f"evr={sample.evr} arch={sample.arch} complete={sample.metadata_complete}"
        )
    else:
        log("[WARN] No packages parsed — check collector markers (RPM_INVENTORY_NEVRA / DPKG_INVENTORY).")
    adapters = [
        LocalMatrixAdapter(),
        SuseOvalAdapter(),
        RedHatOvalAdapter(),
        RedHatCsafAdapter(),
        OsvRedHatAdapter(),
        DebianSecurityTrackerAdapter(),
        UbuntuOvalAdapter(),
        HuaweiAdapter(),
        OracleJavaAdapter(),
    ]
    findings: list[Finding] = []
    missing_metadata = any(not pkg.metadata_complete for pkg in inventory.packages)
    state, reason = "complete", ""
    # Hard gate: selected / detected family has no vendor adapter → inventory-only
    analysis_family = inventory.os.family
    if analysis_family not in IMPLEMENTED and analysis_family not in {"unknown", ""}:
        state = "incomplete"
        reason = (
            f"No vendor adapter for OS family {analysis_family!r}. "
            f"Implemented families: {', '.join(sorted(IMPLEMENTED))}. "
            "Inventory may be reported; confirmed vulnerability assessment is not available."
        )
        inventory.warnings.append(reason)
        log(f"[ASSESSMENT] incomplete: {reason}")
    if missing_metadata:
        state = "incomplete"
        reason = "Package names and versions were imported, but OS release/source/architecture evidence is missing. Select a matching full collector in Metadata collector."
    elif not inventory.packages and not inventory.software:
        state, reason = "incomplete", "No usable inventory rows. Check the input format."
    for adapter in adapters:
        if state == "incomplete":
            break
        if not adapter.applicable(inventory):
            continue
        log(f"[+] Evaluating {adapter.name}")
        try:
            # Keep the report's complete inventory; vendor evaluators see only
            # packages belonging to their own native version scheme.
            scoped_inventory = inventory
            if isinstance(adapter, (DebianSecurityTrackerAdapter, UbuntuOvalAdapter)):
                scoped_inventory = replace(inventory, packages=[p for p in inventory.packages if p.package_manager.lower() in {"deb", "dpkg"}])
            elif isinstance(adapter, (SuseOvalAdapter, RedHatOvalAdapter, RedHatCsafAdapter, OsvRedHatAdapter, HuaweiAdapter)):
                scoped_inventory = replace(inventory, packages=[p for p in inventory.packages if p.package_manager.lower() == "rpm"])
            rows = adapter.evaluate(scoped_inventory, feeds)
            log(f"[OK] {adapter.name}: {len(rows)} vendor/local decisions")
            findings.extend(rows)
            # Surface adapter diagnostics that were attached as warnings during evaluate
            for w in inventory.warnings[-5:]:
                if adapter.name.split()[0] in w or "OVAL" in w or "CSAF" in w or "feed" in w.lower():
                    log(f"[INFO] {w}")
        except Exception as exc:
            message = f"{adapter.name} failed: {exc}"
            state, reason = "incomplete", message
            inventory.warnings.append(message)
            log(f"[WARN] {message}")
    if target != "auto" and (detected_family, detected_product) != (inventory.os.family, inventory.os.product):
        for finding in findings:
            finding.status = FindingStatus.NEEDS_VALIDATION
            finding.review_required = True
            finding.confidence = "Low; selected OS differs from collected evidence"
            note = f"Selected OS {inventory.os.family}/{inventory.os.product} differs from collector evidence {detected_family}/{detected_product}; validate target selection."
            finding.reason = f"{note} {finding.reason}"
            finding.evidence.raw["scope_note"] = f"{note} {finding.evidence.raw.get('scope_note', '')}".strip()
    findings = _dedupe(findings)
    if enrich and findings:
        enrich_findings(findings, feeds, log=log)
    coverage = _coverage(
        inventory, feeds, requested_os_family=target,
        detected_os_family=detected_family, detected_os_product=detected_product,
    )
    try:
        _major = int(inventory.os.major or 0)
    except ValueError:
        _major = 0
    if inventory.os.family == "redhat" and inventory.os.product == "rhel" and _major == 7:
        coverage.append({
            "Area": "Lifecycle / support status",
            "Status": "Warning",
            "Detail": (
                "RHEL 7 Maintenance Support ended 30 Jun 2024; ELS (if entitled) ends 30 Jun 2028. "
                "Vendor OVAL may report packages fixed while the platform is outside full support. "
                "Third-party RPMs (ERIC*, VRTS*) need separate vendor advisories or a local matrix."
            ),
        })
    elif inventory.os.family == "redhat" and inventory.os.product == "rhel" and _major == 8:
        coverage.append({
            "Area": "Lifecycle / support status",
            "Status": "Info",
            "Detail": "RHEL 8 full support window depends on minor/EUS; verify entitlement.",
        })

    for warning in inventory.warnings:
        if "failed:" in warning or "could not be evaluated" in warning or "Debian tracker coverage:" in warning:
            coverage.append({"Area": "Evaluation coverage", "Status": "Incomplete", "Detail": warning})
    if inventory.assessment.get("mode") in {"historical", "advisories"}:
        if state != "incomplete":
            state, reason = "partial", inventory.assessment["reason"]
        coverage.append({"Area": "Debian advisory assessment", "Status": "Partial", "Detail": f"{inventory.assessment.get('source')}; last applicable advisory: {inventory.assessment.get('latest_advisory')}; {inventory.assessment.get('evaluated_packages', 0)} input packages map to sources listed in this release's advisories. {reason}"})
    elif inventory.assessment.get("mode") == "unavailable":
        state, reason = "incomplete", inventory.assessment["reason"]
    elif state == "complete" and any(row.get("Area") in {"Vendor vulnerability source", "Package manager scope", "Red Hat CSAF"} and row.get("Status") in {"Missing", "Missing scope", "Unsupported / feed required", "Mismatch / no eligible packages"} for row in coverage):
        state, reason = "incomplete", "No applicable vendor source/package scope is available for this inventory."
    no_feed_warnings = [
        w for w in inventory.warnings
        if "no feed selected" in w.lower()
        or "required base feed missing" in w.lower()
        or "OVAL feed missing" in w
        or "no local CSAF" in w
    ]
    if state == "complete" and no_feed_warnings:
        state, reason = "incomplete", no_feed_warnings[0]
    if state == "complete" and not findings and not inventory.packages:
        state, reason = "incomplete", "No packages were parsed; zero findings is not a clean assessment."
    failed = [row["Detail"] for row in coverage if row.get("Area") == "Evaluation coverage" and row.get("Status") == "Incomplete" and "Debian tracker coverage:" not in row.get("Detail", "")]
    if failed:
        state, reason = "incomplete", " ".join(failed)
    if state == "complete" and target != "auto" and (detected_family, detected_product) != (inventory.os.family, inventory.os.product):
        state, reason = "partial", "The selected OS differs from collected OS evidence."
    if missing_metadata:
        coverage.append({"Area": "Package metadata", "Status": "Incomplete", "Detail": reason})
    log(f"[ASSESSMENT] {state}: {reason or 'vendor evaluation completed'}")
    return AnalysisResult(
        inventory=inventory,
        findings=findings,
        coverage=coverage,
        requested_os_family=target,
        detected_os_family=detected_family,
        detected_os_product=detected_product,
        assessment_state=state,
        assessment_reason=reason,
    )
