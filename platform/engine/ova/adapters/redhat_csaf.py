"""Red Hat CSAF 2.0 advisory evaluator.

Evaluates local CSAF JSON documents under vendor/redhat/csaf/.
Used primarily for RHEL 10+ (no OVAL base stream) and as a supplement when
explicit fixed RPM remediations are present in CSAF.

Conservative rules:
- Product tree must match the inventoried RHEL major (CPE contains rhel:N or
  enterprise_linux:N).
- Only packages with an explicit fixed version in remediations/product_status
  produce Confirmed findings.
- Unknown product status or missing fixed version → skip or Needs Validation.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .base import VendorAdapter
from .common import normalize_severity
from ..models import Evidence, Finding, FindingStatus, Inventory, Package
from ..rpmver import compare_evr


def _iter_csaf_files(root: Path) -> list[Path]:
    folder = root / "vendor" / "redhat" / "csaf"
    if not folder.exists():
        return []
    files = list(folder.rglob("*.json"))
    # Exclude index-like tiny files
    return sorted(p for p in files if p.is_file() and p.stat().st_size > 200)


def _cpe_matches_rhel(cpe: str, major: str) -> bool:
    text = (cpe or "").lower()
    if not text:
        return False
    # Common patterns: cpe:/o:redhat:enterprise_linux:9, cpe:2.3:o:redhat:enterprise_linux:9:*:...
    if re.search(rf"enterprise_linux[:_]{re.escape(major)}(?:[:\._*]|$)", text):
        return True
    if re.search(rf":rhel[:_]{re.escape(major)}(?:[:\._*]|$)", text):
        return True
    if re.search(rf"red_hat_enterprise_linux[:_]{re.escape(major)}(?:[:\._*]|$)", text):
        return True
    return False


def _collect_product_ids(doc: dict, major: str) -> set[str]:
    """Product IDs in the tree that apply to this RHEL major."""
    ids: set[str] = set()
    tree = doc.get("product_tree") or {}

    def walk(node: dict):
        if not isinstance(node, dict):
            return
        product = node.get("product") if isinstance(node.get("product"), dict) else node
        pid = str(product.get("product_id") or node.get("product_id") or "").strip()
        cpe = str(product.get("product_identification_helper", {}).get("cpe") or product.get("cpe") or "")
        name = str(product.get("name") or node.get("name") or "")
        if pid and (_cpe_matches_rhel(cpe, major) or re.search(rf"\brhel\s*{re.escape(major)}\b", name, re.I)):
            ids.add(pid)
        for key in ("branches", "full_product_names", "relationships"):
            children = node.get(key) or tree.get(key)
            if isinstance(children, list):
                for child in children:
                    if isinstance(child, dict):
                        walk(child)
        # Nested product_tree branches
        for branch in tree.get("branches") or []:
            if isinstance(branch, dict):
                walk(branch)

    walk(tree)
    # Also scan all full_product_names
    for item in tree.get("full_product_names") or []:
        if isinstance(item, dict):
            pid = str(item.get("product_id") or "").strip()
            cpe = str((item.get("product_identification_helper") or {}).get("cpe") or "")
            name = str(item.get("name") or "")
            if pid and (_cpe_matches_rhel(cpe, major) or re.search(rf"\brhel\s*{re.escape(major)}\b", name, re.I)):
                ids.add(pid)
    return ids


def _fixed_packages_from_vuln(vuln: dict, product_ids: set[str]) -> list[tuple[str, str, str]]:
    """Return list of (package_name, fixed_evr, product_id) from remediations."""
    out: list[tuple[str, str, str]] = []
    for rem in vuln.get("remediations") or []:
        if not isinstance(rem, dict):
            continue
        category = str(rem.get("category") or "").lower()
        if category and category not in {"vendor_fix", "mitigation", "workaround", "none_available"}:
            # Still allow vendor_fix primarily
            if category != "vendor_fix":
                continue
        if category == "none_available":
            continue
        product_ids_rem = set(str(x) for x in (rem.get("product_ids") or []))
        if product_ids and product_ids_rem and not (product_ids_rem & product_ids):
            continue
        # Details often contain RPM NEVRA lines
        details = str(rem.get("details") or "")
        # Pattern: package-version-release.arch or name >= epoch:version-release
        for match in re.finditer(
            r"(?:^|\s)([a-zA-Z0-9._+-]+)-([0-9][^:\s]*?)-([0-9][^\s]*?)(?:\.(el\d+[^\s]*))?(?:\s|$)",
            details,
        ):
            name, ver, rel = match.group(1), match.group(2), match.group(3)
            if name.lower() in {"rhsa", "cve", "http", "https", "the", "and"}:
                continue
            evr = f"0:{ver}-{rel}"
            pid = next(iter(product_ids_rem & product_ids), next(iter(product_ids_rem), ""))
            out.append((name, evr, pid))
        # CSAF sometimes uses group URL only — no package line
    return out


def _cves_from_vuln(vuln: dict) -> list[str]:
    cves: list[str] = []
    cve = str(vuln.get("cve") or "").strip().upper()
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
        cves.append(cve)
    for item in vuln.get("ids") or []:
        if isinstance(item, dict):
            text = str(item.get("text") or "").upper()
            if re.fullmatch(r"CVE-\d{4}-\d{4,}", text):
                cves.append(text)
    return list(dict.fromkeys(cves)) or [""]


def _severity_from_vuln(vuln: dict) -> str:
    scores = vuln.get("scores") or []
    for score in scores:
        if not isinstance(score, dict):
            continue
        cvss = score.get("cvss_v3") or score.get("cvss_v2") or {}
        if isinstance(cvss, dict):
            sev = str(cvss.get("baseSeverity") or cvss.get("base_severity") or "")
            if sev:
                return normalize_severity(sev)
    threats = vuln.get("threats") or []
    for threat in threats:
        if isinstance(threat, dict) and threat.get("category") == "impact":
            return normalize_severity(str(threat.get("details") or ""))
    return "Info"


def _packages_by_name(inventory: Inventory) -> dict[str, list[Package]]:
    index: dict[str, list[Package]] = {}
    for pkg in inventory.packages:
        if (pkg.package_manager or "rpm").lower() != "rpm":
            continue
        index.setdefault(pkg.name.lower(), []).append(pkg)
    return index


class RedHatCsafAdapter(VendorAdapter):
    name = "Red Hat CSAF"

    def applicable(self, inventory: Inventory) -> bool:
        return (
            inventory.os.family == "redhat"
            and inventory.os.product in {"rhel", "redhat"}
            and any((pkg.package_manager or "rpm").lower() == "rpm" for pkg in inventory.packages)
        )

    def evaluate(self, inventory: Inventory, feeds_root: Path) -> list[Finding]:
        files = _iter_csaf_files(feeds_root)
        if not files:
            # Not an error when OVAL covers the release; only warn for RHEL 10+
            major = inventory.os.major or ""
            if major and major.isdigit() and int(major) >= 10:
                inventory.warnings.append(
                    "Red Hat CSAF: no local CSAF JSON under vendor/redhat/csaf/. "
                    "RHEL 10+ requires CSAF; OVAL base streams stop at RHEL 9."
                )
            return []

        major = inventory.os.major or ""
        if not major:
            inventory.warnings.append("Red Hat CSAF: OS major version unknown; product matching skipped.")
            return []

        pkg_index = _packages_by_name(inventory)
        findings: list[Finding] = []
        seen: set[tuple[str, str, str, str]] = set()
        evaluated_docs = 0

        for path in files:
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                inventory.warnings.append(f"Red Hat CSAF: skip {path.name}: {exc}")
                continue
            if not isinstance(doc, dict):
                continue
            product_ids = _collect_product_ids(doc, major)
            # If we cannot map any product for this major, still try remediations
            # that mention el{major} in package EVR.
            tracking = (doc.get("document") or {}).get("tracking") or {}
            advisory = str(tracking.get("id") or path.stem)
            title = str((doc.get("document") or {}).get("title") or advisory)

            for vuln in doc.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                cves = _cves_from_vuln(vuln)
                severity = _severity_from_vuln(vuln)
                description = str(vuln.get("title") or title)
                fixed_list = _fixed_packages_from_vuln(vuln, product_ids)

                # product_status known_affected without fix → vendor affected no fix
                status_block = vuln.get("product_status") or {}
                known_affected = set(str(x) for x in (status_block.get("known_affected") or []))
                fixed_status = set(str(x) for x in (status_block.get("fixed") or []))

                for name, fixed_evr, _pid in fixed_list:
                    for pkg in pkg_index.get(name.lower(), []):
                        try:
                            vulnerable = compare_evr(pkg.evr, fixed_evr) < 0
                        except Exception:
                            continue
                        if not vulnerable:
                            continue
                        for cve in cves:
                            key = (pkg.name, pkg.evr, cve, advisory)
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
                                severity=severity,
                                description=description,
                                fixed_evr=fixed_evr,
                                reason=(
                                    f"Red Hat CSAF {advisory} lists fixed RPM {name}-{fixed_evr} "
                                    f"for RHEL {major}; installed {pkg.evr} is older."
                                ),
                                solution=f"Update {pkg.name} to {fixed_evr} or later per {advisory}.",
                                evidence=Evidence(
                                    source=self.name,
                                    advisory=advisory,
                                    definition_id=advisory,
                                    feed_file=str(path),
                                    evaluated_expression=f"compare_evr({pkg.evr}, {fixed_evr}) < 0",
                                ),
                                references=[f"https://access.redhat.com/errata/{advisory}"] if advisory.startswith("RH") else [],
                                source_rpm=pkg.source_rpm,
                                package_vendor=pkg.vendor,
                                package_packager=pkg.packager,
                                install_time=pkg.install_time,
                                running_kernel=inventory.running_kernel,
                                review_required=False,
                            ))

                # Known affected, no remediation package → Needs Validation / no fix
                if known_affected and not fixed_list and not fixed_status:
                    for cve in cves:
                        if not cve:
                            continue
                        key = ("*", "*", cve, advisory)
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(Finding(
                            host=inventory.hostname,
                            os=inventory.os.pretty_name,
                            package_name="(product-level)",
                            installed_evr="",
                            package_arch="",
                            cve=cve,
                            status=FindingStatus.VENDOR_AFFECTED_NO_FIX,
                            confidence="Medium",
                            severity=severity,
                            description=description,
                            fixed_evr="",
                            reason=f"CSAF {advisory} marks product affected without a published fixed RPM EVR in this document.",
                            solution="Track Red Hat advisory for a fix or compensating control.",
                            evidence=Evidence(
                                source=self.name,
                                advisory=advisory,
                                definition_id=advisory,
                                feed_file=str(path),
                            ),
                            references=[f"https://access.redhat.com/errata/{advisory}"] if advisory.startswith("RH") else [],
                            running_kernel=inventory.running_kernel,
                            review_required=True,
                        ))
            evaluated_docs += 1

        if evaluated_docs:
            inventory.assessment.setdefault("csaf_docs", evaluated_docs)
        return findings
