from __future__ import annotations

import bz2
import csv
import gzip
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .base import VendorAdapter
from .common import normalize_severity, oval_findings
from ..models import Evidence, Finding, FindingStatus, Inventory, Package
from ..rpmver import compare_evr


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def open_any(path: Path):
    suffix = "".join(path.suffixes).lower()
    if suffix.endswith(".gz"):
        return gzip.open(path, "rb")
    if suffix.endswith(".bz2"):
        return bz2.open(path, "rb")
    return path.open("rb")


def _arch_matches(installed: str, fixed: str) -> bool:
    return not fixed or fixed in {"*", "noarch"} or installed == fixed


def _finding(inventory: Inventory, pkg: Package, cve: str, fixed: str, advisory: str, severity: str, description: str, source: str, feed: Path, reference: str = "") -> Finding | None:
    if not fixed:
        return None
    cmpv = compare_evr(pkg.evr, fixed)
    if cmpv >= 0:
        return None
    return Finding(
        host=inventory.hostname,
        os=inventory.os.pretty_name,
        package_name=pkg.name,
        installed_evr=pkg.evr,
        package_arch=pkg.arch,
        cve=cve,
        status=FindingStatus.CONFIRMED_VULNERABLE,
        confidence="High",
        severity=normalize_severity(severity),
        description=description,
        fixed_evr=fixed,
        reason=f"Huawei advisory lists {fixed} as the fixed/minimum package EVR; installed EVR is {pkg.evr}.",
        solution=f"Update {pkg.name} to Huawei package {fixed} or a later release approved for {inventory.os.pretty_name}.",
        evidence=Evidence(source=source, advisory=advisory, feed_file=str(feed), reference=reference),
        references=[reference] if reference else [],
        source_rpm=pkg.source_rpm,
        package_vendor=pkg.vendor,
        package_packager=pkg.packager,
        install_time=pkg.install_time,
        running_kernel=inventory.running_kernel,
    )


def parse_yum_updateinfo(path: Path, inventory: Inventory, source: str) -> list[Finding]:
    findings: list[Finding] = []
    index = inventory.package_index()
    with open_any(path) as fh:
        root = ET.parse(fh).getroot()
    # Some HCE feeds wrap updates; support both updateinfo and custom names.
    for update in [x for x in root.iter() if local(x.tag).lower() in {"update", "advisory"}]:
        advisory = ""
        title = description = severity = ""
        cves: list[str] = []
        reference = ""
        for elem in update.iter():
            name = local(elem.tag).lower()
            text = (elem.text or "").strip()
            if name in {"id", "advisoryid", "advisory_id"} and not advisory:
                advisory = text
            elif name in {"title", "synopsis"} and not title:
                title = text
            elif name in {"description", "summary"} and not description:
                description = text
            elif name in {"severity", "impact"} and not severity:
                severity = text
            elif name == "reference":
                cve = elem.attrib.get("id", "")
                if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve, re.I):
                    cves.append(cve.upper())
                reference = reference or elem.attrib.get("href", "")
            elif name == "cve" and re.fullmatch(r"CVE-\d{4}-\d{4,}", text, re.I):
                cves.append(text.upper())
        if not cves:
            cves = re.findall(r"CVE-\d{4}-\d{4,}", f"{title} {description}", re.I)
        for elem in update.iter():
            if local(elem.tag).lower() not in {"package", "rpm"}:
                continue
            name = elem.attrib.get("name", "").strip()
            version = elem.attrib.get("version", "").strip()
            release = elem.attrib.get("release", "").strip()
            epoch = elem.attrib.get("epoch", "0").strip() or "0"
            arch = elem.attrib.get("arch", "").strip()
            if not name or not version:
                continue
            fixed = f"{epoch}:{version}" + (f"-{release}" if release else "")
            for pkg in index.get(name.lower(), []):
                if not _arch_matches(pkg.arch, arch):
                    continue
                for cve in cves or [""]:
                    found = _finding(inventory, pkg, cve.upper(), fixed, advisory, severity, description or title, source, path, reference)
                    if found:
                        findings.append(found)
    return findings


def _parse_nevra_text(value: str) -> tuple[str, str, str] | None:
    text = value.strip().split()[-1].removesuffix(".rpm")
    # name-epoch:version-release.arch or name-version-release.arch
    match = re.match(r"^(?P<name>.+)-(?:(?P<epoch>\d+):)?(?P<version>[^-]+)-(?P<release>[^.]+(?:\.[^.]+)*?)\.(?P<arch>x86_64|aarch64|noarch|i[3-6]86|ppc64le|s390x)$", text)
    if not match:
        return None
    evr = f"{match.group('epoch') or '0'}:{match.group('version')}-{match.group('release')}"
    return match.group("name"), evr, match.group("arch")


def parse_csaf(path: Path, inventory: Inventory, source: str) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    product_names: dict[str, str] = {}
    tree = data.get("product_tree") or {}

    def walk(value):
        if isinstance(value, dict):
            if value.get("product_id") and value.get("name"):
                product_names[str(value["product_id"])] = str(value["name"])
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(tree)

    index = inventory.package_index()
    advisory = str(((data.get("document") or {}).get("tracking") or {}).get("id") or path.stem)
    findings: list[Finding] = []
    for vuln in data.get("vulnerabilities") or []:
        cve = str(vuln.get("cve") or "").upper()
        title = str(vuln.get("title") or "")
        scores = vuln.get("scores") or []
        severity = ""
        if scores:
            cvss = scores[0].get("cvss_v3") or scores[0].get("cvss_v4") or {}
            severity = str(cvss.get("baseSeverity") or cvss.get("base_severity") or "")
        status = vuln.get("product_status") or {}
        fixed_ids = status.get("fixed") or []
        for product_id in fixed_ids:
            parsed = _parse_nevra_text(product_names.get(str(product_id), ""))
            if not parsed:
                continue
            name, fixed, arch = parsed
            for pkg in index.get(name.lower(), []):
                if not _arch_matches(pkg.arch, arch):
                    continue
                found = _finding(inventory, pkg, cve, fixed, advisory, severity, title, source, path)
                if found:
                    findings.append(found)
    return findings


def parse_cvrf(path: Path, inventory: Inventory, source: str) -> list[Finding]:
    with open_any(path) as fh:
        root = ET.parse(fh).getroot()
    product_names: dict[str, str] = {}
    for elem in root.iter():
        if local(elem.tag).lower() in {"fullproductname", "full_product_name"}:
            pid = elem.attrib.get("ProductID") or elem.attrib.get("product_id") or ""
            if pid:
                product_names[pid] = (elem.text or "").strip()
    advisory = next(((x.text or "").strip() for x in root.iter() if local(x.tag).lower() in {"documenttitle", "document_title"}), path.stem)
    index = inventory.package_index()
    findings: list[Finding] = []
    for vuln in [x for x in root.iter() if local(x.tag).lower() == "vulnerability"]:
        cve = next(((x.text or "").strip().upper() for x in vuln.iter() if local(x.tag).lower() == "cve"), "")
        title = next(((x.text or "").strip() for x in vuln.iter() if local(x.tag).lower() == "title"), "")
        severity = next(((x.text or "").strip() for x in vuln.iter() if local(x.tag).lower() in {"severity", "threatdescription"}), "")
        fixed_ids: list[str] = []
        for status in vuln.iter():
            if local(status.tag).lower() == "status" and status.attrib.get("Type", status.attrib.get("type", "")).lower() == "fixed":
                fixed_ids.extend((x.text or "").strip() for x in status.iter() if local(x.tag).lower() == "productid")
        for pid in fixed_ids:
            parsed = _parse_nevra_text(product_names.get(pid, ""))
            if not parsed:
                continue
            name, fixed, arch = parsed
            for pkg in index.get(name.lower(), []):
                if _arch_matches(pkg.arch, arch):
                    found = _finding(inventory, pkg, cve, fixed, advisory, severity, title, source, path)
                    if found:
                        findings.append(found)
    return findings


def _safe_filename(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)


def _normalize_scope(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (value or "").lower())


def _euleros_scoped_paths(feeds_root: Path, inventory: Inventory) -> list[Path]:
    sources = feeds_root / "vendor" / "huawei" / "euleros" / "sources.csv"
    if not sources.exists():
        return []
    paths: list[Path] = []
    actual = _normalize_scope(inventory.os.version)
    with sources.open("r", encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            advisory = (row.get("advisory") or "").strip()
            api_version = (row.get("version") or "").strip()
            os_version = (row.get("os_version") or "").strip()
            # A separate exact collector scope is required. This prevents an
            # advisory downloaded for one EulerOS release from being evaluated
            # against a different release that happens to contain the same RPM.
            if not advisory or not api_version or not os_version:
                continue
            if _normalize_scope(os_version) != actual:
                continue
            stem = f"{_safe_filename(advisory)}__{_safe_filename(api_version)}"
            for path in [
                feeds_root / "vendor" / "huawei" / "euleros" / "cvrf" / f"{stem}.xml",
                feeds_root / "vendor" / "huawei" / "euleros" / "csaf" / f"{stem}.json",
            ]:
                if path.exists():
                    paths.append(path)
    return paths


class HuaweiAdapter(VendorAdapter):
    name = "Huawei Security Advisory"

    def applicable(self, inventory: Inventory) -> bool:
        return inventory.os.family == "huawei" and any(
            (pkg.package_manager or "rpm").lower() == "rpm" for pkg in inventory.packages
        )

    def evaluate(self, inventory: Inventory, feeds_root: Path) -> list[Finding]:
        paths: list[Path] = []
        if inventory.os.product == "hce":
            major = inventory.os.major or "2"
            aggregate = feeds_root / "vendor" / "huawei" / "hce" / major / f"HCE{major}-SA.xml"
            # Catalog stores 2.0/3.0 directories.
            aggregate2 = feeds_root / "vendor" / "huawei" / "hce" / f"{major}.0" / f"HCE{major}-SA.xml"
            paths.extend(p for p in [aggregate, aggregate2] if p.exists())
            for folder in [
                feeds_root / "vendor" / "huawei" / "hce" / f"{major}.0" / "cvrf",
                feeds_root / "vendor" / "huawei" / "hce" / f"{major}.0" / "csaf",
            ]:
                if folder.exists():
                    paths.extend(folder.glob("*"))
        else:
            paths.extend(_euleros_scoped_paths(feeds_root, inventory))

        findings: list[Finding] = []
        for path in sorted(set(p for p in paths if p.is_file())):
            try:
                if path.suffix.lower() == ".json":
                    findings.extend(parse_csaf(path, inventory, "Huawei CSAF"))
                    continue
                with open_any(path) as fh:
                    _event, root = next(ET.iterparse(fh, events=("start",)))
                root_name = local(root.tag).lower()
                if root_name == "oval_definitions":
                    findings.extend(oval_findings(inventory, path, "Huawei OVAL"))
                elif root_name in {"cvrfdoc", "document"}:
                    findings.extend(parse_cvrf(path, inventory, "Huawei CVRF"))
                else:
                    findings.extend(parse_yum_updateinfo(path, inventory, "Huawei HCE Security Advisory"))
            except Exception as exc:
                inventory.warnings.append(f"Huawei feed could not be evaluated ({path.name}): {exc}")
                continue
        return findings
