from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .base import VendorAdapter
from .common import normalize_severity, oval_findings
from ..models import Evidence, Finding, FindingStatus, Inventory, Package
from ..oval import OvalDocument, local
from ..rpmver import compare_evr


LESS_OPS = {"less than", "less than or equal", "less_than", "less_than_or_equal"}


def _stream_from_name(name: str) -> str:
    m = re.search(r"rhel-(\d+)\.(\d+)-(aus|e4s|eus|tus)\.oval", name, re.I)
    return m.group(3).lower() if m else "base"


def _repo_stream_known(inventory: Inventory, stream: str) -> bool:
    if stream == "base":
        return True
    repo_ids, _ = _repository_cpes(None, inventory)
    return any(re.search(rf"(?:^|[^a-z0-9]){re.escape(stream)}(?:[^a-z0-9]|$)", repo.lower()) for repo in repo_ids)


def _confirmed_streams(inventory: Inventory, feeds_root: Path | None) -> set[str]:
    """Streams supported by explicit configuration; not a runtime repo query."""
    streams = {
        stream for stream in ("aus", "e4s", "eus", "tus")
        if _repo_stream_known(inventory, stream)
    }
    _repo_ids, repository_cpes = _repository_cpes(feeds_root, inventory)
    for value in repository_cpes:
        match = re.search(r":rhel_(aus|e4s|eus|tus):", value, re.I)
        if match:
            streams.add(match.group(1).lower())
    return streams


def _source_component(pkg: Package) -> str:
    value = (pkg.source_rpm or "").strip()
    base = value.removesuffix(".src.rpm").removesuffix(".nosrc.rpm")
    match = re.match(r"^(.+)-([^-]+)-([^-]+)$", base)
    return match.group(1) if match else pkg.name


def _repository_cpes(feeds_root: Path | None, inventory: Inventory) -> tuple[list[str], list[str]]:
    repo_ids: list[str] = []
    current_repo = ""
    states: dict[str, set[str]] = {}
    current_state = "unknown"

    def flush():
        if current_repo and current_repo.lower() != "main":
            states.setdefault(current_repo, set()).add(current_state)

    for raw in (inventory.repository_evidence or "").splitlines():
        if raw.strip().startswith("--- "):
            flush()
            current_repo, current_state = "", "unknown"
            continue
        header = re.match(r"^\s*\[([^]]+)\]", raw)
        if header:
            flush()
            current_repo = header.group(1).strip()
            current_state = "unknown"
            continue
        enabled = re.match(r"^\s*enabled\s*=\s*([^#;]*?)(?:\s*[#;].*)?$", raw, re.I)
        if enabled:
            flag = enabled.group(1).strip().lower()
            current_state = "true" if flag in {"1", "true", "yes"} else ("false" if flag in {"0", "false", "no"} else "unknown")
    flush()
    repo_ids = [repo for repo, flags in states.items() if flags == {"true"}]
    if not feeds_root or not repo_ids:
        return repo_ids, []
    path = feeds_root / "vendor" / "redhat" / "repository-to-cpe.json"
    if not path.exists():
        return repo_ids, []
    try:
        import json
        data = (json.loads(path.read_text(encoding="utf-8-sig")) or {}).get("data", {})
        cpes: list[str] = []
        for repo_id in repo_ids:
            cpes.extend((data.get(repo_id) or {}).get("cpes") or [])
        return repo_ids, list(dict.fromkeys(cpes))
    except Exception:
        return repo_ids, []


def _scope_status(inventory: Inventory, affected_cpes: list[str], repository_cpes: list[str]) -> tuple[str, str]:
    affected = {x.lower() for x in affected_cpes if x}
    repositories = {x.lower() for x in repository_cpes if x}
    if affected and repositories:
        overlap = sorted(affected & repositories)
        if overlap:
            return "confirmed", f"Affected CPE matched repository configuration with explicit enabled=true: {', '.join(overlap)}; effective runtime state not collected."
    major = inventory.os.major
    minor = inventory.os.minor
    if affected:
        generic = [x for x in affected if re.search(rf":enterprise_linux:{re.escape(major)}(?::|$)", x)]
        exact = [x for x in affected if minor and re.search(rf":rhel_[a-z0-9]+:{re.escape(major)}\.{re.escape(minor)}(?::|$)", x)]
        if generic or exact:
            matched = generic + exact
            return "inferred", f"Host RHEL {inventory.os.version} matches advisory product CPE: {', '.join(matched)}; repository-to-CPE confirmation unavailable."
        rhel_versions = [m.group(1) for value in affected for m in [re.search(r":(?:enterprise_linux|rhel_[a-z0-9]+):([0-9]+(?:\.[0-9]+)?)", value)] if m]
        if rhel_versions:
            return "mismatch", f"Advisory CPE scope {rhel_versions} does not match host RHEL {inventory.os.version}."
    return "unknown", "Advisory CPE scope could not be confirmed from collected repository evidence."


def _fixed_minor(fixed: str) -> tuple[str, str]:
    match = re.search(r"\.el(\d+)_(\d+)(?:[^0-9]|$)", fixed or "")
    return (match.group(1), match.group(2)) if match else ("", "")


def _metadata(definition: ET.Element) -> tuple[str, str, str, list[str], list[str], str, list[str], list[str]]:
    title = description = severity = advisory = ""
    cves: list[str] = []
    refs: list[str] = []
    affected_cpes: list[str] = []
    affected_platforms: list[str] = []
    md = next((x for x in list(definition) if local(x.tag) == "metadata"), None)
    if md is not None:
        for elem in md.iter():
            tag = local(elem.tag)
            text = (elem.text or "").strip()
            if tag == "title" and not title:
                title = text
            elif tag == "description" and not description:
                description = text
            elif tag == "severity" and not severity:
                severity = text
            elif tag == "reference":
                ref_id = elem.attrib.get("ref_id", "")
                ref_url = elem.attrib.get("ref_url", "")
                source = elem.attrib.get("source", "")
                if re.fullmatch(r"CVE-\d{4}-\d{4,}", ref_id, re.I):
                    cves.append(ref_id.upper())
                if ref_url:
                    refs.append(ref_url)
                if source.upper() == "RHSA" and ref_id:
                    advisory = ref_id
            elif tag == "cpe" and text:
                affected_cpes.append(text)
            elif tag == "platform" and text:
                affected_platforms.append(text)
    if not advisory:
        m = re.search(r"RHSA[-:]?\d{4}[:_-]\d+", title, re.I)
        if m:
            value = m.group(0).upper().replace("RHSA-", "RHSA-").replace("_", ":")
            if value.startswith("RHSA") and ":" not in value:
                value = value.replace("RHSA", "RHSA-")
            advisory = value
    if not cves:
        cves = sorted(set(x.upper() for x in re.findall(r"CVE-\d{4}-\d{4,}", f"{title} {description}", re.I)))
    return (
        title, description, severity, list(dict.fromkeys(cves)), list(dict.fromkeys(refs)), advisory,
        list(dict.fromkeys(affected_cpes)), list(dict.fromkeys(affected_platforms)),
    )


def _literal_names(document: OvalDocument, test: ET.Element) -> list[str]:
    obj_ref = document._object_ref(test)  # intentionally reuse parser internals
    xml = document.objects.get(obj_ref)
    if not xml:
        return []
    obj = ET.fromstring(xml)
    names: list[str] = []
    for elem in obj.iter():
        if local(elem.tag) == "name" and not elem.attrib.get("var_ref"):
            value = (elem.text or "").strip()
            if value and elem.attrib.get("operation", "equals").lower().replace("_", " ") in {"equals", "equal"}:
                names.append(value)
    return list(dict.fromkeys(names))


def _thresholds(document: OvalDocument, test: ET.Element) -> list[tuple[str, str, str]]:
    """Return (fixed_evr, operation, arch) thresholds from test states.

    Signature entities are intentionally ignored here. This fallback is used to
    reproduce Red Hat/Tenable package-version checks when the collector lacks
    repository/signature evidence. It is only applied to an exact RHEL product
    stream file or the base RHEL major file.
    """
    out: list[tuple[str, str, str]] = []
    for state_ref in document._state_refs(test):
        xml = document.states.get(state_ref)
        if not xml:
            continue
        state = ET.fromstring(xml)
        fixed = op = arch = ""
        for entity in list(state):
            key = local(entity.tag)
            value = (entity.text or "").strip()
            operation = entity.attrib.get("operation", "equals").lower().replace("_", " ")
            if key == "evr" and operation in {"less than", "less than or equal"} and value:
                fixed, op = value, operation
            elif key in {"arch", "architecture"} and operation in {"equals", "equal"}:
                arch = value
        if fixed:
            out.append((fixed, op, arch))
    return out


def _arch_matches(pkg: Package, arch: str) -> bool:
    return not arch or arch == "noarch" or pkg.arch == arch


def package_threshold_findings(
    inventory: Inventory,
    path: Path,
    source: str = "Red Hat OVAL Package Threshold",
    feeds_root: Path | None = None,
) -> list[Finding]:
    """Conservative RHSA package-threshold fallback.

    Full OVAL evaluation remains preferred. If Red Hat's full OVAL definition
    becomes UNKNOWN because local repository/signature tests were not captured,
    this parser still extracts explicit fixed RPM EVRs and compares them with
    installed RPMs. A generic major-version RHEL CPE is sufficient product
    evidence for the base stream (the same local-check model used by Nessus).
    AUS/E4S/EUS/TUS remain gated by explicit repository-stream evidence.
    """
    document = OvalDocument(path)
    index = inventory.package_index()
    stream = _stream_from_name(path.name)
    stream_known = _repo_stream_known(inventory, stream)
    repo_ids, repository_cpes = _repository_cpes(feeds_root, inventory)
    rows: list[Finding] = []
    seen: set[tuple[str, str, str, str, str]] = set()

    for def_id, xml in document.definitions.items():
        definition = ET.fromstring(xml)
        if definition.attrib.get("class", "") not in {"vulnerability", "patch"}:
            continue
        title, description, severity, cves, refs, advisory, affected_cpes, affected_platforms = _metadata(definition)
        if not cves:
            continue
        scope_status, scope_note = _scope_status(inventory, affected_cpes, repository_cpes)
        if scope_status == "mismatch":
            continue
        criteria = next((x for x in list(definition) if local(x.tag) == "criteria"), None)
        if criteria is None:
            continue
        test_ids = [x.attrib.get("test_ref", "") for x in criteria.iter() if local(x.tag) == "criterion" and x.attrib.get("test_ref")]
        for test_id in test_ids:
            test_xml = document.tests.get(test_id)
            if not test_xml:
                continue
            test = ET.fromstring(test_xml)
            if local(test.tag) != "rpminfo_test":
                continue
            names = _literal_names(document, test)
            if not names:
                continue
            thresholds = _thresholds(document, test)
            if not thresholds:
                continue
            for name in names:
                for pkg in index.get(name.lower(), []):
                    for fixed, operation, arch in thresholds:
                        if not _arch_matches(pkg, arch):
                            continue
                        if compare_evr(pkg.evr, fixed) >= 0:
                            continue
                        for cve in cves:
                            key = (pkg.name, pkg.evr, cve, advisory or def_id, fixed)
                            if key in seen:
                                continue
                            seen.add(key)
                            fixed_major, fixed_minor = _fixed_minor(fixed)
                            scope_applicable = (
                                scope_status == "confirmed"
                                or (stream == "base" and scope_status == "inferred")
                                or (stream != "base" and stream_known)
                            )
                            review = not scope_applicable
                            if review:
                                stream_note = f"Red Hat stream '{stream}' applicability requires validation for host RHEL {inventory.os.version}; the fixed build targets RHEL {fixed_major or inventory.os.major}.{fixed_minor or inventory.os.minor} and product/repository evidence was not sufficient."
                            elif scope_status == "confirmed":
                                stream_note = f"Red Hat stream '{stream}' matched collected repository-configuration-to-CPE evidence; effective runtime state and entitlement were not queried."
                            elif stream == "base":
                                stream_note = f"The generic Red Hat Enterprise Linux {inventory.os.major} product CPE confirms base-stream applicability; a cross-minor fixed build remains an applicable RHEL {inventory.os.major} update."
                            else:
                                stream_note = f"Red Hat support stream '{stream}' matched explicit enabled=true repository configuration; effective runtime state not collected."
                            component = _source_component(pkg)
                            rows.append(Finding(
                                host=inventory.hostname,
                                os=inventory.os.pretty_name,
                                package_name=component,
                                installed_evr=pkg.evr,
                                package_arch=pkg.arch,
                                cve=cve,
                                status=FindingStatus.CONFIRMED_VULNERABLE if not review else FindingStatus.NEEDS_VALIDATION,
                                confidence="High; Red Hat product/advisory and installed RPM threshold" if not review else "Medium; advisory/package match, product or repository scope unresolved",
                                severity=normalize_severity(severity),
                                description=description or title,
                                fixed_evr=fixed,
                                reason=f"Red Hat advisory package threshold from {path.name}: installed binary RPM {pkg.name} {pkg.evr} (source component {component}) is lower than fixed EVR {fixed}. {stream_note} {scope_note}",
                                solution=(
                                    f"Validate the enabled Red Hat repository stream/CPE, then update the {component} package set, including {pkg.name}, according to {advisory or 'the Red Hat advisory'}."
                                    if review else
                                    f"Update the {component} package set, including {pkg.name}, to the Red Hat build fixed by {advisory or 'the Red Hat advisory'} for the confirmed repository stream."
                                ),
                                evidence=Evidence(
                                    source=source,
                                    advisory=advisory,
                                    definition_id=def_id,
                                    feed_file=str(path),
                                    reference=refs[0] if refs else "",
                                    evaluated_expression=f"RPM threshold fallback: {pkg.evr} < {fixed}; stream={stream}; repo_stream_known={stream_known}",
                                    raw={
                                        "stream": stream,
                                        "repository_stream_confirmed": stream_known,
                                        "repository_ids": repo_ids,
                                        "repository_cpes": repository_cpes,
                                        "affected_cpes": affected_cpes,
                                        "affected_platforms": affected_platforms,
                                        "scope_status": scope_status,
                                        "scope_note": scope_note,
                                        "test_id": test_id,
                                        "matched_binary_packages": [pkg.name],
                                        "installed_binary_versions": {pkg.name: pkg.evr},
                                        "fixed_binary_versions": {pkg.name: fixed},
                                    },
                                ),
                                references=refs,
                                source_rpm=pkg.source_rpm,
                                package_vendor=pkg.vendor,
                                package_packager=pkg.packager,
                                install_time=pkg.install_time,
                                running_kernel=inventory.running_kernel,
                                review_required=review,
                            ))
    return rows


def _normalize_strict_findings(findings: list[Finding], inventory: Inventory) -> list[Finding]:
    index = inventory.package_index()
    for finding in findings:
        candidates = [
            pkg for pkg in index.get(finding.package_name.lower(), [])
            if pkg.evr == finding.installed_evr and pkg.arch == finding.package_arch
        ]
        if not candidates:
            continue
        pkg = candidates[0]
        binary_name = pkg.name
        component = _source_component(pkg)
        finding.package_name = component
        finding.source_rpm = pkg.source_rpm
        finding.reason += f" The matched binary RPM is {binary_name}; its source component is {component}."
        finding.solution = f"Update the {component} package set, including {binary_name}, according to {finding.evidence.advisory or 'the Red Hat advisory'}."
        finding.evidence.raw.update({
            "scope_status": "confirmed",
            "scope_note": "The complete Red Hat OVAL product and package criteria tree evaluated TRUE.",
            "matched_binary_packages": [binary_name],
            "installed_binary_versions": {binary_name: pkg.evr},
            "fixed_binary_versions": {binary_name: finding.fixed_evr},
        })
    return findings


class RedHatOvalAdapter(VendorAdapter):
    name = "Red Hat OVAL"

    def applicable(self, inventory: Inventory) -> bool:
        return (
            inventory.os.family == "redhat"
            and inventory.os.product == "rhel"
            and any((pkg.package_manager or "rpm").lower() == "rpm" for pkg in inventory.packages)
        )

    def _select(self, inventory: Inventory, root: Path) -> list[Path]:
        major, minor = inventory.os.major, inventory.os.minor
        folder = root / "vendor" / "redhat" / f"RHEL{major}"
        paths: list[Path] = []
        # A support-stream feed is applicable only when an enabled repository
        # or its repository-to-CPE mapping proves AUS/E4S/EUS/TUS. Evaluating
        # every same-minor stream creates mutually exclusive findings and does
        # not match Nessus plugin applicability semantics.
        confirmed_streams = _confirmed_streams(inventory, root)
        if minor:
            for stream in sorted(confirmed_streams):
                candidate = folder / f"rhel-{major}.{minor}-{stream}.oval.xml.bz2"
                if candidate.exists():
                    paths.append(candidate)
        base = folder / f"rhel-{major}.oval.xml.bz2"
        if base.exists():
            paths.append(base)
        # Explicitly supplied extra product streams remain supported.
        stream_dir = root / "vendor" / "redhat" / "streams" / f"RHEL{major}"
        if stream_dir.exists():
            for candidate in sorted(stream_dir.glob("*.xml*")):
                stream = _stream_from_name(candidate.name)
                if stream == "base" or stream in confirmed_streams:
                    paths.append(candidate)
        return list(dict.fromkeys(paths))

    def evaluate(self, inventory: Inventory, feeds_root: Path) -> list[Finding]:
        findings: list[Finding] = []
        paths = self._select(inventory, feeds_root)
        rpm_count = sum(1 for p in inventory.packages if (p.package_manager or "rpm").lower() == "rpm")
        if not paths:
            inventory.warnings.append(
                f"Red Hat OVAL: no feed selected for RHEL {inventory.os.major or '?'}"
                f".{inventory.os.minor or 'x'} under vendor/redhat/RHEL{inventory.os.major or '?'}/. "
                f"Expected rhel-{inventory.os.major or 'N'}.oval.xml.bz2 (and optional stream files). "
                f"RPM packages in inventory={rpm_count}."
            )
            return findings
        inventory.warnings.append(
            f"Red Hat OVAL: evaluating {len(paths)} feed(s) for "
            f"{inventory.os.pretty_name or inventory.os.product} "
            f"major={inventory.os.major} minor={inventory.os.minor or '-'} "
            f"rpm_packages={rpm_count}: " + ", ".join(p.name for p in paths)
        )
        for path in paths:
            # First: strict full-tree OVAL evaluation.
            strict = _normalize_strict_findings(oval_findings(inventory, path, self.name), inventory)
            findings.extend(strict)
            strict_keys = {(x.package_name, x.installed_evr, x.cve, x.fixed_evr) for x in strict}
            # Second: explicit Red Hat RPM fixed-threshold fallback. This is
            # critical when signature/repository criteria are UNKNOWN, and is
            # the behavior demonstrated by Tenable plugin 206787.
            for row in package_threshold_findings(inventory, path, feeds_root=feeds_root):
                key = (row.package_name, row.installed_evr, row.cve, row.fixed_evr)
                if key not in strict_keys:
                    findings.append(row)
        if not findings:
            inventory.warnings.append(
                "Red Hat OVAL: 0 confirmed package findings after strict + threshold evaluation. "
                "This can mean hosts are patched for the loaded definitions, the inventory EVR "
                "format did not match OVAL package names, or the wrong major feed was used. "
                "Check Summary coverage and that collector output includes RPM_INVENTORY_NEVRA."
            )
        return findings
