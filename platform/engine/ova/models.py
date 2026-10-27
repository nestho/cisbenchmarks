from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any


class Truth(str, Enum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"
    ERROR = "error"


class FindingStatus(str, Enum):
    CONFIRMED_VULNERABLE = "Confirmed Vulnerable"
    VENDOR_AFFECTED_NO_FIX = "Vendor Affected - No Fixed EVR"
    FIXED_NOT_VULNERABLE = "Fixed / Not Vulnerable"
    POTENTIAL = "Potential Vulnerable"
    NEEDS_VALIDATION = "Needs Validation"
    REBOOT_REQUIRED = "Reboot Required"
    INFORMATIONAL = "Informational"
    ANALYSIS_INCOMPLETE = "Analysis Incomplete"


@dataclass(slots=True)
class OSIdentity:
    family: str = "unknown"
    product: str = "unknown"
    version: str = ""
    major: str = ""
    minor: str = ""
    service_pack: str = ""
    pretty_name: str = ""
    cpe_name: str = ""
    id_like: str = ""
    architecture: str = ""
    release_files: dict[str, str] = field(default_factory=dict)
    # Debian's security data is keyed by release suite/codename (for example
    # bookworm), rather than only by the numeric VERSION_ID.
    codename: str = ""
    support_suite: str = ""

    @property
    def scope_key(self) -> str:
        bits = [self.family, self.major]
        if self.minor:
            bits.append(self.minor)
        if self.service_pack:
            bits.append(f"sp{self.service_pack}")
        return ":".join(x for x in bits if x)


@dataclass(slots=True)
class Package:
    name: str
    epoch: str
    version: str
    release: str
    arch: str
    vendor: str = ""
    packager: str = ""
    source_rpm: str = ""
    install_time: str = ""
    build_time: str = ""
    signature: str = ""
    raw_line: str = ""
    package_manager: str = "rpm"
    native_version: str = ""
    source_package: str = ""
    source_version: str = ""
    status: str = ""
    maintainer: str = ""
    origin: str = ""
    metadata_complete: bool = True
    validation_metadata: str = ""

    @property
    def evr(self) -> str:
        if self.package_manager.lower() in {"deb", "dpkg"}:
            return self.native_version or self.version
        epoch = self.epoch if self.epoch not in {"", "(none)", "None", "none"} else "0"
        return f"{epoch}:{self.version}-{self.release}" if self.release else f"{epoch}:{self.version}"

    @property
    def nevra(self) -> str:
        if self.package_manager.lower() in {"deb", "dpkg"}:
            return f"{self.name}_{self.installed_version}_{self.arch}"
        return f"{self.name}-{self.version}-{self.release}.{self.arch}" if self.release else f"{self.name}-{self.version}.{self.arch}"

    @property
    def installed_version(self) -> str:
        """Package-manager-native installed version used by vendor adapters."""
        return self.native_version or self.evr

    @property
    def source_name(self) -> str:
        if self.source_package:
            return self.source_package
        value = self.source_rpm or ""
        value = value.removesuffix(".src.rpm").removesuffix(".nosrc.rpm")
        # Source RPM is name-version-release; names themselves can contain '-'.
        return value.rsplit("-", 2)[0] if value else self.name

    @property
    def source_installed_version(self) -> str:
        """Version of the installed source package represented by this binary."""
        return self.source_version or self.installed_version

    @property
    def identity(self) -> str:
        """Stable cross-package-manager identity for indexing and diagnostics."""
        return f"{self.package_manager.lower()}:{self.name.lower()}:{self.arch.lower()}"

    @property
    def signature_keyid(self) -> str:
        import re
        m = re.search(r"Key ID\s+([0-9A-Fa-f]{8,40})", self.signature or "")
        return m.group(1).lower() if m else ""


@dataclass(slots=True)
class SoftwareComponent:
    kind: str
    product: str
    vendor: str
    version: str
    path: str
    build: str = ""
    architecture: str = ""
    evidence: str = ""


@dataclass(slots=True)
class Inventory:
    source_file: Path
    hostname: str
    fqdn: str
    collection_time_local: str
    collection_time_utc: str
    running_kernel: str
    uname: str
    os: OSIdentity
    packages: list[Package]
    software: list[SoftwareComponent] = field(default_factory=list)
    repository_evidence: str = ""
    warnings: list[str] = field(default_factory=list)
    context_file: str = ""
    assessment: dict[str, Any] = field(default_factory=dict)

    def package_index(self) -> dict[str, list[Package]]:
        out: dict[str, list[Package]] = {}
        for pkg in self.packages:
            out.setdefault(pkg.name.lower(), []).append(pkg)
        return out

    def source_package_index(self) -> dict[str, list[Package]]:
        """Index installed binary packages under their source package name."""
        out: dict[str, list[Package]] = {}
        for pkg in self.packages:
            out.setdefault(pkg.source_name.lower(), []).append(pkg)
        return out


@dataclass(slots=True)
class Evidence:
    source: str
    advisory: str = ""
    definition_id: str = ""
    feed_file: str = ""
    reference: str = ""
    evaluated_expression: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    host: str
    os: str
    package_name: str
    installed_evr: str
    package_arch: str
    cve: str
    status: FindingStatus
    confidence: str
    severity: str = "Info"
    cvss: str = ""
    description: str = ""
    fixed_evr: str = ""
    reason: str = ""
    solution: str = ""
    evidence: Evidence = field(default_factory=lambda: Evidence(source="Unknown"))
    kev: bool = False
    kev_date_added: str = ""
    epss_score: str = ""
    epss_percentile: str = ""
    cwe: str = ""
    references: list[str] = field(default_factory=list)
    source_rpm: str = ""
    package_vendor: str = ""
    package_packager: str = ""
    install_time: str = ""
    running_kernel: str = ""
    review_required: bool = False
    package_manager: str = "rpm"
    source_package: str = ""

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["evidence_source"] = self.evidence.source
        data["advisory"] = self.evidence.advisory
        data["definition_id"] = self.evidence.definition_id
        data["feed_file"] = self.evidence.feed_file
        data["reference"] = self.evidence.reference
        data["evaluated_expression"] = self.evidence.evaluated_expression
        data.pop("evidence", None)
        data["references"] = "\n".join(self.references)
        return data


@dataclass(slots=True)
class FeedStatus:
    key: str
    label: str
    path: Path
    url: str
    state: str
    message: str
    sha256: str = ""
    size: int = 0
    updated_at: str = ""
