from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

from .models import Inventory, OSIdentity, Package, SoftwareComponent

# Accept both clean collector output and terminal captures copied from MobaXterm/SSH.
MARKER_RE = re.compile(r"=====\s*([A-Z0-9_]+)\s*=====", re.I)
# Bracketed shell prompts, ordinary user@host prompts, and appliance prompts
# such as ``SiNOS#`` are all present in customer terminal captures.
PROMPT_RE = re.compile(
    r"^(?:\[[^\]\r\n]+\]|(?:[A-Za-z0-9_.-]+@)?[A-Za-z0-9_.-]+(?::[^\s#$>]*)?)[#$>]\s*"
)
CONTINUATION_RE = re.compile(r"^>\s+")
FILE_HEADER_RE = re.compile(r"^---\s*(/[^\r\n]+?)\s*---$")
RPM_LINE_RE = re.compile(r"^[^|\r\n]+\|[^|\r\n]*\|[^|\r\n]+\|[^|\r\n]*\|[^|\r\n]+\|.*$")
ARCH_RE = re.compile(r"^(?:x86_64|aarch64|arm64|i[3-6]86|ppc64le|ppc64|s390x|riscv64|noarch)$", re.I)
DPKG_ARCH_RE = re.compile(
    r"^(?:all|amd64|i386|arm64|armel|armhf|mips|mipsel|mips64el|ppc64el|s390x|riscv64|x32)$",
    re.I,
)
DEB822_FIELD_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9-]*):\s*(.*)$")

SECTION_LINE_RE = re.compile(r"^\s*SECTION:\s*(.+?)\s*$", re.I)
META_LINE_RE = re.compile(r"^META\|([A-Z0-9_]+)\|(.+)$")
PKG_PIPE_RE = re.compile(r"^PKG\|([^|]+)\|([^|]+)\|([^|]*)$")


def _parse_pkg_pipe_line(line: str, default_manager: str = "rpm") -> Package | None:
    """Parse collector V6 line: PKG|name|version-release|arch"""
    s = _payload(line)
    m = PKG_PIPE_RE.match(s)
    if not m:
        return None
    name, ver_rel, arch = m.group(1).strip(), m.group(2).strip(), (m.group(3) or "").strip() or "noarch"
    epoch, version, release = "0", ver_rel, ""
    # deb style often has epoch:version
    if ":" in ver_rel and not ver_rel.startswith(":"):
        left, right = ver_rel.split(":", 1)
        if left.isdigit():
            epoch, ver_rel = left, right
            version = ver_rel
    # rpm style version-release (release often contains .elN)
    if "-" in ver_rel and default_manager == "rpm":
        # split last segment that looks like release (contains digits)
        parts = ver_rel.rsplit("-", 1)
        if len(parts) == 2 and re.search(r"\d", parts[1]):
            version, release = parts[0], parts[1]
        else:
            version = ver_rel
    else:
        version = ver_rel
    manager = "deb" if DPKG_ARCH_RE.match(arch) or arch in {"all", "amd64"} else default_manager
    if manager == "deb":
        return Package(
            name=name, epoch=_debian_epoch(ver_rel), version=version, release=release or "0",
            arch=arch, package_manager="deb", native_version=m.group(2).strip(),
            raw_line=s, metadata_complete=True,
        )
    return Package(
        name=name, epoch=epoch, version=version, release=release or "0",
        arch=arch, package_manager="rpm", raw_line=s, metadata_complete=True,
    )




def _payload(line: str) -> str:
    """Remove common shell prompt/continuation prefixes without changing data rows."""
    s = line.strip("\r\n")
    s = PROMPT_RE.sub("", s).strip()
    s = CONTINUATION_RE.sub("", s).strip()
    return s


def _is_command(line: str) -> bool:
    s = _payload(line)
    if not s:
        return False
    patterns = (
        r"^(?:export|setenv)\b",
        r"^echo\b",
        r"^printf\b",
        r"^date(?:\s|$)",
        r"^hostname(?:\s|$)",
        r"^uname(?:\s|$)",
        r"^cat\s+",
        r"^grep\s+",
        r"^find\s+",
        r"^rpm\s+-q",
        r"^rpm\s+-qa",
        r"^dpkg-query\b",
        r"^dpkg\s+--",
        r"^for\s+",
        r"^if\s+",
        r"^then$",
        r"^else$",
        r"^fi$",
        r"^do$",
        r"^done$",
        r"^subscription-manager\b",
        r"^(?:enable|en|whoami)$",
    )
    return any(re.match(p, s, re.I) for p in patterns)


def _clean_epoch(value: str) -> str:
    value = value.strip()
    return "0" if value.lower() in {"", "(none)", "none"} else value


def _parse_os_release(release_files: dict[str, str], fallback_text: str) -> OSIdentity:
    ordered = [key for key in ("/etc/os-release", "/usr/lib/os-release") if key in release_files]
    ordered.extend(key for key in release_files if key not in ordered)
    merged = "\n".join(release_files[key] for key in ordered) or fallback_text
    data: dict[str, str] = {}
    for raw in merged.splitlines():
        line = _payload(raw)
        if "=" not in line or _is_command(line):
            continue
        key, value = line.split("=", 1)
        key = key.strip().upper()
        value = value.strip().strip('"').strip("'")
        if key in {
            "NAME", "VERSION", "VERSION_ID", "PRETTY_NAME", "ID", "ID_LIKE", "CPE_NAME",
            "VERSION_CODENAME", "DEBIAN_CODENAME",
        }:
            data.setdefault(key, value)

    pretty = data.get("PRETTY_NAME") or data.get("NAME") or ""
    version = data.get("VERSION_ID") or data.get("VERSION") or ""
    os_id = data.get("ID", "").lower()
    id_like = data.get("ID_LIKE", "").lower()
    lower = f"{os_id} {id_like} {pretty} {merged}".lower()

    family = "unknown"
    product = os_id or "unknown"
    # These IDs need exact handling before fuzzy inspection of a raw terminal
    # transcript. A Debian package description may mention Ubuntu/Red Hat, but
    # that must not change the explicitly declared operating system.
    known_ids = {
        "rhel": ("redhat", "rhel"), "sles": ("suse", "sles"),
        "sled": ("suse", "sled"), "rocky": ("redhat-compatible", "rocky"),
        "almalinux": ("redhat-compatible", "almalinux"),
        "centos": ("redhat-compatible", "centos"), "ol": ("oracle", "oraclelinux"),
        "amzn": ("amazon-linux", "amazon-linux"), "fedora": ("fedora", "fedora"),
        "opensuse": ("opensuse", "opensuse"), "opensuse-leap": ("opensuse", "opensuse"),
        "opensuse-tumbleweed": ("opensuse", "opensuse"), "alpine": ("alpine", "alpine"),
        "arch": ("arch", "arch"), "linuxmint": ("mint", "linuxmint"),
        "openeuler": ("openeuler", "openeuler"),
    }
    if os_id in known_ids:
        family, product = known_ids[os_id]
    elif os_id == "debian":
        family, product = "debian", "debian"
    elif os_id == "ubuntu":
        family, product = "ubuntu", "ubuntu"
    elif os_id in {"kali", "kali-linux"}:
        family, product = "kali", "kali"
    elif any(x in lower for x in ["sles", "suse linux enterprise server"]):
        family, product = "suse", "sles"
    elif "hce" in lower or "huawei cloud euleros" in lower:
        family, product = "huawei", "hce"
    elif "euleros" in lower:
        family, product = "huawei", "euleros"
    elif "openeuler" in lower:
        family, product = "openeuler", "openeuler"
    elif any(x in lower for x in ["red hat enterprise linux", " rhel", "rhel "]):
        family, product = "redhat", "rhel"
    elif "centos" in lower:
        family, product = "redhat-compatible", "centos"
    elif "rocky" in lower:
        family, product = "redhat-compatible", "rocky"
    elif "almalinux" in lower or "alma linux" in lower:
        family, product = "redhat-compatible", "almalinux"
    elif "oracle linux" in lower:
        family, product = "oracle", "oraclelinux"

    major = minor = service_pack = ""
    nums = re.findall(r"\d+", version)
    if nums:
        major = nums[0]
        minor = nums[1] if len(nums) > 1 else ""
    sp_match = re.search(r"\bSP\s*(\d+)\b", pretty, re.I)
    if sp_match:
        service_pack = sp_match.group(1)
    elif product == "sles" and minor:
        service_pack = minor

    codename = data.get("VERSION_CODENAME") or data.get("DEBIAN_CODENAME") or ""
    if not codename and product == "debian":
        codename_match = re.search(r"\(([^()]+)\)", data.get("VERSION", ""))
        if codename_match:
            codename = codename_match.group(1).strip().lower()
        else:
            codename = {"9": "stretch", "10": "buster", "11": "bullseye", "12": "bookworm", "13": "trixie"}.get(major, "")

    return OSIdentity(
        family=family,
        product=product,
        version=version,
        major=major,
        minor=minor,
        service_pack=service_pack,
        pretty_name=pretty or (f"{product} {version}".strip() if product != "unknown" else ""),
        cpe_name=data.get("CPE_NAME", ""),
        id_like=id_like,
        release_files=release_files,
        codename=codename,
        support_suite=codename,
    )


def _infer_os_from_packages(identity: OSIdentity, packages: list[Package]) -> OSIdentity:
    """Second-line OS inference for package-only captures.

    Do not override explicit /etc/os-release evidence. This exists so a valid
    RPM inventory cannot silently disable the vendor adapter just because the
    terminal capture omitted the OS section.
    """
    if identity.family != "unknown" and identity.product != "unknown":
        return identity

    idx: dict[str, list[Package]] = {}
    for p in packages:
        idx.setdefault(p.name.lower(), []).append(p)

    for key in ("redhat-release", "redhat-release-server", "redhat-release-workstation"):
        rows = idx.get(key, [])
        if rows:
            p = rows[0]
            nums = re.findall(r"\d+", p.version)
            major = nums[0] if nums else ""
            minor = nums[1] if len(nums) > 1 else ""
            version = ".".join(x for x in (major, minor) if x) or p.version
            return OSIdentity(
                family="redhat", product="rhel", version=version, major=major, minor=minor,
                pretty_name=f"Red Hat Enterprise Linux {version}".strip(), architecture=p.arch,
                release_files=identity.release_files,
            )

    for key in ("sles-release", "sle-release"):
        rows = idx.get(key, [])
        if rows:
            p = rows[0]
            nums = re.findall(r"\d+", p.version)
            major = nums[0] if nums else ""
            minor = nums[1] if len(nums) > 1 else ""
            version = ".".join(x for x in (major, minor) if x) or p.version
            return OSIdentity(
                family="suse", product="sles", version=version, major=major, minor=minor,
                service_pack=minor, pretty_name=f"SUSE Linux Enterprise Server {version}".strip(),
                architecture=p.arch, release_files=identity.release_files,
            )

    # Conservative vendor/release fallback. This is only used when a release
    # package is absent. It identifies the distro family/major, not a support stream.
    redhat_rows = [p for p in packages if "red hat" in f"{p.vendor} {p.packager}".lower()]
    if redhat_rows:
        major_counts: dict[str, int] = {}
        for p in redhat_rows:
            m = re.search(r"\.el(\d+)(?:[_.]|$)", p.release)
            if m:
                major_counts[m.group(1)] = major_counts.get(m.group(1), 0) + 1
        if major_counts:
            major = max(major_counts, key=major_counts.get)
            return OSIdentity(
                family="redhat", product="rhel", version=major, major=major,
                pretty_name=f"Red Hat Enterprise Linux {major} (inferred from RPM metadata)",
                architecture=redhat_rows[0].arch, release_files=identity.release_files,
            )
    return identity


def _parse_java_components(lines: list[str]) -> list[SoftwareComponent]:
    components: list[SoftwareComponent] = []
    current_path = ""
    attrs: dict[str, str] = {}

    def flush() -> None:
        nonlocal current_path, attrs
        if not current_path and not attrs:
            return
        version = attrs.get("JAVA_VERSION", "").strip('"')
        vendor = (attrs.get("IMPLEMENTOR") or attrs.get("JAVA_VENDOR") or "").strip('"')
        arch = (attrs.get("OS_ARCH") or "").strip('"')
        build = (attrs.get("BUILD_TYPE") or attrs.get("JAVA_RUNTIME_VERSION") or "").strip('"')
        if current_path or version:
            components.append(SoftwareComponent(
                kind="runtime", product="Java SE", vendor=vendor or "Unknown",
                version=version, path=current_path, build=build, architecture=arch,
                evidence="release file / self-reported Java metadata",
            ))
        current_path, attrs = "", {}

    for raw in lines:
        s = _payload(raw)
        if not s or _is_command(s):
            continue
        if s.startswith("--- JAVA_HOME=") and s.endswith(" ---"):
            flush()
            current_path = s[len("--- JAVA_HOME="):-len(" ---")].strip()
            continue
        if s.startswith("JAVA_HOME="):
            flush()
            current_path = s.split("=", 1)[1].strip().strip('"')
            continue
        if "=" in s:
            k, v = s.split("=", 1)
            if k.strip().upper() in {"JAVA_VERSION", "IMPLEMENTOR", "JAVA_VENDOR", "OS_ARCH", "BUILD_TYPE", "JAVA_RUNTIME_VERSION"}:
                attrs[k.strip().upper()] = v.strip()
    flush()
    return components


def _extract_raw_release_files(lines: list[str]) -> dict[str, str]:
    """Recover os-release from appliance transcripts that have no VA markers."""
    files: dict[str, str] = {}
    current = ""
    values: list[str] = []

    def flush() -> None:
        nonlocal current, values
        if current and values:
            files[current] = "\n".join(values)
        current, values = "", []

    for raw in lines:
        s = _payload(raw)
        command = re.match(r"^cat\s+\S*(/etc/(?:os-release|debian_version))\s*$", s, re.I)
        if command:
            flush()
            current = command.group(1)
            continue
        if not current:
            continue
        if PROMPT_RE.match(raw.strip()) or _is_command(s):
            flush()
            continue
        if current.endswith("os-release"):
            if re.match(r"^[A-Z][A-Z0-9_]*=", s):
                values.append(s)
            elif values:
                flush()
        elif current.endswith("debian_version"):
            if re.fullmatch(r"[A-Za-z0-9.+~_-]+", s):
                values.append(s)
            elif values:
                flush()
    flush()
    return files


def _debian_source(value: str, binary_name: str, binary_version: str) -> tuple[str, str]:
    """Parse Debian's ``Source: name (version)`` control-field syntax."""
    value = value.strip()
    if not value:
        return binary_name, binary_version
    match = re.fullmatch(r"([^\s()]+)(?:\s+\(([^()]+)\))?", value)
    if not match:
        # A malformed source field must never shift neighboring columns.
        return binary_name, binary_version
    return match.group(1), (match.group(2) or binary_version)


def _debian_epoch(version: str) -> str:
    prefix, separator, _ = version.partition(":")
    return prefix if separator and prefix.isdigit() else "0"


def _debian_package(
    *,
    name: str,
    status: str,
    native_version: str,
    arch: str,
    source_value: str = "",
    source_version: str = "",
    maintainer: str = "",
    origin: str = "",
    raw_line: str = "",
) -> Package | None:
    name = name.strip()
    status = " ".join(status.lower().split())
    native_version = native_version.strip()
    arch = arch.strip().lower()
    if len(status.split()) != 3 or status.split()[1:] != ["ok", "installed"] or not name or not native_version or not DPKG_ARCH_RE.match(arch):
        return None
    # ${binary:Package} includes an architecture qualifier when required.
    if ":" in name and name.rsplit(":", 1)[1].lower() == arch:
        name = name.rsplit(":", 1)[0]
    source_name, inferred_source_version = _debian_source(source_value, name, native_version)
    actual_source_version = source_version.strip() or inferred_source_version
    return Package(
        name=name,
        epoch=_debian_epoch(native_version),
        version=native_version,
        release="",
        arch=arch,
        vendor=origin.strip(),
        packager=maintainer.strip(),
        raw_line=raw_line,
        package_manager="dpkg",
        native_version=native_version,
        source_package=source_name,
        source_version=actual_source_version,
        status=status,
        maintainer=maintainer.strip(),
        origin=origin.strip(),
    )


def _dedupe_debian(packages: list[Package]) -> list[Package]:
    out: list[Package] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for pkg in packages:
        key = (pkg.name, pkg.native_version, pkg.arch, pkg.source_package, pkg.source_version)
        if key not in seen:
            seen.add(key)
            out.append(pkg)
    return out


def _parse_structured_dpkg(lines: list[str]) -> list[Package]:
    """Parse the pipe-delimited rows emitted by the safe Debian collector."""
    packages: list[Package] = []
    for raw in lines:
        s = _payload(raw)
        if not s or _is_command(s) or "${" in s:
            continue
        # Schema: binary|Status|Version|Architecture|source|source-version|
        #         Maintainer|Origin. Origin is optional on many installations.
        parts = [part.strip() for part in s.split("|", 7)]
        if len(parts) < 7:
            continue
        if len(parts) == 7 and DPKG_ARCH_RE.fullmatch(parts[2]):
            # New collector: binary|version|arch|source|source-version|maintainer|status.
            name, version, arch, source_name, source_version, maintainer, status = parts
            origin = ""
        else:
            # Retain the original status-first schema.
            name, status, version, arch, source_name, source_version, maintainer = parts[:7]
            origin = parts[7] if len(parts) >= 8 else ""
        pkg = _debian_package(
            name=name,
            status=status,
            native_version=version,
            arch=arch,
            source_value=source_name,
            source_version=source_version,
            maintainer=maintainer,
            origin=origin,
            raw_line=s,
        )
        if pkg:
            packages.append(pkg)
    return _dedupe_debian(packages)


def _parse_raw_dpkg_status(lines: list[str]) -> list[Package]:
    """Parse repeated raw /var/lib/dpkg/status dumps from terminal captures.

    Requiring all of Package, Status, Version and Architecture intentionally
    rejects lossy two-column package/version lists: those cannot prove package
    status, architecture, or source-package provenance.
    """
    packages: list[Package] = []
    fields: dict[str, str] = {}
    raw_fields: list[str] = []

    def flush() -> None:
        nonlocal fields, raw_fields
        if fields:
            pkg = _debian_package(
                name=fields.get("Package", ""),
                status=fields.get("Status", ""),
                native_version=fields.get("Version", ""),
                arch=fields.get("Architecture", ""),
                source_value=fields.get("Source", ""),
                maintainer=fields.get("Maintainer", ""),
                origin=fields.get("Origin", ""),
                raw_line="\n".join(raw_fields),
            )
            if pkg:
                packages.append(pkg)
        fields, raw_fields = {}, []

    for raw in lines:
        # Deb822 continuation lines are data belonging to the preceding field.
        # Do not let text such as " Package: ..." inside Description become a
        # new control field after _payload() trims whitespace.
        if raw.startswith((" ", "\t")):
            continue
        s = _payload(raw)
        if not s:
            flush()
            continue
        match = DEB822_FIELD_RE.match(s)
        if not match:
            # Shell/appliance commands delimit stanzas even in imperfect logs.
            if PROMPT_RE.match(raw.strip()) or _is_command(s):
                flush()
            continue
        key, value = match.group(1), match.group(2).strip()
        if key == "Package" and "Package" in fields:
            flush()
        fields[key] = value
        raw_fields.append(s)
    flush()
    return _dedupe_debian(packages)


def _parse_package_version_list(lines: list[str]) -> list[Package]:
    """Retain complete two-column inventories without inventing source metadata.

    Every nonblank line must conform: a shifted/damaged list is not silently
    salvaged into plausible package/version pairs.
    """
    rows = [line.strip().split() for line in lines if line.strip()]
    if not rows or any(
        len(row) != 2
        or not re.fullmatch(r"[a-z0-9][a-z0-9+._-]*(?::[a-z0-9_-]+)?", row[0])
        or not re.fullmatch(r"[0-9][A-Za-z0-9.+:~_-]*", row[1])
        for row in rows
    ):
        return []
    return [Package(
        name=name, epoch="", version=version, release="", arch="",
        native_version=version, package_manager="unknown", metadata_complete=False,
        status="Reported in package/version list; installation metadata not collected",
        raw_line=f"{name}\t{version}",
    ) for name, version in dict.fromkeys(tuple(row) for row in rows)]


def attach_inventory_context(inventory: Inventory, context_path: str | Path) -> Inventory:
    """Use explicitly supplied collector metadata only for exact matching rows."""
    context = parse_inventory(context_path)
    index: dict[tuple[str, str], list[Package]] = {}
    for pkg in context.packages:
        if pkg.metadata_complete:
            index.setdefault((pkg.name, pkg.installed_version), []).append(pkg)
    matched: list[Package] = []
    for pkg in inventory.packages:
        if pkg.metadata_complete:
            raise ValueError("A metadata collector is only needed for a two-column package/version list.")
        options = index.get((pkg.name, pkg.installed_version), [])
        if len(options) != 1:
            raise ValueError(f"Collector metadata must match exactly one installed package for {pkg.name}={pkg.installed_version}; found {len(options)}. No context was applied.")
        matched.append(replace(options[0]))
    if not matched or context.os.family == "unknown":
        raise ValueError("The metadata collector must contain installed packages and an identified OS.")
    return replace(
        inventory, packages=matched, os=context.os, hostname=context.hostname,
        fqdn=context.fqdn, running_kernel=context.running_kernel, uname=context.uname,
        collection_time_local=context.collection_time_local,
        collection_time_utc=context.collection_time_utc,
        repository_evidence=context.repository_evidence, context_file=str(Path(context_path)),
        warnings=[f"Metadata supplied by {Path(context_path).name}; all {len(matched)} input package names and versions exactly matched the supplied collector. Host/OS/source metadata describe that collector snapshot."] + context.warnings,
    )


def _parse_native_database(lines: list[str], manager: str) -> list[Package]:
    """Installed APK/pacman inventory only; no RPM or Debian version guesses."""
    fields: dict[str, str] = {}
    records: dict[tuple, Package] = {}
    keys = {"P": "name", "V": "version", "A": "arch", "o": "source"} if manager == "apk" else {"Name": "name", "Version": "version", "Architecture": "arch", "Packager": "vendor"}
    for raw in [*lines, ""]:
        line = _payload(raw)
        if not line:
            name, version = fields.get("name", ""), fields.get("version", "")
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.:@-]*", name) and version and not re.search(r"\s", version):
                pkg = Package(name, "0", version, "", fields.get("arch", ""), package_manager=manager, native_version=version, source_package=fields.get("source", ""), vendor=fields.get("vendor", ""), status="installed")
                records[(name, version, pkg.arch)] = pkg
            fields = {}
        elif ":" in line:
            key, value = line.split(":", 1)
            if key.strip() in keys:
                fields[keys[key.strip()]] = value.strip()
    return list(records.values())


def _parse_native_rows(lines: list[str], manager: str, fallback: bool = False) -> list[Package]:
    records: dict[tuple, Package] = {}
    for raw in lines:
        line = _payload(raw)
        parts = line.split() if fallback else [x.strip() for x in line.split("|")]
        if fallback:
            if len(parts) != 2:
                continue
            name, version = parts
            arch = source_name = maintainer = build = installed = validation = ""
        elif manager == "apk" and len(parts) == 6:
            name, version, arch, source_name, maintainer, build = parts
            installed = validation = ""
        elif manager == "pacman" and len(parts) == 8:
            name, version, source_name, arch, build, installed, maintainer, validation = parts
        else:
            continue
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.:@-]*", name) or not version or re.search(r"\s", version):
            continue
        if fallback and (name.isupper() or name == "pacman"):
            continue
        pkg = Package(
            name, "0", version, "", arch, package_manager=manager,
            native_version=version, source_package=source_name, packager=maintainer,
            maintainer=maintainer, build_time=build, install_time=installed,
            validation_metadata=validation, status="installed",
            metadata_complete=not fallback and bool(arch), raw_line=line,
        )
        records[(name, version, arch)] = pkg
    return list(records.values())


def parse_inventory(path: str | Path) -> Inventory:
    source = Path(path)
    text = source.read_text(encoding="utf-8-sig", errors="replace")
    lines = text.splitlines()

    sections: dict[str, list[str]] = {"PREAMBLE": []}
    current = "PREAMBLE"
    for raw in lines:
        payload = _payload(raw)
        marker = MARKER_RE.search(payload)
        if marker:
            current = marker.group(1).upper().replace(" ", "_")
            sections.setdefault(current, [])
            continue
        sm = SECTION_LINE_RE.match(payload)
        if sm:
            # LINUX_REPORT_SAFE_V6 style: "SECTION: PACKAGE INVENTORY"
            current = re.sub(r"[^A-Z0-9]+", "_", sm.group(1).upper()).strip("_")
            sections.setdefault(current, [])
            continue
        sections.setdefault(current, []).append(raw)

    def section_data(name: str) -> list[str]:
        return sections.get(name, [])

    def clean_values(name: str) -> list[str]:
        out: list[str] = []
        for raw in section_data(name):
            s = _payload(raw)
            if not s or _is_command(s) or MARKER_RE.search(s):
                continue
            out.append(s)
        return out

    # META| from collector V6 (anywhere in file)
    meta: dict[str, str] = {}
    for raw in lines:
        s = _payload(raw)
        mm = META_LINE_RE.match(s)
        if mm:
            meta[mm.group(1).upper()] = mm.group(2).strip()

    host_values = clean_values("HOSTNAME")
    hostname = meta.get("HOSTNAME") or next((x for x in host_values if re.fullmatch(r"[A-Za-z0-9_.:-]+", x)), "")
    if not hostname:
        hostname = meta.get("HOSTNAME_FULL", "").split(".")[0] or source.stem.split("_")[0]
    fqdn = next((x for x in host_values if "." in x and x != hostname and re.fullmatch(r"[A-Za-z0-9_.:-]+", x)), "")

    kernel_values = clean_values("KERNEL_RUNNING")
    uname = next((x for x in kernel_values if x.startswith("Linux ")), "")
    if not uname:
        uname = next((x for x in clean_values("OS_AND_KERNEL") if x.startswith("Linux ")), "")
    running_kernel = next((x for x in kernel_values if " " not in x and re.search(r"\d", x)), "")
    if not running_kernel and uname:
        parts = uname.split()
        running_kernel = parts[2] if len(parts) > 2 else ""
    if not running_kernel:
        raw_kernel = next((_payload(x) for x in lines if _payload(x).startswith("Linux version ")), "")
        if raw_kernel:
            parts = raw_kernel.split()
            running_kernel = parts[2] if len(parts) > 2 else ""
            uname = raw_kernel

    release_files: dict[str, str] = {}
    current_file = "/etc/os-release"
    buff: list[str] = []
    for raw in section_data("OS_RELEASE"):
        s = _payload(raw)
        if not s or _is_command(s):
            continue
        fm = FILE_HEADER_RE.match(s)
        if fm:
            if buff:
                release_files[current_file] = "\n".join(buff)
            current_file, buff = fm.group(1), []
            continue
        buff.append(s)
    if buff:
        release_files[current_file] = "\n".join(buff)
    if not release_files:
        for alt in ("OS_AND_KERNEL", "CONTEXT"):
            alt_lines = section_data(alt)
            body = [_payload(x) for x in alt_lines if "=" in _payload(x)]
            if any(b.startswith("PRETTY_NAME=") or b.startswith("ID=") for b in body):
                release_files["/etc/os-release"] = "\n".join(body)
                break
    if not release_files:
        release_files = _extract_raw_release_files(lines)
    release_fallback = section_data("OS_RELEASE") or section_data("OS_AND_KERNEL") or lines
    os_identity = _parse_os_release(release_files, "\n".join(_payload(x) for x in release_fallback))

    if uname:
        uname_parts = uname.split()
        os_identity.architecture = next((part for part in reversed(uname_parts) if ARCH_RE.match(part)), os_identity.architecture)
    machine_arch = clean_values("MACHINE_ARCHITECTURE")
    if machine_arch and ARCH_RE.fullmatch(machine_arch[0]):
        os_identity.architecture = machine_arch[0]

    warnings: list[str] = clean_values("COLLECTOR_WARNINGS")
    dpkg_marker_present = "DPKG_INVENTORY" in sections
    packages: list[Package] = _parse_structured_dpkg(section_data("DPKG_INVENTORY")) if dpkg_marker_present else []
    if dpkg_marker_present and not packages:
        warnings.append("DPKG_INVENTORY marker was found, but no installed dpkg package rows were valid.")
    if not dpkg_marker_present or "DPKG_STATUS_DATABASE" in sections:
        raw_dpkg_packages = _parse_raw_dpkg_status(section_data("DPKG_STATUS_DATABASE") if "DPKG_STATUS_DATABASE" in sections else lines)
        if raw_dpkg_packages:
            # Native status is authoritative for legacy dpkg virtual fields.
            identities = {(p.name, p.native_version, p.arch) for p in raw_dpkg_packages}
            packages = [p for p in packages if (p.name, p.native_version, p.arch) not in identities]
            packages.extend(raw_dpkg_packages)
            if not dpkg_marker_present:
                warnings.append("DPKG_INVENTORY marker not found; raw /var/lib/dpkg/status fallback was parsed and deduplicated.")

    for marker, manager in (("APK_INSTALLED_DATABASE", "apk"), ("PACMAN_INVENTORY", "pacman")):
        if marker in sections:
            packages.extend(_parse_native_database(section_data(marker), manager))
    for marker, manager in (("APK_INVENTORY", "apk"), ("PACMAN_INVENTORY", "pacman")):
        packages.extend(_parse_native_rows(section_data(marker), manager))
    if not any(p.package_manager == "pacman" for p in packages):
        packages.extend(_parse_native_rows(section_data("PACMAN_INVENTORY_FALLBACK"), "pacman", fallback=True))

    rpm_marker_present = "RPM_INVENTORY_NEVRA" in sections
    native_marker_present = any(key in sections for key in ("DPKG_INVENTORY", "DPKG_STATUS_DATABASE", "APK_INVENTORY", "APK_INSTALLED_DATABASE", "PACMAN_INVENTORY", "PACMAN_INVENTORY_FALLBACK"))
    rpm_lines = section_data("RPM_INVENTORY_NEVRA") if rpm_marker_present else ([] if packages or native_marker_present else lines)
    if not rpm_marker_present and rpm_lines:
        warnings.append("RPM_INVENTORY_NEVRA marker not found; strict fallback parser was used.")

    seen: set[tuple[str, str, str, str, str]] = set()
    for raw in rpm_lines:
        s = _payload(raw)
        if not s or _is_command(s) or not RPM_LINE_RE.match(s):
            continue
        if "%{NAME}" in s or " --qf " in s or s.startswith("rpm -"):
            continue
        parts = [x.strip() for x in s.split("|")]
        if len(parts) < 9:
            continue
        name, epoch, version, release, arch, vendor, packager, source_rpm = parts[:8]
        if not name or not version or not ARCH_RE.match(arch):
            continue
        # Collector schemas supported:
        # 9  fields: ... SOURCERPM | INSTALLTIME
        # 10 fields: ... SOURCERPM | INSTALLTIME | BUILDTIME
        # 11+ fields: above + signature text (remaining pipes are preserved)
        install_time = parts[8] if len(parts) >= 9 else ""
        build_time = parts[9] if len(parts) >= 10 else ""
        signature = "|".join(parts[10:]).strip() if len(parts) >= 11 else ""
        pkg = Package(
            name=name, epoch=_clean_epoch(epoch), version=version, release=release, arch=arch,
            vendor=vendor, packager=packager, source_rpm=source_rpm,
            install_time=install_time, build_time=build_time, signature=signature, raw_line=s,
        )
        key = (pkg.name, pkg.evr, pkg.arch, pkg.source_rpm, pkg.vendor)
        if key in seen:
            continue
        seen.add(key)
        packages.append(pkg)

    signature_rows: dict[tuple, set[str]] = {}
    for line in clean_values("RPM_SIGNATURE_METADATA"):
        parts = line.split("|", 5)
        if len(parts) == 6:
            name, epoch, version, release, arch, metadata = parts
            key = (name, _clean_epoch(epoch), version, release, arch)
            signature_rows.setdefault(key, set()).add(metadata.rstrip("|"))
    for pkg in packages:
        key = (pkg.name, pkg.epoch, pkg.version, pkg.release, pkg.arch)
        values = signature_rows.get(key, set()) if pkg.package_manager == "rpm" else set()
        if len(values) == 1:
            pkg.signature = next(iter(values))
        elif len(values) > 1:
            pkg.signature = ""
            warnings.append(f"Conflicting RPM signature metadata for {pkg.nevra}; signature not assigned.")
    if "RPM_SIGNATURE_QUERY_UNSUPPORTED" in warnings:
        for pkg in packages:
            if pkg.package_manager == "rpm":
                pkg.signature = ""

    # LINUX_REPORT_SAFE_V6: PKG|name|ver|arch under PACKAGE_INVENTORY (or whole file)
    if not packages:
        pkg_section = section_data("PACKAGE_INVENTORY") or section_data("PACKAGE") or []
        if not pkg_section:
            pkg_section = [raw for raw in lines if PKG_PIPE_RE.match(_payload(raw))]
        guessed = "rpm"
        for raw in pkg_section:
            m = PKG_PIPE_RE.match(_payload(raw))
            if m and DPKG_ARCH_RE.match((m.group(3) or "").strip()):
                guessed = "deb"
                break
        for raw in pkg_section:
            pkg = _parse_pkg_pipe_line(raw, default_manager=guessed)
            if pkg:
                packages.append(pkg)
        if packages:
            warnings.append(f"Parsed {len(packages)} packages from collector PKG| inventory (LINUX_REPORT_SAFE_V6 style).")

    if meta.get("OS_FAMILY") and (not os_identity.family or os_identity.family == "unknown"):
        fam = meta["OS_FAMILY"].strip().lower()
        os_identity = replace(os_identity, family=fam)
    if meta.get("OS_VERSION") and not os_identity.version:
        ver = meta["OS_VERSION"].strip()
        major = ver.split(".")[0]
        os_identity = replace(os_identity, version=ver, major=major)
    if meta.get("HOSTNAME_FULL") and not fqdn:
        fqdn = meta["HOSTNAME_FULL"]

    if not packages and not native_marker_present and not rpm_marker_present:
        packages = _parse_package_version_list(lines)
        if packages:
            warnings = [w for w in warnings if "strict fallback parser" not in w]
            warnings.append("Package/version list imported. OS release, architecture, installation status and source-package mapping are not present. Select the full metadata collector for this same host to enable vulnerability assessment.")
    os_identity = _infer_os_from_packages(os_identity, [p for p in packages if p.metadata_complete])
    if not os_identity.architecture:
        arch_counts: dict[str, int] = {}
        for p in packages:
            if p.arch not in {"noarch", "all"}:
                arch_counts[p.arch] = arch_counts.get(p.arch, 0) + 1
        if arch_counts:
            os_identity.architecture = max(arch_counts, key=arch_counts.get)

    software = _parse_java_components(section_data("JAVA_INSTALLATIONS"))
    repo_sections = ("RHEL_REPOSITORY_CONFIG", "APT_REPOSITORY_CONFIG", "PACKAGE_REPOSITORY_CONFIG",
                     "RPM_REPOSITORY_CONFIG_EVIDENCE", "SUSE_REPOSITORY_CONFIG_EVIDENCE",
                     "APT_REPOSITORY_CONFIG_EVIDENCE", "APK_REPOSITORY_CONFIG_EVIDENCE",
                     "PACMAN_REPOSITORY_CONFIG_EVIDENCE")
    repository_evidence = "\n".join(value for marker in repo_sections for value in clean_values(marker))
    if repository_evidence:
        warnings.append("Repository configuration evidence only; effective enabled repositories were not queried. Missing enabled= is unknown, not disabled.")

    # Platform / container intelligence from enhanced collector (scope, not vulns by itself)
    platform_notes: list[str] = []
    found_procs = [
        line.strip() for line in section_data("CONTAINER_PROCESS_SCAN")
        if line.strip().startswith("--- FOUND:")
    ]
    if found_procs:
        names = []
        for line in found_procs:
            # --- FOUND: dockerd ---
            name = line.replace("--- FOUND:", "").replace("---", "").strip()
            if name:
                names.append(name)
        if names:
            platform_notes.append("container_runtimes=" + ",".join(dict.fromkeys(names)))
    svc_lines = [
        line.strip() for line in section_data("SYSTEMD_SERVICE_STATE")
        if "|active=" in line and "active=active" in line
    ]
    if svc_lines:
        active = [line.split("|", 1)[0] for line in svc_lines]
        platform_notes.append("active_services=" + ",".join(dict.fromkeys(active)))
    fs_hits = [
        line.strip() for line in section_data("FILESYSTEM_INDICATORS")
        if line.strip().startswith("EXISTS:")
    ]
    if fs_hits:
        platform_notes.append(f"fs_indicators={len(fs_hits)}")
    cgroup_hits = [
        line.strip() for line in section_data("CGROUP_CONTAINER_HINTS")
        if line.strip() and not line.strip().startswith("=====")
    ]
    if cgroup_hits:
        platform_notes.append("nested_or_cgroup=" + ",".join(dict.fromkeys(cgroup_hits))[:200])
    bin_vers = [
        line.strip() for line in section_data("NON_PKG_BINARY_VERSIONS")
        if "|" in line.strip()
    ]
    if bin_vers:
        platform_notes.append(f"extra_binaries={len(bin_vers)}")
        # Surface standalone runtime binaries as software-like evidence for report scope
        for line in bin_vers[:40]:
            parts = line.split("|", 2)
            if len(parts) >= 2:
                warnings.append(
                    f"Platform binary outside package DB: {parts[0]} path={parts[1]}"
                    + (f" ver={parts[2]}" if len(parts) > 2 else "")
                )
    if platform_notes:
        warnings.append("Platform intelligence: " + "; ".join(platform_notes))

    if not packages:
        warnings.append("No valid installed package rows were parsed.")
    if "VA_OFFLINE_INVENTORY_BEGIN" in sections and "VA_OFFLINE_INVENTORY_END" not in sections:
        warnings.append("failed: Collector capture is truncated; end marker is missing.")
    if "VA_CONTAINER_INVENTORY_BEGIN" in sections and "VA_CONTAINER_INVENTORY_END" not in sections:
        warnings.append("Container/platform section is truncated; platform intelligence may be incomplete.")
    if os_identity.family == "unknown":
        warnings.append("OS identity could not be determined from release files or package evidence.")
    elif not release_files:
        manager = packages[0].package_manager if packages else "package"
        warnings.append(f"OS identity inferred from {manager} evidence: {os_identity.pretty_name}.")

    def first_value(name: str) -> str:
        vals = clean_values(name)
        return vals[0] if vals else ""

    return Inventory(
        source_file=source,
        hostname=hostname,
        fqdn=fqdn,
        collection_time_local=first_value("COLLECTION_TIME_LOCAL"),
        collection_time_utc=first_value("COLLECTION_TIME_UTC"),
        running_kernel=running_kernel,
        uname=uname,
        os=os_identity,
        packages=packages,
        software=software,
        repository_evidence=repository_evidence,
        warnings=warnings,
    )
