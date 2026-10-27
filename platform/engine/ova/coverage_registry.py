"""Declared implementation scope, deliberately separate from feed freshness.

This is a capability inventory, NOT a claim that any host is fully assessed.
New adapters must explicitly register their version rules here.
"""
from pathlib import Path
from .feed_manager import vendor_feed_specs, feed_freshness

CATALOG = (
    ("redhat", "Red Hat Enterprise Linux", "6, 7, 8 (including 8.10), 9", "OVAL; base + explicitly configured support streams"),
    ("suse", "SUSE Linux Enterprise Server", "11, 12, 15; SP criteria require evaluation", "SLES OVAL; not all SUSE products"),
    ("debian", "Debian GNU/Linux", "Release/codename must exist in loaded evidence", "Tracker + DSA/DLA/ELA; historical coverage may be partial"),
    ("huawei", "Huawei HCE / EulerOS", "HCE 2.0, 3.0; EulerOS separately configured", "HCE advisories; exact product/version required"),
    ("ubuntu", "Ubuntu", "18.04, 20.04, 22.04, 24.04 (codename OVAL)", "Canonical USN + CVE OVAL; dpkginfo evaluation"),
    ("oracle", "Oracle Linux", "Not implemented", "Oracle Java support is NOT Oracle Linux support"),
    ("rocky", "Rocky Linux", "Not implemented", "Do not reuse RHEL decisions"),
    ("alma", "AlmaLinux", "Not implemented", "Do not reuse RHEL decisions"),
    ("centos", "CentOS / CentOS Stream", "Not implemented", "Dedicated release/stream mapping required"),
    ("amazon", "Amazon Linux", "Not implemented", "Dedicated ALAS adapter required"),
    ("fedora", "Fedora", "Not implemented", "Dedicated vendor adapter required"),
    ("opensuse", "openSUSE", "Not implemented", "SLES support is NOT openSUSE support"),
    ("alpine", "Alpine Linux", "Not implemented", "Native inventory only"),
    ("arch", "Arch Linux", "Not implemented", "Native inventory only"),
    ("mint", "Linux Mint", "Not implemented", "Do not substitute Ubuntu/Debian without package provenance"),
    ("kali", "Kali Linux", "Not implemented", "Do not substitute Debian without package provenance"),
    ("openeuler", "openEuler", "Not implemented", "Huawei HCE support is NOT openEuler support"),
)
IMPLEMENTED = frozenset({"redhat", "suse", "debian", "huawei", "ubuntu"})
VERSION_MAJORS = {"redhat": {"6", "7", "8", "9"}, "suse": {"11", "12", "15"}}


def coverage_rows(root: str | Path) -> list[dict]:
    """Offline inspection of registered vendor feeds only; NVD cannot add scope."""
    feeds = feed_freshness(root, vendor_feed_specs())
    rows = []
    for family, label, versions, note in CATALOG:
        matching = [r for r in feeds if r["group"] == family]
        counts = {key: sum(r["state"] == key for r in matching)
                  for key in ("current", "stale", "missing", "invalid")}
        state = "Adapter available; scope must be evaluated" if family in IMPLEMENTED else "Inventory only; vendor adapter not implemented"
        if family in IMPLEMENTED and not any(r["state"] in {"current", "stale"} for r in matching):
            state = "Vendor feed unavailable / invalid"
        rows.append({
            "family": family, "distribution": label, "versions": versions,
            "architecture": "Per-host and per-advisory; not universally certified",
            "implementation": state, "feed_state": counts,
            "note": note,
        })
    rows.insert(1, {
        "family": "redhat", "distribution": "RHEL 10+", "versions": "10 onward",
        "architecture": "Not implemented", "implementation": "CSAF adapter available when local CSAF JSON present",
        "feed_state": {}, "note": "OVAL covers RHEL 6-9; RHEL 10+ requires vendor/redhat/csaf/*.json",
    })
    return rows


def scope_preview(family: str, root: str | Path, inventory=None) -> str:
    """Conservative preview; the existing engine owns actual assessment results."""
    if family == "auto" and inventory is None:
        return "Coverage: choose an OS or a collector. Feed freshness does not establish OS coverage."
    if family == "auto":
        family = inventory.os.family
    if family not in IMPLEMENTED:
        return "Coverage: inventory only / vendor adapter not implemented. Current NVD feeds do not change this."
    if inventory is None:
        return "Coverage: adapter exists; host release, architecture and support stream have not been evaluated."
    os = inventory.os
    details = f"Collected: {os.pretty_name or os.product} | version={os.version or 'unknown'} | arch={os.architecture or 'unknown'}"
    if os.family != family:
        return f"Coverage: selected OS conflicts with collected OS; validation required. {details}"
    if not os.version or not os.architecture or any(not p.metadata_complete for p in inventory.packages):
        return f"Coverage: host/package metadata incomplete; not established. {details}"
    root = Path(root)
    if family in VERSION_MAJORS and os.major not in VERSION_MAJORS[family]:
        return f"Coverage: release not in the implemented catalog. {details}"
    if family == "redhat":
        major = os.major or ""
        if major.isdigit() and int(major) >= 10:
            csaf_dir = root / "vendor/redhat/csaf"
            available = csaf_dir.is_dir() and any(csaf_dir.rglob("*.json"))
            note = "RHEL 10+ uses CSAF JSON under vendor/redhat/csaf/; OVAL base streams stop at RHEL 9."
            return (
                f"Coverage: {'CSAF documents present (not proof of coverage)' if available else 'required CSAF documents missing'}. "
                f"{details}. {note}"
            )
        required = root / "vendor/redhat" / f"RHEL{os.major}" / f"rhel-{os.major}.oval.xml.bz2"
        note = "Base feed only; architecture, product and support-stream applicability still require evaluation."
    elif family == "suse":
        if os.product != "sles":
            return f"Coverage: product is outside the SLES catalog. {details}"
        required = root / "vendor/suse" / f"suse.linux.enterprise.server.{os.major}.xml.gz"
        note = f"Service pack={os.service_pack or 'unknown'}; exact product/SP criteria still require evaluation."
    elif family == "huawei":
        if os.product != "hce" or os.version not in {"2", "2.0", "3", "3.0"}:
            return f"Coverage: no standard HCE version match; EulerOS needs separately configured exact-version evidence. {details}"
        required = root / "vendor/huawei/hce" / f"{os.major}.0" / f"HCE{os.major}-SA.xml"
        note = "Exact product, architecture and advisory applicability still require evaluation."
    elif family == "ubuntu":
        code = (os.codename or "").split("-")[0].lower()
        if not code:
            return f"Coverage: Ubuntu codename missing; cannot select OVAL. {details}"
        usn = root / "vendor/ubuntu" / f"com.ubuntu.{code}.usn.oval.xml.bz2"
        cve = root / "vendor/ubuntu" / f"com.ubuntu.{code}.cve.oval.xml.bz2"
        available = (usn.is_file() and usn.stat().st_size > 0) or (cve.is_file() and cve.stat().st_size > 0)
        note = f"Canonical OVAL for codename={code}; dpkginfo fixed-threshold findings only."
        return (
            f"Coverage: {'candidate Ubuntu OVAL present (not proof of coverage)' if available else 'required Ubuntu OVAL missing'}. "
            f"{details}. {note}"
        )
    else:
        return f"Coverage: Debian release '{os.codename or 'unknown'}' must be checked in loaded tracker/advisories; historical-only evidence is partial. {details}"
    available = required.is_file() and required.stat().st_size > 0
    return f"Coverage: {'candidate feed present (not proof of coverage)' if available else 'required base feed missing'}. {details}. {note}"
