from __future__ import annotations

import bz2
import csv
import gzip
import hashlib
import json
import os
import shutil
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable

import requests

from .models import FeedStatus

USER_AGENT = "OfflineVA/3.8 (vendor-first offline vulnerability analysis)"
NVD_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
UBUNTU_OVAL_BASE = "https://security-metadata.canonical.com/oval"


class OperationCancelled(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class FeedSpec:
    key: str
    group: str
    label: str
    url: str
    relative_path: str
    kind: str
    required: bool = False
    max_age_hours: int = 168


def vendor_feed_specs() -> list[FeedSpec]:
    return [
        # Debian Security Tracker is keyed by source package and release
        # codename. DSA/DLA/ELA provide explicitly partial published-fix
        # coverage when a retired release is no longer in the main JSON.
        FeedSpec("debian-security-tracker", "debian", "Debian Security Tracker", "https://security-tracker.debian.org/tracker/data/json", "vendor/debian/security-tracker.json", "debian-tracker", False, 24),
        FeedSpec("debian-dsa", "debian", "Debian DSA advisory history", "https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DSA/list", "vendor/debian/dsa-list", "debian-advisories", False, 24),
        FeedSpec("debian-dla", "debian", "Debian DLA advisory history", "https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DLA/list", "vendor/debian/dla-list", "debian-advisories", False, 24),
        FeedSpec("debian-ela", "debian", "Freexian Debian ELTS advisories", "https://salsa.debian.org/freexian-team/extended-lts/security-tracker/-/raw/master/data/ELA/list", "vendor/debian/ela-list", "debian-advisories", False, 24),
        # SUSE fixed/not-affected vulnerability streams. The analyzer evaluates
        # the full OVAL criteria tree; it does not flatten rpminfo states.
        FeedSpec("suse-sles11", "suse", "SLES 11 Server OVAL", "https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.server.11.xml.gz", "vendor/suse/suse.linux.enterprise.server.11.xml.gz", "oval", False, 720),
        FeedSpec("suse-sle11", "suse", "SLE 11 generic OVAL fallback", "https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.11.xml.gz", "vendor/suse/suse.linux.enterprise.11.xml.gz", "oval", False, 720),
        FeedSpec("suse-sles12", "suse", "SLES 12 Server OVAL", "https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.server.12.xml.gz", "vendor/suse/suse.linux.enterprise.server.12.xml.gz", "oval", False, 168),
        FeedSpec("suse-sles15", "suse", "SLES 15 Server OVAL", "https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.server.15.xml.gz", "vendor/suse/suse.linux.enterprise.server.15.xml.gz", "oval", False, 168),
        # Exact RHEL major streams. Additional product streams can be dropped in
        # vendor/redhat/streams and are evaluated independently.
        FeedSpec("rhel6-oval", "redhat", "RHEL 6 OVAL v2", "https://security.access.redhat.com/data/oval/v2/RHEL6/rhel-6.oval.xml.bz2", "vendor/redhat/RHEL6/rhel-6.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel7-oval", "redhat", "RHEL 7 OVAL v2", "https://security.access.redhat.com/data/oval/v2/RHEL7/rhel-7.oval.xml.bz2", "vendor/redhat/RHEL7/rhel-7.oval.xml.bz2", "oval", False, 168),
        
        # OSV Red Hat ecosystem dump (Grype/Trivy-class offline matching)
        FeedSpec(
            "osv-redhat",
            "redhat",
            "OSV Red Hat ecosystem (RHSA/RHBA fixed ranges)",
            "https://osv-vulnerabilities.storage.googleapis.com/Red%20Hat/all.zip",
            "vendor/osv/redhat/all.zip",
            "osv",
            False,
            168,
        ),
FeedSpec("rhel8-oval", "redhat", "RHEL 8 OVAL v2", "https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.oval.xml.bz2", "vendor/redhat/RHEL8/rhel-8.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel9-oval", "redhat", "RHEL 9 OVAL v2", "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.oval.xml.bz2", "vendor/redhat/RHEL9/rhel-9.oval.xml.bz2", "oval", False, 168),
        # Exact lifecycle/support streams published by Red Hat. These are
        # required for advisories such as RHSA-2024:6421 that only apply to
        # RHEL 8.6 AUS/TUS/E4S/EUS rather than the generic base stream.
        FeedSpec("rhel8-2-aus", "redhat", "RHEL 8.2 AUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.2-aus.oval.xml.bz2", "vendor/redhat/RHEL8/rhel-8.2-aus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel8-2-e4s", "redhat", "RHEL 8.2 E4S OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.2-e4s.oval.xml.bz2", "vendor/redhat/RHEL8/rhel-8.2-e4s.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel8-2-eus", "redhat", "RHEL 8.2 EUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.2-eus.oval.xml.bz2", "vendor/redhat/RHEL8/rhel-8.2-eus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel8-2-tus", "redhat", "RHEL 8.2 TUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.2-tus.oval.xml.bz2", "vendor/redhat/RHEL8/rhel-8.2-tus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel8-4-aus", "redhat", "RHEL 8.4 AUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.4-aus.oval.xml.bz2", "vendor/redhat/RHEL8/rhel-8.4-aus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel8-4-e4s", "redhat", "RHEL 8.4 E4S OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.4-e4s.oval.xml.bz2", "vendor/redhat/RHEL8/rhel-8.4-e4s.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel8-4-eus", "redhat", "RHEL 8.4 EUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.4-eus.oval.xml.bz2", "vendor/redhat/RHEL8/rhel-8.4-eus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel8-4-tus", "redhat", "RHEL 8.4 TUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.4-tus.oval.xml.bz2", "vendor/redhat/RHEL8/rhel-8.4-tus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel8-6-aus", "redhat", "RHEL 8.6 AUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.6-aus.oval.xml.bz2", "vendor/redhat/RHEL8/rhel-8.6-aus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel8-6-e4s", "redhat", "RHEL 8.6 E4S OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.6-e4s.oval.xml.bz2", "vendor/redhat/RHEL8/rhel-8.6-e4s.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel8-6-eus", "redhat", "RHEL 8.6 EUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.6-eus.oval.xml.bz2", "vendor/redhat/RHEL8/rhel-8.6-eus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel8-6-tus", "redhat", "RHEL 8.6 TUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.6-tus.oval.xml.bz2", "vendor/redhat/RHEL8/rhel-8.6-tus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel8-8-aus", "redhat", "RHEL 8.8 AUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.8-aus.oval.xml.bz2", "vendor/redhat/RHEL8/rhel-8.8-aus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel8-8-e4s", "redhat", "RHEL 8.8 E4S OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.8-e4s.oval.xml.bz2", "vendor/redhat/RHEL8/rhel-8.8-e4s.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel8-8-eus", "redhat", "RHEL 8.8 EUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.8-eus.oval.xml.bz2", "vendor/redhat/RHEL8/rhel-8.8-eus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel8-8-tus", "redhat", "RHEL 8.8 TUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.8-tus.oval.xml.bz2", "vendor/redhat/RHEL8/rhel-8.8-tus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel9-0-e4s", "redhat", "RHEL 9.0 E4S OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.0-e4s.oval.xml.bz2", "vendor/redhat/RHEL9/rhel-9.0-e4s.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel9-0-eus", "redhat", "RHEL 9.0 EUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.0-eus.oval.xml.bz2", "vendor/redhat/RHEL9/rhel-9.0-eus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel9-2-aus", "redhat", "RHEL 9.2 AUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.2-aus.oval.xml.bz2", "vendor/redhat/RHEL9/rhel-9.2-aus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel9-2-e4s", "redhat", "RHEL 9.2 E4S OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.2-e4s.oval.xml.bz2", "vendor/redhat/RHEL9/rhel-9.2-e4s.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel9-2-eus", "redhat", "RHEL 9.2 EUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.2-eus.oval.xml.bz2", "vendor/redhat/RHEL9/rhel-9.2-eus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel9-4-aus", "redhat", "RHEL 9.4 AUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.4-aus.oval.xml.bz2", "vendor/redhat/RHEL9/rhel-9.4-aus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel9-4-e4s", "redhat", "RHEL 9.4 E4S OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.4-e4s.oval.xml.bz2", "vendor/redhat/RHEL9/rhel-9.4-e4s.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel9-4-eus", "redhat", "RHEL 9.4 EUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.4-eus.oval.xml.bz2", "vendor/redhat/RHEL9/rhel-9.4-eus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel9-6-aus", "redhat", "RHEL 9.6 AUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.6-aus.oval.xml.bz2", "vendor/redhat/RHEL9/rhel-9.6-aus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel9-6-e4s", "redhat", "RHEL 9.6 E4S OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.6-e4s.oval.xml.bz2", "vendor/redhat/RHEL9/rhel-9.6-e4s.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel9-6-eus", "redhat", "RHEL 9.6 EUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.6-eus.oval.xml.bz2", "vendor/redhat/RHEL9/rhel-9.6-eus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel9-8-e4s", "redhat", "RHEL 9.8 E4S OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.8-e4s.oval.xml.bz2", "vendor/redhat/RHEL9/rhel-9.8-e4s.oval.xml.bz2", "oval", False, 168),
        FeedSpec("rhel9-8-eus", "redhat", "RHEL 9.8 EUS OVAL", "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.8-eus.oval.xml.bz2", "vendor/redhat/RHEL9/rhel-9.8-eus.oval.xml.bz2", "oval", False, 168),
        FeedSpec("redhat-csaf-index", "redhat", "Red Hat CSAF advisory index", "https://security.access.redhat.com/data/csaf/v2/advisories/index.txt", "vendor/redhat/csaf/index.txt", "text", False, 24),
        FeedSpec("redhat-repo-cpe", "redhat", "Red Hat repository-to-CPE mapping", "https://security.access.redhat.com/data/meta/v1/repository-to-cpe.json", "vendor/redhat/repository-to-cpe.json", "json", False, 168),
        # HCE official aggregate advisory XML. Individual CVRF/CSAF documents may
        # also be placed under the matching vendor/huawei/hce/<major>.0 folder.
        FeedSpec("hce2-sa", "huawei", "Huawei Cloud EulerOS 2.0 Security Advisories", "https://repo.huaweicloud.com/hce/2.0/sa/HCE2-SA.xml", "vendor/huawei/hce/2.0/HCE2-SA.xml", "xml", False, 24),
        FeedSpec("hce3-sa", "huawei", "Huawei Cloud EulerOS 3.0 Security Advisories", "https://repo.huaweicloud.com/hce/3.0/sa/HCE3-SA.xml", "vendor/huawei/hce/3.0/HCE3-SA.xml", "xml", False, 24),
        # Ubuntu Canonical OVAL (USN + CVE) per supported LTS / recent release.
        # dpkginfo_test evaluation is implemented in oval.py.
        FeedSpec("ubuntu-noble-usn", "ubuntu", "Ubuntu 24.04 Noble USN OVAL", f"{UBUNTU_OVAL_BASE}/com.ubuntu.noble.usn.oval.xml.bz2", "vendor/ubuntu/com.ubuntu.noble.usn.oval.xml.bz2", "oval", False, 168),
        FeedSpec("ubuntu-noble-cve", "ubuntu", "Ubuntu 24.04 Noble CVE OVAL", f"{UBUNTU_OVAL_BASE}/com.ubuntu.noble.cve.oval.xml.bz2", "vendor/ubuntu/com.ubuntu.noble.cve.oval.xml.bz2", "oval", False, 168),
        FeedSpec("ubuntu-jammy-usn", "ubuntu", "Ubuntu 22.04 Jammy USN OVAL", f"{UBUNTU_OVAL_BASE}/com.ubuntu.jammy.usn.oval.xml.bz2", "vendor/ubuntu/com.ubuntu.jammy.usn.oval.xml.bz2", "oval", False, 168),
        FeedSpec("ubuntu-jammy-cve", "ubuntu", "Ubuntu 22.04 Jammy CVE OVAL", f"{UBUNTU_OVAL_BASE}/com.ubuntu.jammy.cve.oval.xml.bz2", "vendor/ubuntu/com.ubuntu.jammy.cve.oval.xml.bz2", "oval", False, 168),
        FeedSpec("ubuntu-focal-usn", "ubuntu", "Ubuntu 20.04 Focal USN OVAL", f"{UBUNTU_OVAL_BASE}/com.ubuntu.focal.usn.oval.xml.bz2", "vendor/ubuntu/com.ubuntu.focal.usn.oval.xml.bz2", "oval", False, 168),
        FeedSpec("ubuntu-focal-cve", "ubuntu", "Ubuntu 20.04 Focal CVE OVAL", f"{UBUNTU_OVAL_BASE}/com.ubuntu.focal.cve.oval.xml.bz2", "vendor/ubuntu/com.ubuntu.focal.cve.oval.xml.bz2", "oval", False, 168),
        FeedSpec("ubuntu-bionic-usn", "ubuntu", "Ubuntu 18.04 Bionic USN OVAL", f"{UBUNTU_OVAL_BASE}/com.ubuntu.bionic.usn.oval.xml.bz2", "vendor/ubuntu/com.ubuntu.bionic.usn.oval.xml.bz2", "oval", False, 720),
        FeedSpec("ubuntu-bionic-cve", "ubuntu", "Ubuntu 18.04 Bionic CVE OVAL", f"{UBUNTU_OVAL_BASE}/com.ubuntu.bionic.cve.oval.xml.bz2", "vendor/ubuntu/com.ubuntu.bionic.cve.oval.xml.bz2", "oval", False, 720),
        FeedSpec("cisa-kev", "enrichment", "CISA Known Exploited Vulnerabilities", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "enrichment/cisa/known_exploited_vulnerabilities.json", "kev", False, 24),
        FeedSpec("epss", "enrichment", "FIRST EPSS current scores", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz", "enrichment/epss/epss_scores-current.csv.gz", "epss", False, 24),
    ]


def nvd_feed_specs(start_year: int, end_year: int, include_recent: bool = True) -> list[FeedSpec]:
    specs: list[FeedSpec] = []
    for year in range(start_year, end_year + 1):
        filename = f"nvdcve-2.0-{year}.json.gz"
        specs.append(FeedSpec(f"nvd-{year}", "nvd", f"NVD CVE {year}", f"{NVD_BASE}/{filename}", f"nvd/{filename}", "nvd", False, 8760 if year < datetime.now().year else 24))
    if include_recent:
        for name in ("recent", "modified"):
            filename = f"nvdcve-2.0-{name}.json.gz"
            specs.append(FeedSpec(f"nvd-{name}", "nvd", f"NVD CVE {name}", f"{NVD_BASE}/{filename}", f"nvd/{filename}", "nvd", False, 24))
    return specs


def filter_feed_specs_for_os(specs: Iterable[FeedSpec], target_os_family: str = "auto") -> list[FeedSpec]:
    """Keep common enrichment plus only the explicitly selected vendor family."""
    target = (target_os_family or "auto").strip().lower()
    aliases = {"rhel": "redhat", "sles": "suse", "oracle-linux": "oracle", "almalinux": "alma", "amazon-linux": "amazon"}
    target = aliases.get(target, target)
    if target == "auto":
        return list(specs)
    vendor_group = {
        "redhat": "redhat",
        "suse": "suse",
        "debian": "debian",
        "huawei": "huawei",
        "ubuntu": "ubuntu",
    }.get(target)
    common_groups = {"nvd", "enrichment"}
    return [spec for spec in specs if spec.group in common_groups or (vendor_group and spec.group == vendor_group)]


def all_feed_specs(
    root: str | Path,
    start_year: int,
    end_year: int,
    include_recent: bool = True,
    target_os_family: str = "auto",
) -> list[FeedSpec]:
    """Return configured feeds, optionally scoped to one selected OS family."""
    root_path = Path(root)
    specs = nvd_feed_specs(start_year, end_year, include_recent) + vendor_feed_specs() + euleros_source_specs(root_path)
    return filter_feed_specs_for_os(specs, target_os_family)


def feed_freshness(
    root: str | Path,
    specs: Iterable[FeedSpec],
    *,
    now: datetime | None = None,
) -> list[dict]:
    """Describe feed validity without contacting the network.

    Expiry follows the same file-mtime/max-age policy used by ``ensure_feeds``.
    Manifest validation is preserved separately so a present but invalid feed
    cannot be described as merely stale.
    """
    root_path = Path(root)
    manifest = load_manifest(root_path)
    manifest_rows = manifest.get("feeds", {})
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    rows: list[dict] = []
    for spec in specs:
        path = root_path / spec.relative_path
        saved = manifest_rows.get(spec.key, {})
        exists = path.exists() and path.stat().st_size > 0
        validated = bool(saved.get("validated")) if saved else False
        modified = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc) if exists else None
        valid_until = modified + timedelta(hours=spec.max_age_hours) if modified else None
        stale = bool(valid_until and current > valid_until)
        if not exists:
            state = "missing"
        elif not validated:
            state = "invalid"
        elif stale:
            state = "stale"
        else:
            state = "current"
        rows.append({
            "key": spec.key,
            "label": spec.label,
            "group": spec.group,
            "path": str(path),
            "relative_path": spec.relative_path,
            "state": state,
            "message": saved.get("validation", "manifest validation unavailable"),
            "sha256": saved.get("sha256", ""),
            "size": path.stat().st_size if exists else 0,
            "checked_at": saved.get("checked_at", ""),
            "file_updated_at": modified.isoformat() if modified else "",
            "valid_until": valid_until.isoformat() if valid_until else "",
            "max_age_hours": spec.max_age_hours,
            "stale": stale,
            "validated": validated,
        })
    return rows


def summarize_feed_freshness(rows: Iterable[dict]) -> dict:
    values = list(rows)
    counts = {state: sum(1 for row in values if row.get("state") == state) for state in ("current", "stale", "missing", "invalid")}
    checked = sorted(str(row.get("checked_at") or "") for row in values if row.get("checked_at"))
    expiries = sorted(str(row.get("valid_until") or "") for row in values if row.get("valid_until"))
    issues = [row for row in values if row.get("state") != "current"]
    return {
        "counts": counts,
        "issue_count": len(issues),
        "issue_labels": [str(row.get("label") or row.get("key") or "feed") for row in issues],
        "checked_from": checked[0] if checked else "",
        "checked_to": checked[-1] if checked else "",
        "valid_until": expiries[0] if expiries else "",
        "current": not issues,
    }


def _open_binary(path: Path):
    """Open plain or compressed feed files, including atomic *.part downloads."""
    name = path.name.lower()
    if name.endswith((".gz", ".gz.part")):
        return gzip.open(path, "rb")
    if name.endswith((".bz2", ".bz2.part")):
        return bz2.open(path, "rb")
    return path.open("rb")


def validate_feed(path: Path, kind: str) -> tuple[bool, str]:
    if not path.exists() or path.stat().st_size == 0:
        return False, "missing or empty"
    try:
        if kind == "debian-advisories":
            from .adapters.debian_advisories import parse_advisories
            records = parse_advisories(path)
            return (True, f"{len(records)} Debian advisory release records") if records else (False, "No Debian advisory release records")
        with _open_binary(path) as fh:
            prefix = fh.read(131072)
        stripped = prefix.lstrip(b"\xef\xbb\xbf\x00\t\r\n ")
        if kind in {"oval", "xml"}:
            if not stripped.startswith(b"<"):
                return False, "not XML"
            # Parse at least the root element from the full compressed stream.
            with _open_binary(path) as fh:
                _event, root = next(ET.iterparse(fh, events=("start",)))
            local = root.tag.rsplit("}", 1)[-1].lower()
            if local not in {"oval_definitions", "cvrfdoc", "document", "advisories", "security_advisories", "updates", "channel"}:
                return False, f"unexpected XML root: {local}"
            return True, f"valid XML root={local}"
        if kind in {"json", "kev", "nvd", "debian-tracker"}:
            if not stripped.startswith((b"{", b"[")):
                return False, "not JSON"
            if kind == "debian-tracker":
                data = json.loads(path.read_text(encoding="utf-8-sig"))
                if not isinstance(data, dict) or not data:
                    return False, "Debian tracker root object missing"
                valid_sample = False
                for source_issues in data.values():
                    if not isinstance(source_issues, dict):
                        continue
                    for cve, issue in source_issues.items():
                        if str(cve).upper().startswith("CVE-") and isinstance(issue, dict) and isinstance(issue.get("releases"), dict):
                            valid_sample = True
                            break
                    if valid_sample:
                        break
                if not valid_sample:
                    return False, "Debian tracker CVE/release records missing"
                return True, "valid Debian Security Tracker JSON"
            if kind == "kev":
                data = json.loads(path.read_text(encoding="utf-8-sig"))
                if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
                    return False, "KEV vulnerabilities array missing"
            elif kind == "json" and path.stat().st_size < 20_000_000:
                json.loads(path.read_text(encoding="utf-8-sig"))
            return True, "valid JSON/gzip prefix"
        if kind == "epss":
            with _open_binary(path) as fh:
                text = fh.read(8192).decode("utf-8-sig", errors="replace")
            lines = [x for x in text.splitlines() if x and not x.startswith("#")]
            if not lines or not {"cve", "epss", "percentile"}.issubset({x.strip().lower() for x in lines[0].split(",")}):
                return False, "EPSS CSV header invalid"
            return True, "valid EPSS CSV"
        if kind == "text":
            return True, "valid text file"
        return True, "file present"
    except Exception as exc:
        return False, f"validation failed: {exc}"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _manifest_path(root: Path) -> Path:
    return root / "feed_manifest.json"


def load_manifest(root: Path) -> dict:
    path = _manifest_path(root)
    if not path.exists():
        return {"schema": 1, "feeds": {}}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"schema": 1, "feeds": {}}


def save_manifest(root: Path, manifest: dict) -> None:
    root.mkdir(parents=True, exist_ok=True)
    tmp = _manifest_path(root).with_suffix(".json.tmp")
    tmp.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, _manifest_path(root))


def ensure_local_templates(root: Path) -> None:
    local = root / "local_rules"
    local.mkdir(parents=True, exist_ok=True)
    matrix = local / "approved_patch_matrix.csv"
    if not matrix.exists():
        matrix.write_text(
            "os_family,os_product,os_version,package_manager,package_name,source_package,source_rpm,version_scheme,fixed_package_version,cve,advisory,fixed_epoch,fixed_version,fixed_release,arch,status,confidence,severity,cvss,reference,notes\n",
            encoding="utf-8-sig",
        )
    oracle_dir = root / "vendor" / "oracle"
    oracle_dir.mkdir(parents=True, exist_ok=True)
    oracle_rules = oracle_dir / "java_cpu_rules.csv"
    if not oracle_rules.exists():
        packaged = Path(__file__).resolve().parents[1] / "feeds" / "vendor" / "oracle" / "java_cpu_rules.csv"
        if packaged.exists():
            shutil.copy2(packaged, oracle_rules)
        else:
            oracle_rules.write_text("advisory,major,fixed_version,severity,cves,reference,description\n", encoding="utf-8-sig")
    sources = root / "vendor" / "huawei" / "euleros" / "sources.csv"
    sources.parent.mkdir(parents=True, exist_ok=True)
    if not sources.exists():
        sources.write_text("advisory,version,os_version\n", encoding="utf-8-sig")
    for folder in [
        root / "vendor" / "debian",
        root / "vendor" / "huawei" / "euleros" / "cvrf",
        root / "vendor" / "huawei" / "euleros" / "csaf",
        root / "vendor" / "huawei" / "hce" / "2.0" / "cvrf",
        root / "vendor" / "huawei" / "hce" / "2.0" / "csaf",
        root / "vendor" / "huawei" / "hce" / "3.0" / "cvrf",
        root / "vendor" / "huawei" / "hce" / "3.0" / "csaf",
        root / "vendor" / "redhat" / "streams",
    ]:
        folder.mkdir(parents=True, exist_ok=True)


def euleros_source_specs(root: Path) -> list[FeedSpec]:
    path = root / "vendor" / "huawei" / "euleros" / "sources.csv"
    if not path.exists():
        return []
    out: list[FeedSpec] = []
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            advisory = (row.get("advisory") or "").strip()
            version = (row.get("version") or "").strip()
            if not advisory or not version:
                continue
            q_version = requests.utils.quote(version, safe="")
            q_adv = requests.utils.quote(advisory, safe="")
            cvrf_url = "https://devdata.huaweicloud.com/rest/developer/fwdo/rest/developer/servlet/hddprmsoservice/v1/euleros/security_advisories" + f"?sa_no={q_adv}&version={q_version}"
            csaf_url = "https://devdata.huaweicloud.com/rest/developer/fwdo/rest/developer/servlet/hddprmsoservice/v1/euleros/security_advisories/csaf" + f"?sa_no=csaf_{q_adv}.json&version={q_version}"
            safe_adv = re_safe(advisory)
            safe_version = re_safe(version)
            stem = f"{safe_adv}__{safe_version}"
            out.extend([
                FeedSpec(f"euleros-{stem}-cvrf", "huawei", f"EulerOS {advisory} CVRF ({version})", cvrf_url, f"vendor/huawei/euleros/cvrf/{stem}.xml", "xml", False, 720),
                FeedSpec(f"euleros-{stem}-csaf", "huawei", f"EulerOS {advisory} CSAF ({version})", csaf_url, f"vendor/huawei/euleros/csaf/{stem}.json", "json", False, 720),
            ])
    return out


def re_safe(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)


def _is_stale(path: Path, hours: int) -> bool:
    return time.time() - path.stat().st_mtime > hours * 3600


def _remote_meta(session: requests.Session, url: str) -> tuple[str, str]:
    try:
        response = session.head(url, timeout=20, allow_redirects=True)
        if response.ok:
            return response.headers.get("ETag", ""), response.headers.get("Last-Modified", "")
    except requests.RequestException:
        pass
    return "", ""


def _download(
    session: requests.Session,
    spec: FeedSpec,
    destination: Path,
    cancel: Callable[[], bool] | None,
    log: Callable[[str], None],
    progress: Callable[[str, int, int], None] | None = None,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    part = destination.with_suffix(destination.suffix + ".part")
    for attempt in range(1, 4):
        if cancel and cancel():
            raise OperationCancelled("Feed update cancelled")
        try:
            log(f"[+] Downloading {spec.label} (attempt {attempt}/3)")
            with session.get(spec.url, timeout=(20, 180), stream=True, allow_redirects=True) as response:
                response.raise_for_status()
                content_type = (response.headers.get("Content-Type") or "").lower()
                try:
                    total_bytes = int(response.headers.get("Content-Length") or 0)
                except (TypeError, ValueError):
                    total_bytes = 0
                downloaded_bytes = 0
                if progress:
                    progress(spec.label, downloaded_bytes, total_bytes)
                with part.open("wb") as fh:
                    for chunk in response.iter_content(1024 * 1024):
                        if cancel and cancel():
                            raise OperationCancelled("Feed update cancelled")
                        if chunk:
                            fh.write(chunk)
                            downloaded_bytes += len(chunk)
                            if progress:
                                progress(spec.label, downloaded_bytes, total_bytes)
            ok, msg = validate_feed(part, spec.kind)
            if not ok:
                raise ValueError(f"downloaded file failed validation: {msg}; content-type={content_type}")
            os.replace(part, destination)
            return
        except OperationCancelled:
            part.unlink(missing_ok=True)
            raise
        except Exception as exc:
            part.unlink(missing_ok=True)
            if attempt >= 3:
                raise RuntimeError(f"{spec.label}: {exc}") from exc
            log(f"[WARN] {spec.label}: {exc}; retrying")
            time.sleep(attempt * 2)


def ensure_feeds(
    root: str | Path,
    specs: Iterable[FeedSpec],
    *,
    force: bool = False,
    refresh_stale: bool = True,
    remote_check: bool = True,
    cancel: Callable[[], bool] | None = None,
    log: Callable[[str], None] = print,
    progress: Callable[[str, int, int], None] | None = None,
) -> list[FeedStatus]:
    root = Path(root)
    ensure_local_templates(root)
    manifest = load_manifest(root)
    manifest.setdefault("feeds", {})
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    statuses: list[FeedStatus] = []

    for spec in specs:
        if cancel and cancel():
            save_manifest(root, manifest)
            session.close()
            raise OperationCancelled("Feed update cancelled")
        log(f"[CHECK] {spec.label}")
        path = root / spec.relative_path
        ok, validation_msg = validate_feed(path, spec.kind)
        old = manifest["feeds"].get(spec.key, {})
        need = force or not ok or (refresh_stale and ok and _is_stale(path, spec.max_age_hours))
        etag = last_modified = ""
        if remote_check and ok and not force:
            etag, last_modified = _remote_meta(session, spec.url)
            if etag and etag != old.get("etag", ""):
                need = True
            elif last_modified and last_modified != old.get("last_modified", ""):
                need = True

        try:
            if need:
                _download(session, spec, path, cancel, log, progress)
                ok, validation_msg = validate_feed(path, spec.kind)
                etag, last_modified = _remote_meta(session, spec.url) if remote_check else (etag, last_modified)
                state = "downloaded"
            else:
                state = "present"
            digest = sha256_file(path) if ok else ""
            updated = datetime.now(timezone.utc).isoformat()
            manifest["feeds"][spec.key] = {
                "label": spec.label,
                "url": spec.url,
                "relative_path": spec.relative_path,
                "kind": spec.kind,
                "sha256": digest,
                "size": path.stat().st_size if path.exists() else 0,
                "validated": ok,
                "validation": validation_msg,
                "etag": etag or old.get("etag", ""),
                "last_modified": last_modified or old.get("last_modified", ""),
                "checked_at": updated,
            }
            statuses.append(FeedStatus(spec.key, spec.label, path, spec.url, state if ok else "invalid", validation_msg, digest, path.stat().st_size if path.exists() else 0, updated))
            log(f"[OK] {spec.label}: {state}, {validation_msg}")
        except OperationCancelled:
            save_manifest(root, manifest)
            session.close()
            raise
        except Exception as exc:
            state = "error-required" if spec.required else "error-optional"
            statuses.append(FeedStatus(spec.key, spec.label, path, spec.url, state, str(exc)))
            log(f"[WARN] {spec.label}: {exc}")
            if spec.required:
                save_manifest(root, manifest)
                session.close()
                raise
    save_manifest(root, manifest)
    session.close()
    return statuses


def bootstrap_all(
    root: str | Path,
    start_year: int,
    end_year: int,
    include_recent: bool,
    target_os_family: str = "auto",
    **kwargs,
) -> list[FeedStatus]:
    root_path = Path(root)
    ensure_local_templates(root_path)
    specs = all_feed_specs(root_path, start_year, end_year, include_recent, target_os_family)
    return ensure_feeds(root_path, specs, **kwargs)
