"""Ubuntu vendor adapter — Canonical USN + CVE OVAL (dpkginfo).

OVAL feeds are published per release codename under security-metadata.canonical.com.
Only confirmed package findings with an explicit fixed version threshold are emitted.
"""

from __future__ import annotations

from pathlib import Path

from .base import VendorAdapter
from .common import oval_findings
from ..models import Finding, Inventory

# Supported Ubuntu LTS / interim codenames with published OVAL.
UBUNTU_CODENAMES = (
    "noble",      # 24.04
    "jammy",      # 22.04
    "focal",      # 20.04
    "bionic",     # 18.04
    "xenial",     # 16.04
    "mantic",     # 23.10
    "lunar",      # 23.04
    "kinetic",    # 22.10
    "impish",     # 21.10
    "hirsute",    # 21.04
    "groovy",     # 20.10
    "eoan",       # 19.10
    "disco",      # 19.04
    "cosmic",     # 18.10
    "trusty",     # 14.04
)


class UbuntuOvalAdapter(VendorAdapter):
    name = "Ubuntu OVAL"

    def applicable(self, inventory: Inventory) -> bool:
        if inventory.os.family not in {"ubuntu", "debian"}:
            return False
        # Ubuntu product, or Debian family with ubuntu-like ID
        product = (inventory.os.product or "").lower()
        pretty = (inventory.os.pretty_name or "").lower()
        id_like = (inventory.os.id_like or "").lower()
        is_ubuntu = (
            product == "ubuntu"
            or "ubuntu" in pretty
            or "ubuntu" in id_like
            or inventory.os.family == "ubuntu"
        )
        if not is_ubuntu:
            return False
        return any(
            (pkg.package_manager or "").lower() in {"deb", "dpkg"}
            for pkg in inventory.packages
        )

    def _codename(self, inventory: Inventory) -> str:
        code = (inventory.os.codename or "").strip().lower()
        if code:
            # Strip variant suffixes (e.g. jammy-security)
            code = code.split("-")[0].split(".")[0]
            return code
        # Fallback from VERSION_ID
        version = (inventory.os.version or "").strip()
        mapping = {
            "24.04": "noble",
            "22.04": "jammy",
            "20.04": "focal",
            "18.04": "bionic",
            "16.04": "xenial",
            "14.04": "trusty",
            "23.10": "mantic",
            "23.04": "lunar",
            "22.10": "kinetic",
        }
        for key, name in mapping.items():
            if version.startswith(key):
                return name
        return ""

    def _select(self, inventory: Inventory, root: Path) -> list[Path]:
        codename = self._codename(inventory)
        folder = root / "vendor" / "ubuntu"
        if not folder.exists():
            return []
        selected: list[Path] = []
        if codename:
            # Prefer USN oval (patch-oriented), then CVE oval.
            for kind in ("usn", "cve"):
                exact = folder / f"com.ubuntu.{codename}.{kind}.oval.xml.bz2"
                if exact.exists() and exact.stat().st_size > 0:
                    selected.append(exact)
                # Uncompressed fallback
                plain = folder / f"com.ubuntu.{codename}.{kind}.oval.xml"
                if plain.exists() and plain.stat().st_size > 0:
                    selected.append(plain)
        if selected:
            return list(dict.fromkeys(selected))
        # Last resort: any oval under vendor/ubuntu matching codename
        if codename:
            selected.extend(sorted(folder.glob(f"*{codename}*.oval.xml*")))
        return list(dict.fromkeys(p for p in selected if p.is_file() and p.stat().st_size > 0))

    def evaluate(self, inventory: Inventory, feeds_root: Path) -> list[Finding]:
        paths = self._select(inventory, feeds_root)
        if not paths:
            codename = self._codename(inventory) or "unknown"
            inventory.warnings.append(
                f"Ubuntu OVAL: no feed for codename={codename!r} under vendor/ubuntu/. "
                "Download Canonical OVAL (USN/CVE) for this release before confirming findings."
            )
            inventory.assessment.update(
                mode="unavailable",
                reason=f"Ubuntu OVAL feed missing for release {codename!r}.",
            )
            return []
        inventory.assessment.update(mode="oval", source=self.name)
        findings: list[Finding] = []
        for path in paths:
            findings.extend(oval_findings(inventory, path, self.name))
        return findings
