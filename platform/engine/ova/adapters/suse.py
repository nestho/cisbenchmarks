from __future__ import annotations

from pathlib import Path

from .base import VendorAdapter
from .common import oval_findings
from ..models import Finding, Inventory


class SuseOvalAdapter(VendorAdapter):
    name = "SUSE OVAL"

    def applicable(self, inventory: Inventory) -> bool:
        return inventory.os.family == "suse" and any(
            (pkg.package_manager or "rpm").lower() == "rpm" for pkg in inventory.packages
        )

    def _select(self, inventory: Inventory, root: Path) -> list[Path]:
        major = inventory.os.major
        folder = root / "vendor" / "suse"
        preferred = folder / f"suse.linux.enterprise.server.{major}.xml.gz"
        fallback = folder / f"suse.linux.enterprise.{major}.xml.gz"
        # Prefer exact per-SP files, then the Server product feed, then the
        # generic SLE fallback. Do not evaluate overlapping flavors together.
        exact: list[Path] = []
        if inventory.os.service_pack:
            patterns = [
                f"*server*{major}*sp{inventory.os.service_pack}*.xml*",
                f"*server*{major}.{inventory.os.service_pack}*.xml*",
            ]
            for pattern in patterns:
                exact.extend(sorted(folder.glob(pattern)))
        exact = list(dict.fromkeys(p for p in exact if "affected" not in p.name and "-patch" not in p.name))
        if exact:
            return exact
        if preferred.exists():
            return [preferred]
        if fallback.exists():
            return [fallback]
        return []

    def evaluate(self, inventory: Inventory, feeds_root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in self._select(inventory, feeds_root):
            findings.extend(oval_findings(inventory, path, self.name))
        return findings
