from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from ..models import Finding, Inventory


class VendorAdapter(ABC):
    name = "VendorAdapter"

    @abstractmethod
    def applicable(self, inventory: Inventory) -> bool:
        raise NotImplementedError

    @abstractmethod
    def evaluate(self, inventory: Inventory, feeds_root: Path) -> list[Finding]:
        raise NotImplementedError
