from __future__ import annotations

import abc
from pathlib import Path
from typing import List, Optional, Set
from secureship.models import Finding, FindingCategory


class BaseScanner(abc.ABC):
    """Abstract base class for all SecureShip scanners."""

    category: FindingCategory
    name: str

    @property
    @abc.abstractmethod
    def supported_extensions(self) -> Set[str]:
        """File extensions this scanner inspects (e.g., {'.py', '.js'}). Empty means custom filtering."""
        pass

    @abc.abstractmethod
    def scan_file(self, file_path: Path, relative_path: str, content: str) -> List[Finding]:
        """Scan a single file's content and return identified findings."""
        pass

    def can_scan(self, file_path: Path) -> bool:
        """Determines if the scanner should process the given file."""
        if not self.supported_extensions:
            return True
        return file_path.suffix.lower() in self.supported_extensions
