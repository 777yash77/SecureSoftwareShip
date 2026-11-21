from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Dict, List, Set
from secureship.models import Finding, Severity, ShipStatus, ScanSummary


class Scorer:
    """Computes security scores and determines Ship-Readiness verdicts."""

    PENALTIES = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 5,
        Severity.LOW: 2,
    }

    @classmethod
    def calculate_score(cls, findings: List[Finding]) -> int:
        score = 100
        for finding in findings:
            penalty = cls.PENALTIES.get(finding.severity, 0)
            score -= penalty
        return max(0, min(100, score))

    @classmethod
    def determine_ship_status(
        cls,
        score: int,
        critical_count: int,
        min_score: int = 80,
        strict_violations: Optional[List[str]] = None,
    ) -> ShipStatus:
        if critical_count > 0 or (strict_violations and len(strict_violations) > 0):
            return ShipStatus.BLOCKED
        if score < min_score:
            if score < 50:
                return ShipStatus.BLOCKED
            return ShipStatus.NEEDS_REVIEW
        return ShipStatus.READY_TO_SHIP

    @classmethod
    def generate_summary(
        cls,
        findings: List[Finding],
        files_scanned: int,
        lines_scanned: int,
        duration_ms: float,
        min_score: int = 80,
        strict_categories: Optional[List[FindingCategory]] = None,
    ) -> ScanSummary:
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == Severity.LOW)

        score = cls.calculate_score(findings)

        strict_violations: List[str] = []
        if strict_categories:
            strict_set = set(strict_categories)
            for cat in strict_set:
                count = sum(1 for f in findings if f.category == cat)
                if count > 0:
                    cat_name = cat.value if hasattr(cat, "value") else str(cat)
                    strict_violations.append(f"{cat_name} ({count} finding{'s' if count > 1 else ''})")

        status = cls.determine_ship_status(
            score=score,
            critical_count=critical_count,
            min_score=min_score,
            strict_violations=strict_violations,
        )

        owasp_breakdown: Dict[str, int] = {}
        category_breakdown: Dict[str, int] = {}

        for f in findings:
            cat = f.category.value if hasattr(f.category, "value") else str(f.category)
            category_breakdown[cat] = category_breakdown.get(cat, 0) + 1
            if f.owasp_category:
                owasp_breakdown[f.owasp_category] = (
                    owasp_breakdown.get(f.owasp_category, 0) + 1
                )

        return ScanSummary(
            total_findings=len(findings),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            files_scanned=files_scanned,
            lines_scanned=lines_scanned,
            scan_duration_ms=round(duration_ms, 2),
            security_score=score,
            min_score=min_score,
            strict_violations=strict_violations,
            ship_status=status,
            owasp_breakdown=owasp_breakdown,
            category_breakdown=category_breakdown,
        )


class IgnoreMatcher:
    """Handles .secureshipignore pattern matching and inline comment suppressions."""

    SUPPRESSION_TOKENS = (
        "secureship-ignore",
        "secureship:ignore",
    )

    def __init__(self, root_path: Path):
        self.root_path = root_path.resolve()
        self.patterns: List[str] = [
            ".git/*",
            ".git",
            "node_modules/*",
            "node_modules",
            "__pycache__/*",
            "__pycache__",
            "*.pyc",
            ".pytest_cache/*",
            ".venv/*",
            "venv/*",
            "dist/*",
            "build/*",
        ]
        self._load_ignore_file()

    def _load_ignore_file(self) -> None:
        ignore_file = self.root_path / ".secureshipignore"
        if ignore_file.exists():
            try:
                content = ignore_file.read_text(encoding="utf-8")
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.patterns.append(line)
            except Exception:
                pass

    def is_ignored(self, path: Path) -> bool:
        try:
            rel_path = path.resolve().relative_to(self.root_path).as_posix()
        except ValueError:
            rel_path = path.as_posix()

        for pattern in self.patterns:
            pattern = pattern.strip()
            # If pattern ends with '/', match directories
            clean_pattern = pattern.rstrip("/")
            if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(rel_path, clean_pattern):
                return True
            # Match components
            parts = rel_path.split("/")
            if any(fnmatch.fnmatch(p, clean_pattern) for p in parts):
                return True
        return False

    @classmethod
    def is_line_suppressed(cls, line_content: str, rule_id: Optional[str] = None) -> bool:
        """Check for inline suppression e.g. # secureship-ignore or // secureship-ignore [RULE_ID]."""
        content_lower = line_content.lower()
        for token in cls.SUPPRESSION_TOKENS:
            if token in content_lower:
                # If specific rule specified after token, check match
                idx = content_lower.find(token)
                rest = content_lower[idx + len(token):].strip()
                if not rest or rest.startswith(":") or not rule_id:
                    return True
                if rule_id.lower() in rest:
                    return True
                return True
        return False
