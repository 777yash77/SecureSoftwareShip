from __future__ import annotations

import datetime
import os
import re
import subprocess
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from secureship.config import load_config
from secureship.db import HistoryDB
from secureship.models import Finding, FindingCategory, ScanResult, Severity
from secureship.scanners import (
    BaseScanner,
    IaCScanner,
    SASTScanner,
    SCAScanner,
    SecretsScanner,
)
from secureship.scorer import IgnoreMatcher, Scorer


class SecureShipEngine:
    """Core scanning engine orchestrating all static, secrets, dependency, and IaC scanners."""

    def __init__(
        self,
        target_path: str = ".",
        categories: Optional[List[FindingCategory]] = None,
    ):
        self.target_path = Path(target_path).resolve()
        self.ignore_matcher = IgnoreMatcher(self.target_path)
        all_scanners: List[BaseScanner] = [
            SecretsScanner(),
            SASTScanner(),
            SCAScanner(),
            IaCScanner(),
        ]
        if categories:
            allowed = set(categories)
            self.scanners = [s for s in all_scanners if s.category in allowed]
        else:
            self.scanners = all_scanners

        self.db = HistoryDB()


    def _resolve_effective_config(
        self,
        min_score: Optional[int] = None,
        strict_categories: Optional[List[FindingCategory]] = None,
    ) -> Tuple[int, List[FindingCategory]]:
        cfg = load_config(self.target_path)
        effective_min = min_score if min_score is not None else int(cfg.get("min_score", 80))

        if strict_categories is not None:
            effective_strict = list(strict_categories)
        elif "strict_categories" in cfg:
            effective_strict = []
            for c in cfg["strict_categories"]:
                try:
                    effective_strict.append(FindingCategory(c.upper()))
                except ValueError:
                    pass
        else:
            effective_strict = []

        return effective_min, effective_strict

    def scan(
        self,
        min_severity: Optional[Severity] = None,
        min_score: Optional[int] = None,
        strict_categories: Optional[List[FindingCategory]] = None,
    ) -> ScanResult:
        """Executes full scan over target_path (directory or single file)."""
        start_time = time.perf_counter()
        scan_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        effective_min_score, effective_strict = self._resolve_effective_config(
            min_score=min_score, strict_categories=strict_categories
        )

        all_findings: List[Finding] = []
        files_scanned = 0
        lines_scanned = 0

        if not self.target_path.exists():
            repo_root = Path(__file__).resolve().parent.parent.parent
            if (repo_root / self.target_path.name).exists():
                self.target_path = (repo_root / self.target_path.name).resolve()
                self.ignore_matcher = IgnoreMatcher(self.target_path)
            elif (repo_root / self.target_path).exists():
                self.target_path = (repo_root / self.target_path).resolve()
                self.ignore_matcher = IgnoreMatcher(self.target_path)

        if not self.target_path.exists():
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            summary = Scorer.generate_summary(
                [],
                0,
                0,
                duration_ms,
                min_score=effective_min_score,
                strict_categories=effective_strict,
            )
            return ScanResult(
                scan_id=scan_id,
                timestamp=timestamp,
                target_path=str(self.target_path),
                summary=summary,
                findings=[],
            )

        if self.target_path.is_file():
            # Scan single file
            rel_path = self.target_path.name
            findings, lines = self._scan_single_file(self.target_path, rel_path)
            all_findings.extend(findings)
            files_scanned = 1
            lines_scanned = lines
        elif self.target_path.is_dir():
            # Scan directory recursively
            for root, dirs, files in os.walk(self.target_path):
                # Filter out ignored directories in-place to avoid descending
                dirs[:] = [
                    d
                    for d in dirs
                    if not self.ignore_matcher.is_ignored(Path(root) / d)
                ]

                for file_name in files:
                    file_path = Path(root) / file_name
                    if self.ignore_matcher.is_ignored(file_path):
                        continue

                    try:
                        rel_path = file_path.relative_to(self.target_path).as_posix()
                    except ValueError:
                        rel_path = file_path.as_posix()

                    findings, lines = self._scan_single_file(file_path, rel_path)
                    if lines > 0 or findings:
                        files_scanned += 1
                        lines_scanned += lines
                    all_findings.extend(findings)

        # Filter by min_severity if requested
        if min_severity:
            min_weight = min_severity.weight
            all_findings = [f for f in all_findings if f.severity.weight >= min_weight]

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        summary = Scorer.generate_summary(
            findings=all_findings,
            files_scanned=files_scanned,
            lines_scanned=lines_scanned,
            duration_ms=duration_ms,
            min_score=effective_min_score,
            strict_categories=effective_strict,
        )

        result = ScanResult(
            scan_id=scan_id,
            timestamp=timestamp,
            target_path=str(self.target_path),
            summary=summary,
            findings=all_findings,
        )

        # Persist scan to SQLite history
        try:
            self.db.save_scan(result)
        except Exception:
            pass

        return result

    def scan_staged(
        self,
        min_severity: Optional[Severity] = None,
        min_score: Optional[int] = None,
        strict_categories: Optional[List[FindingCategory]] = None,
    ) -> ScanResult:
        """Executes fast diff scan on Git staged changes only."""
        start_time = time.perf_counter()
        scan_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        effective_min_score, effective_strict = self._resolve_effective_config(
            min_score=min_score, strict_categories=strict_categories
        )

        staged_files_map = self._get_git_staged_changes()
        all_findings: List[Finding] = []
        files_scanned = 0
        lines_scanned = 0

        for rel_file_path, modified_lines in staged_files_map.items():
            full_path = self.target_path / rel_file_path
            if not full_path.exists() or self.ignore_matcher.is_ignored(full_path):
                continue

            findings, lines = self._scan_single_file(full_path, rel_file_path)
            files_scanned += 1
            lines_scanned += len(modified_lines) if modified_lines else lines

            # Filter findings to only those that touch modified lines
            if modified_lines:
                staged_findings = [
                    f for f in findings if any(f.line_start <= line <= f.line_end for line in modified_lines)
                ]
                all_findings.extend(staged_findings)
            else:
                all_findings.extend(findings)

        if min_severity:
            min_weight = min_severity.weight
            all_findings = [f for f in all_findings if f.severity.weight >= min_weight]

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        summary = Scorer.generate_summary(
            findings=all_findings,
            files_scanned=files_scanned,
            lines_scanned=lines_scanned,
            duration_ms=duration_ms,
            min_score=effective_min_score,
            strict_categories=effective_strict,
        )

        result = ScanResult(
            scan_id=scan_id,
            timestamp=timestamp,
            target_path=f"{self.target_path} (Git Staged Diff)",
            summary=summary,
            findings=all_findings,
        )

        try:
            self.db.save_scan(result)
        except Exception:
            pass

        return result

    def _get_git_staged_changes(self) -> Dict[str, Set[int]]:
        """Parses git diff --cached to return mapping of staged files to added/modified line numbers."""
        staged_map: Dict[str, Set[int]] = {}
        try:
            # 1. Get list of staged files
            proc = subprocess.run(
                ["git", "diff", "--name-only", "--cached"],
                cwd=str(self.target_path),
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode != 0:
                return staged_map

            file_names = [f.strip() for f in proc.stdout.splitlines() if f.strip()]
            for fname in file_names:
                staged_map[fname] = set()

            # 2. Extract modified line numbers via unified diff
            diff_proc = subprocess.run(
                ["git", "diff", "--cached", "-U0"],
                cwd=str(self.target_path),
                capture_output=True,
                text=True,
                timeout=10,
            )
            if diff_proc.returncode == 0:
                current_file = ""
                for line in diff_proc.stdout.splitlines():
                    if line.startswith("+++ b/"):
                        current_file = line[6:].strip()
                    elif line.startswith("@@ ") and current_file in staged_map:
                        # e.g., @@ -10,0 +12,5 @@
                        match = re.search(r"\+(\d+)(?:,(\d+))?", line)
                        if match:
                            start_line = int(match.group(1))
                            count = int(match.group(2)) if match.group(2) else 1
                            for l_idx in range(start_line, start_line + max(1, count)):
                                staged_map[current_file].add(l_idx)
        except Exception:
            pass
        return staged_map

    def scan_content(self, file_path_str: str, content: str) -> List[Finding]:
        """Scan raw content directly for on-the-fly / in-editor analysis."""
        file_path = Path(file_path_str)
        findings: List[Finding] = []
        for scanner in self.scanners:
            if scanner.can_scan(file_path):
                try:
                    f_list = scanner.scan_file(file_path, file_path_str, content)
                    findings.extend(f_list)
                except Exception:
                    pass
        return findings

    def _scan_single_file(self, file_path: Path, relative_path: str) -> tuple[List[Finding], int]:
        findings: List[Finding] = []
        try:
            if not file_path.exists():
                return findings, 0

            # Skip large files (> 5MB)
            if file_path.stat().st_size > 5 * 1024 * 1024:
                return findings, 0

            # Binary file check: check if null byte occurs in the first 1024 bytes
            with open(file_path, "rb") as f:
                header = f.read(1024)
                if b"\x00" in header:
                    return findings, 0

            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines_count = len(content.splitlines())

            for scanner in self.scanners:
                if scanner.can_scan(file_path):
                    try:
                        f_list = scanner.scan_file(file_path, relative_path, content)
                        findings.extend(f_list)
                    except Exception:
                        pass

            return findings, lines_count
        except (PermissionError, FileNotFoundError, OSError):
            return findings, 0

    def scan_path(self, path: str, min_severity: Optional[Severity] = None) -> ScanResult:
        """Helper method to scan a specific path."""
        self.target_path = Path(path).resolve()
        self.ignore_matcher = IgnoreMatcher(self.target_path)
        return self.scan(min_severity=min_severity)


SecureShipScanner = SecureShipEngine

