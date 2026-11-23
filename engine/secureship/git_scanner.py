from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from secureship.scanners.secrets_scanner import SecretsScanner


@dataclass
class HistoricalSecretFinding:
    commit_sha: str
    author: str
    date: str
    message: str
    file_path: str
    line_number: int
    rule_id: str
    secret_type: str
    redacted_secret: str
    remediation_cmd: str


class GitHistoryScanner:
    """Scans Git repository commit history for historical secret and credential leaks."""

    def __init__(self, target_path: Optional[str] = None):
        self.target_path = Path(target_path).resolve() if target_path else Path.cwd()
        self.secrets_scanner = SecretsScanner()

    def scan_history(
        self,
        repo_dir: Optional[Path] = None,
        max_commits: int = 50,
        branch: Optional[str] = None,
    ) -> List[HistoricalSecretFinding]:
        root = (repo_dir or self.target_path).resolve()
        git_dir = root / ".git"
        if not git_dir.exists():
            return []

        cmd = ["git", "-C", str(root), "log", "-p", f"-n{max_commits}", "--no-color"]
        if branch:
            cmd.append(branch)

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", check=False)
            if res.returncode != 0:
                return []
            return self._parse_log_diff(res.stdout)
        except Exception:
            return []

    def _parse_log_diff(self, log_output: str) -> List[HistoricalSecretFinding]:
        findings: List[HistoricalSecretFinding] = []

        current_commit = ""
        current_author = ""
        current_date = ""
        current_msg = ""
        current_file = ""
        line_num = 0

        for line in log_output.splitlines():
            # Match commit hash
            commit_match = re.match(r"^commit\s+([a-f0-9]{40})", line)
            if commit_match:
                current_commit = commit_match.group(1)[:8]
                current_author = ""
                current_date = ""
                current_msg = ""
                continue

            if line.startswith("Author: "):
                current_author = line.replace("Author: ", "").strip()
                continue

            if line.startswith("Date: "):
                current_date = line.replace("Date: ", "").strip()
                continue

            if line.startswith("    ") and not current_msg:
                current_msg = line.strip()
                continue

            if line.startswith("diff --git "):
                m = re.search(r"b/(.+)$", line)
                if m:
                    current_file = m.group(1)
                line_num = 0
                continue

            if line.startswith("@@ "):
                m = re.search(r"\+(\d+)", line)
                if m:
                    line_num = int(m.group(1)) - 1
                continue

            if line.startswith("+") and not line.startswith("+++"):
                line_num += 1
                added_code = line[1:].strip()
                if not added_code:
                    continue

                # Run line through secrets scanner
                sec_findings = self.secrets_scanner.scan_file(
                    Path(current_file), current_file, added_code
                )
                for sf in sec_findings:
                    findings.append(HistoricalSecretFinding(
                        commit_sha=current_commit,
                        author=current_author,
                        date=current_date,
                        message=current_msg,
                        file_path=current_file,
                        line_number=line_num,
                        rule_id=sf.rule_id,
                        secret_type=sf.title,
                        redacted_secret=sf.code_snippet,
                        remediation_cmd=f"git filter-repo --invert-paths --path {current_file}",
                    ))
            elif not line.startswith("-"):
                line_num += 1

        return findings

    @staticmethod
    def findings_to_dict(findings: List[HistoricalSecretFinding]) -> List[Dict[str, Any]]:
        return [
            {
                "commit_sha": f.commit_sha,
                "author": f.author,
                "date": f.date,
                "message": f.message,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "rule_id": f.rule_id,
                "secret_type": f.secret_type,
                "redacted_secret": f.redacted_secret,
                "remediation_cmd": f.remediation_cmd,
            }
            for f in findings
        ]
