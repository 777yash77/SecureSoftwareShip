from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class RemediationResult:
    rule_id: str
    description: str
    file_path: str
    line_number: int
    original: str
    replacement: str


class RemediationEngine:
    """Automated security auto-fix engine for safe vulnerability remediation and code hardening."""

    def __init__(self, target_path: Optional[str] = None):
        self.target_path = Path(target_path).resolve() if target_path else Path.cwd()

    def remediate_content(
        self,
        relative_path: str,
        content: str,
        target_rules: Optional[Set[str]] = None,
    ) -> Tuple[str, List[RemediationResult]]:
        """Applies safe auto-fixes to content and returns modified content with audit log."""
        results: List[RemediationResult] = []
        new_content = content
        ext = Path(relative_path).suffix.lower()
        filename = Path(relative_path).name.lower()

        # 1. Dockerfile remediations
        if "dockerfile" in filename or ext == ".dockerfile":
            new_content, fixes = self._remediate_dockerfile(relative_path, new_content, target_rules)
            results.extend(fixes)

        # 2. Docker Compose remediations
        elif filename in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            new_content, fixes = self._remediate_docker_compose(relative_path, new_content, target_rules)
            results.extend(fixes)

        # 3. Kubernetes manifests
        elif ext in (".yml", ".yaml") and any(k in content for k in ("apiVersion:", "kind: Deployment", "kind: Pod")):
            new_content, fixes = self._remediate_k8s(relative_path, new_content, target_rules)
            results.extend(fixes)

        # 4. Python source files
        elif ext == ".py":
            new_content, fixes = self._remediate_python(relative_path, new_content, target_rules)
            results.extend(fixes)

        # 5. JavaScript / TypeScript files
        elif ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            new_content, fixes = self._remediate_javascript(relative_path, new_content, target_rules)
            results.extend(fixes)

        return new_content, results

    # -------------------------------------------------------------------------
    # DOCKERFILE FIXES
    # -------------------------------------------------------------------------
    def _remediate_dockerfile(
        self, relative_path: str, content: str, target_rules: Optional[Set[str]]
    ) -> Tuple[str, List[RemediationResult]]:
        results: List[RemediationResult] = []
        lines = content.splitlines(keepends=True)
        new_lines: List[str] = []

        has_user = any(re.match(r"^\s*USER\s+", l, re.IGNORECASE) for l in lines)
        user_added = False

        for idx, line in enumerate(lines, 1):
            modified_line = line

            # Rule: IAC-DOCKER-001 (Unpinned/latest image tag)
            if (not target_rules or "IAC-DOCKER-001" in target_rules) and re.match(r"^\s*FROM\s+[^\s:]+:latest\b", line, re.IGNORECASE):
                sub = re.sub(r":latest\b", ":pinned-stable", line, flags=re.IGNORECASE)
                results.append(RemediationResult(
                    rule_id="IAC-DOCKER-001",
                    description="Replaced unpinned ':latest' base image tag with ':pinned-stable'",
                    file_path=relative_path,
                    line_number=idx,
                    original=line.strip(),
                    replacement=sub.strip(),
                ))
                modified_line = sub

            # Rule: IAC-DOCKER-005 (Use COPY instead of ADD)
            if (not target_rules or "IAC-DOCKER-005" in target_rules) and re.match(r"^\s*ADD\s+", line, re.IGNORECASE) and not re.search(r"https?://|\.tar|\.gz|\.zip", line, re.IGNORECASE):
                sub = re.sub(r"^\s*ADD\b", "COPY", line, flags=re.IGNORECASE)
                results.append(RemediationResult(
                    rule_id="IAC-DOCKER-005",
                    description="Replaced insecure ADD instruction with COPY",
                    file_path=relative_path,
                    line_number=idx,
                    original=line.strip(),
                    replacement=sub.strip(),
                ))
                modified_line = sub

            # Rule: IAC-DOCKER-002 (Inject USER nonroot before CMD / ENTRYPOINT)
            if (not target_rules or "IAC-DOCKER-002" in target_rules) and not has_user and not user_added and re.match(r"^\s*(CMD|ENTRYPOINT)\s+", line, re.IGNORECASE):
                new_lines.append("# [secureship-fix] Enforce least-privilege non-root execution\nUSER nonroot\n")
                user_added = True
                results.append(RemediationResult(
                    rule_id="IAC-DOCKER-002",
                    description="Injected 'USER nonroot' directive before container startup entrypoint",
                    file_path=relative_path,
                    line_number=idx,
                    original=line.strip(),
                    replacement=f"USER nonroot\n{line.strip()}",
                ))

            new_lines.append(modified_line)

        return "".join(new_lines), results

    # -------------------------------------------------------------------------
    # DOCKER COMPOSE FIXES
    # -------------------------------------------------------------------------
    def _remediate_docker_compose(
        self, relative_path: str, content: str, target_rules: Optional[Set[str]]
    ) -> Tuple[str, List[RemediationResult]]:
        results: List[RemediationResult] = []
        lines = content.splitlines(keepends=True)
        new_lines: List[str] = []

        for idx, line in enumerate(lines, 1):
            modified_line = line

            # Rule: IAC-COMPOSE-001 (privileged: true -> false)
            if (not target_rules or "IAC-COMPOSE-001" in target_rules) and re.search(r"^\s*privileged\s*:\s*true\b", line, re.IGNORECASE):
                sub = re.sub(r":\s*true\b", ": false", line, flags=re.IGNORECASE)
                results.append(RemediationResult(
                    rule_id="IAC-COMPOSE-001",
                    description="Disabled container privileged mode (privileged: false)",
                    file_path=relative_path,
                    line_number=idx,
                    original=line.strip(),
                    replacement=sub.strip(),
                ))
                modified_line = sub

            new_lines.append(modified_line)

        return "".join(new_lines), results

    # -------------------------------------------------------------------------
    # KUBERNETES FIXES
    # -------------------------------------------------------------------------
    def _remediate_k8s(
        self, relative_path: str, content: str, target_rules: Optional[Set[str]]
    ) -> Tuple[str, List[RemediationResult]]:
        results: List[RemediationResult] = []
        lines = content.splitlines(keepends=True)
        new_lines: List[str] = []

        for idx, line in enumerate(lines, 1):
            modified_line = line

            # Rule: IAC-K8S-002 (privileged: true -> false)
            if (not target_rules or "IAC-K8S-002" in target_rules) and re.search(r"^\s*privileged\s*:\s*true\b", line, re.IGNORECASE):
                sub = re.sub(r":\s*true\b", ": false", line, flags=re.IGNORECASE)
                results.append(RemediationResult(
                    rule_id="IAC-K8S-002",
                    description="Disabled Kubernetes privileged securityContext",
                    file_path=relative_path,
                    line_number=idx,
                    original=line.strip(),
                    replacement=sub.strip(),
                ))
                modified_line = sub

            # Rule: IAC-K8S-004 (hostNetwork: true -> false)
            if (not target_rules or "IAC-K8S-004" in target_rules) and re.search(r"^\s*hostNetwork\s*:\s*true\b", line, re.IGNORECASE):
                sub = re.sub(r":\s*true\b", ": false", line, flags=re.IGNORECASE)
                results.append(RemediationResult(
                    rule_id="IAC-K8S-004",
                    description="Disabled hostNetwork in Pod spec",
                    file_path=relative_path,
                    line_number=idx,
                    original=line.strip(),
                    replacement=sub.strip(),
                ))
                modified_line = sub

            new_lines.append(modified_line)

        return "".join(new_lines), results

    # -------------------------------------------------------------------------
    # PYTHON FIXES
    # -------------------------------------------------------------------------
    def _remediate_python(
        self, relative_path: str, content: str, target_rules: Optional[Set[str]]
    ) -> Tuple[str, List[RemediationResult]]:
        results: List[RemediationResult] = []
        lines = content.splitlines(keepends=True)
        new_lines: List[str] = []

        for idx, line in enumerate(lines, 1):
            modified_line = line

            # Rule: SAST-PY-006 (tempfile.mktemp -> NamedTemporaryFile)
            if (not target_rules or "SAST-PY-006" in target_rules) and "tempfile.mktemp(" in modified_line:
                sub = modified_line.replace("tempfile.mktemp(", "tempfile.NamedTemporaryFile(delete=False).name # replaces insecure mktemp (")
                results.append(RemediationResult(
                    rule_id="SAST-PY-006",
                    description="Replaced insecure tempfile.mktemp() with safe NamedTemporaryFile()",
                    file_path=relative_path,
                    line_number=idx,
                    original=line.strip(),
                    replacement=sub.strip(),
                ))
                modified_line = sub

            # Rule: SAST-PY-004 (md5 / sha1 -> sha256)
            if (not target_rules or "SAST-PY-004" in target_rules):
                if "hashlib.md5(" in modified_line:
                    sub = modified_line.replace("hashlib.md5(", "hashlib.sha256(")
                    results.append(RemediationResult(
                        rule_id="SAST-PY-004",
                        description="Upgraded broken MD5 hashing algorithm to SHA-256",
                        file_path=relative_path,
                        line_number=idx,
                        original=line.strip(),
                        replacement=sub.strip(),
                    ))
                    modified_line = sub
                elif "hashlib.sha1(" in modified_line:
                    sub = modified_line.replace("hashlib.sha1(", "hashlib.sha256(")
                    results.append(RemediationResult(
                        rule_id="SAST-PY-004",
                        description="Upgraded weak SHA-1 hashing algorithm to SHA-256",
                        file_path=relative_path,
                        line_number=idx,
                        original=line.strip(),
                        replacement=sub.strip(),
                    ))
                    modified_line = sub

            # Rule: SAST-PY-010 (Flask debug=True -> debug=False)
            if (not target_rules or "SAST-PY-010" in target_rules) and re.search(r"\bdebug\s*=\s*True\b", modified_line):
                sub = re.sub(r"\bdebug\s*=\s*True\b", "debug=False", modified_line)
                results.append(RemediationResult(
                    rule_id="SAST-PY-010",
                    description="Disabled Flask interactive debugger in production (debug=False)",
                    file_path=relative_path,
                    line_number=idx,
                    original=line.strip(),
                    replacement=sub.strip(),
                ))
                modified_line = sub

            # Rule: SAST-PY-007 (Bind to 0.0.0.0 -> 127.0.0.1)
            if (not target_rules or "SAST-PY-007" in target_rules) and ("'0.0.0.0'" in modified_line or '"0.0.0.0"' in modified_line):
                sub = modified_line.replace("'0.0.0.0'", "'127.0.0.1'").replace('"0.0.0.0"', '"127.0.0.1"')
                results.append(RemediationResult(
                    rule_id="SAST-PY-007",
                    description="Restricted wildcard network binding from 0.0.0.0 to localhost (127.0.0.1)",
                    file_path=relative_path,
                    line_number=idx,
                    original=line.strip(),
                    replacement=sub.strip(),
                ))
                modified_line = sub

            new_lines.append(modified_line)

        return "".join(new_lines), results

    # -------------------------------------------------------------------------
    # JAVASCRIPT FIXES
    # -------------------------------------------------------------------------
    def _remediate_javascript(
        self, relative_path: str, content: str, target_rules: Optional[Set[str]]
    ) -> Tuple[str, List[RemediationResult]]:
        results: List[RemediationResult] = []
        lines = content.splitlines(keepends=True)
        new_lines: List[str] = []

        for idx, line in enumerate(lines, 1):
            modified_line = line

            # Rule: SAST-JS-007 (cors({ origin: '*' }))
            if (not target_rules or "SAST-JS-007" in target_rules) and re.search(r"origin\s*:\s*['\"]\*['\"]", line):
                sub = re.sub(r"origin\s*:\s*['\"]\*['\"]", "origin: false /* restricted by secureship */", line)
                results.append(RemediationResult(
                    rule_id="SAST-JS-007",
                    description="Removed wildcard CORS policy (origin: '*')",
                    file_path=relative_path,
                    line_number=idx,
                    original=line.strip(),
                    replacement=sub.strip(),
                ))
                modified_line = sub

            new_lines.append(modified_line)

        return "".join(new_lines), results

    # -------------------------------------------------------------------------
    # SCAN & REMEDIATE TREE
    # -------------------------------------------------------------------------
    def scan_and_remediate(
        self,
        target_dir: Optional[Path] = None,
        apply: bool = False,
        rules: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Scans directory and either calculates diffs (dry-run) or applies remediation in-place."""
        root = (target_dir or self.target_path).resolve()
        target_rules = set(r.upper() for r in rules) if rules else None

        scanned_files = 0
        remediated_files = 0
        total_fixes = 0
        file_diffs: Dict[str, str] = {}
        all_results: List[RemediationResult] = []

        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if any(part.startswith(".") or part in ("node_modules", "dist", "build", ".venv", "venv", "__pycache__") for part in p.parts):
                continue

            try:
                content = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            scanned_files += 1
            rel = str(p.relative_to(root)).replace("\\", "/")
            new_content, results = self.remediate_content(rel, content, target_rules)

            if results:
                remediated_files += 1
                total_fixes += len(results)
                all_results.extend(results)

                # Generate diff
                diff_lines = list(difflib.unified_diff(
                    content.splitlines(keepends=True),
                    new_content.splitlines(keepends=True),
                    fromfile=f"a/{rel}",
                    tofile=f"b/{rel}",
                ))
                file_diffs[rel] = "".join(diff_lines)

                if apply:
                    p.write_text(new_content, encoding="utf-8")

        return {
            "scanned_files": scanned_files,
            "remediated_files": remediated_files,
            "total_fixes": total_fixes,
            "applied": apply,
            "diffs": file_diffs,
            "results": [
                {
                    "rule_id": r.rule_id,
                    "description": r.description,
                    "file_path": r.file_path,
                    "line_number": r.line_number,
                    "original": r.original,
                    "replacement": r.replacement,
                }
                for r in all_results
            ],
        }
