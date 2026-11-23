from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ContainerAuditFinding:
    rule_id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    file_path: str
    line_number: int
    snippet: str
    description: str
    remediation: str


class ContainerAuditor:
    """Deep container image and Dockerfile security inspector."""

    def __init__(self, target_path: Optional[str] = None):
        self.target_path = Path(target_path).resolve() if target_path else Path.cwd()

    def audit_file(self, file_path: Path, relative_path: str, content: str) -> List[ContainerAuditFinding]:
        findings: List[ContainerAuditFinding] = []
        lines = content.splitlines()

        # Check for multi-stage build
        from_matches = re.findall(r"^\s*FROM\s+", content, re.MULTILINE | re.IGNORECASE)
        has_multistage = len(from_matches) > 1
        has_healthcheck = bool(re.search(r"^\s*HEALTHCHECK\s+", content, re.MULTILINE | re.IGNORECASE))

        # Check for missing multi-stage build on compiled / build-heavy projects
        if not has_multistage and any(b in content for b in ("npm run build", "go build", "mvn package", "gcc", "pip install")):
            findings.append(ContainerAuditFinding(
                rule_id="CONTAINER-001",
                title="Single-Stage Build Leaking Compiler Toolchain",
                severity="MEDIUM",
                file_path=relative_path,
                line_number=1,
                snippet=lines[0] if lines else "FROM ...",
                description="Production container image uses a single-stage build. Compilers, build tools, and dev dependencies will bloat image and expand attack surface.",
                remediation="Adopt multi-stage builds (e.g., 'FROM golang:1.21 AS builder' and 'FROM alpine:3.19 AS runner')."
            ))

        # Check for missing HEALTHCHECK
        if not has_healthcheck:
            findings.append(ContainerAuditFinding(
                rule_id="CONTAINER-002",
                title="Missing Container HEALTHCHECK Instruction",
                severity="LOW",
                file_path=relative_path,
                line_number=1,
                snippet="Dockerfile",
                description="Container has no HEALTHCHECK instruction, preventing orchestrators (K8s/Docker Swarm) from detecting hanging, crashed, or deadlocked processes.",
                remediation="Add 'HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8080/health || exit 1'"
            ))

        for idx, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#"):
                continue

            # Check for secrets in ARG instructions
            if re.search(r"^\s*ARG\s+[a-zA-Z0-9_]*(SECRET|TOKEN|PASSWORD|KEY|PAT|CREDENTIAL)", line_stripped, re.IGNORECASE):
                findings.append(ContainerAuditFinding(
                    rule_id="CONTAINER-003",
                    title="Build-Time Secret Exposed via ARG Instruction",
                    severity="HIGH",
                    file_path=relative_path,
                    line_number=idx,
                    snippet=line_stripped,
                    description="ARG instructions are recorded in container image metadata and can be inspected via 'docker history'.",
                    remediation="Use BuildKit secret mounts instead: 'RUN --mount=type=secret,id=mysecret ...'"
                ))

            # Check for apt-get clean omission (cache bloat)
            if "apt-get install" in line_stripped and "rm -rf /var/lib/apt/lists" not in line_stripped and not any("rm -rf /var/lib/apt/lists" in l for l in lines[idx-1:idx+3]):
                findings.append(ContainerAuditFinding(
                    rule_id="CONTAINER-004",
                    title="Package Manager Cache Persisted in Container Layer",
                    severity="LOW",
                    file_path=relative_path,
                    line_number=idx,
                    snippet=line_stripped,
                    description="apt-get package caches are persisted into the container layer, inflating image size and attack surface.",
                    remediation="Combine apt-get update, install, and 'rm -rf /var/lib/apt/lists/*' into a single RUN layer."
                ))

            # Check for SUID binaries creation
            if re.search(r"chmod\s+(?:u\+s|[0-7]?[4-7][0-7]{2})", line_stripped):
                findings.append(ContainerAuditFinding(
                    rule_id="CONTAINER-005",
                    title="Dangerous SUID Bit Enabled on Binary",
                    severity="HIGH",
                    file_path=relative_path,
                    line_number=idx,
                    snippet=line_stripped,
                    description="Setting SUID bit allows unprivileged processes to execute binary with file owner privileges (root).",
                    remediation="Remove SUID bit and run processes using least privilege."
                ))

        return findings

    def audit_directory(self, target_dir: Optional[Path] = None) -> List[ContainerAuditFinding]:
        root = (target_dir or self.target_path).resolve()
        findings: List[ContainerAuditFinding] = []

        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if "dockerfile" in p.name.lower() or p.suffix.lower() == ".dockerfile":
                rel = str(p.relative_to(root)).replace("\\", "/")
                try:
                    content = p.read_text(encoding="utf-8", errors="replace")
                    findings.extend(self.audit_file(p, rel, content))
                except Exception:
                    pass

        # Check for missing .dockerignore if Dockerfiles exist
        if findings and not (root / ".dockerignore").exists():
            findings.append(ContainerAuditFinding(
                rule_id="CONTAINER-006",
                title="Missing .dockerignore in Project Root",
                severity="MEDIUM",
                file_path=".dockerignore",
                line_number=1,
                snippet="Project Root",
                description="No .dockerignore file found. Building containers may inadvertently send .git, .env, and secrets to the Docker daemon build context.",
                remediation="Create a .dockerignore file excluding .git, .env, node_modules, and sensitive data."
            ))

        return findings

    @staticmethod
    def findings_to_dict(findings: List[ContainerAuditFinding]) -> List[Dict[str, Any]]:
        return [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "snippet": f.snippet,
                "description": f.description,
                "remediation": f.remediation,
            }
            for f in findings
        ]
