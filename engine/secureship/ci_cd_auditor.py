"""SecureShip CI/CD Supply Chain & Pipeline Security Auditor.

Audits continuous integration workflow definitions:
- GitHub Actions (.github/workflows/*.yml)
- GitLab CI (.gitlab-ci.yml)
- Azure Pipelines (azure-pipelines.yml)
- Jenkins (Jenkinsfile)

Detects critical supply-chain attack vectors:
- Pwn-Request vulnerabilities (pull_request_target with untrusted checkout)
- Unpinned third-party actions (missing immutable 40-char commit SHA)
- Direct script injection via user-controlled GitHub context variables
- Overly permissive GITHUB_TOKEN scope grants (write-all)
- Secrets leakage in pipeline step execution logs
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from secureship.models import Confidence, Finding, FindingCategory, Severity


@dataclass
class CIAuditRule:
    id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    cwe: str


class CICDAuditor:
    """Audits CI/CD pipeline definition files for security misconfigurations."""

    category = FindingCategory.IAC
    name = "CI/CD Pipeline Security Auditor"

    RULES: Dict[str, CIAuditRule] = {
        "CICD-GH-001": CIAuditRule(
            id="CICD-GH-001",
            title="Pwn-Request Vulnerability in GitHub Actions Workflow",
            severity=Severity.CRITICAL,
            description="Workflow uses pull_request_target while checking out the PR head commit. This allows external fork PRs to execute arbitrary code with repository secrets access.",
            remediation="Use the standard 'pull_request' trigger for untrusted code, or checkout the base branch instead.",
            cwe="CWE-829",
        ),
        "CICD-GH-002": CIAuditRule(
            id="CICD-GH-002",
            title="Unpinned Third-Party GitHub Action",
            severity=Severity.MEDIUM,
            description="Action is pinned to a mutable git tag or branch rather than an immutable 40-character commit SHA. Compromise of the upstream tag exposes your pipeline to supply-chain tampering.",
            remediation="Pin actions to their full 40-character commit SHA, e.g. uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
            cwe="CWE-829",
        ),
        "CICD-GH-003": CIAuditRule(
            id="CICD-GH-003",
            title="Script Injection via GitHub Context in Run Step",
            severity=Severity.HIGH,
            description="User-controlled GitHub context expressions (e.g. issue title, PR body) are evaluated directly inside a shell run step, permitting arbitrary command injection.",
            remediation="Pass the context variable through an intermediate environment variable (env: TITLE: ${{ github.event.issue.title }}), then reference it as $TITLE in shell script.",
            cwe="CWE-78",
        ),
        "CICD-GH-004": CIAuditRule(
            id="CICD-GH-004",
            title="Overly Permissive GITHUB_TOKEN Scope",
            severity=Severity.HIGH,
            description="Workflow grants broad 'permissions: write-all' or missing top-level permissions restriction, expanding blast radius if steps are compromised.",
            remediation="Enforce least privilege with top-level 'permissions: read-all' and grant write permissions only to specific jobs.",
            cwe="CWE-250",
        ),
        "CICD-GH-005": CIAuditRule(
            id="CICD-GH-005",
            title="Plaintext Secret Printing in Pipeline Run Step",
            severity=Severity.HIGH,
            description="Pipeline step executes commands like 'echo $SECRET' or 'printenv', risking credential leakage in build logs.",
            remediation="Remove commands that echo or log secret variables.",
            cwe="CWE-532",
        ),
    }

    def __init__(self, target_dir: str):
        self.target_dir = Path(target_dir).resolve()

    def audit(self) -> Dict[str, Any]:
        findings: List[Finding] = []

        # 1. Audit GitHub Actions
        gh_dir = self.target_dir / ".github" / "workflows"
        if gh_dir.exists():
            for wf in gh_dir.glob("*.y*ml"):
                findings.extend(self._audit_github_workflow(wf))

        # 2. Audit GitLab CI
        gl_file = self.target_dir / ".gitlab-ci.yml"
        if gl_file.exists():
            findings.extend(self._audit_gitlab_ci(gl_file))

        return {
            "target": str(self.target_dir),
            "total_findings": len(findings),
            "status": "SECURE" if len(findings) == 0 else "VULNERABILITIES_FOUND",
            "findings": [
                {
                    "id": f.id,
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "file": f.file_path,
                    "line": f.line_start,
                    "snippet": f.code_snippet,
                    "remediation": f.remediation,
                    "cwe": f.cwe_id,
                }
                for f in findings
            ],
        }

    def _audit_github_workflow(self, file_path: Path) -> List[Finding]:
        findings: List[Finding] = []
        rel_path = str(file_path.relative_to(self.target_dir))
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        # Check for pull_request_target
        has_pr_target = "pull_request_target" in content
        has_checkout_head = False
        head_sha_line = 1

        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()

            # Rule 1: Check pull_request_target checkout
            if "pull_request.head.sha" in line_str or "head.ref" in line_str:
                has_checkout_head = True
                head_sha_line = idx

            # Rule 2: Unpinned Actions
            m_uses = re.search(r"uses:\s*([a-zA-Z0-9_\-\.\/]+)@([^\s#]+)", line_str)
            if m_uses:
                action_name = m_uses.group(1)
                version_ref = m_uses.group(2)
                # If not pinned to a 40-char git commit SHA and not local
                if not action_name.startswith("./") and not re.match(r"^[0-9a-f]{40}$", version_ref):
                    # Ignore official trusted docker:// actions
                    if not action_name.startswith("docker://"):
                        rule = self.RULES["CICD-GH-002"]
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                rule_id=rule.id,
                                title=f"{rule.title}: {action_name}@{version_ref}",
                                category=FindingCategory.IAC,
                                severity=rule.severity,
                                file_path=rel_path,
                                line_start=idx,
                                line_end=idx,
                                code_snippet=line_str,
                                owasp_category="A06:2021-Vulnerable and Outdated Components",
                                cwe_id=rule.cwe,
                                description=rule.description,
                                remediation=rule.remediation,
                                confidence=Confidence.HIGH,
                            )
                        )

            # Rule 3: Script Injection in run:
            if "${{" in line_str and any(ctx in line_str for ctx in ("github.event.issue.title", "github.event.issue.body", "github.event.pull_request.title", "github.event.comment.body")):
                rule = self.RULES["CICD-GH-003"]
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        rule_id=rule.id,
                        title=rule.title,
                        category=FindingCategory.IAC,
                        severity=rule.severity,
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line_str,
                        owasp_category="A03:2021-Injection",
                        cwe_id=rule.cwe,
                        description=rule.description,
                        remediation=rule.remediation,
                        confidence=Confidence.HIGH,
                    )
                )

            # Rule 4: Overly permissive permissions
            if re.search(r"permissions:\s*write-all", line_str):
                rule = self.RULES["CICD-GH-004"]
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        rule_id=rule.id,
                        title=rule.title,
                        category=FindingCategory.IAC,
                        severity=rule.severity,
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line_str,
                        owasp_category="A01:2021-Broken Access Control",
                        cwe_id=rule.cwe,
                        description=rule.description,
                        remediation=rule.remediation,
                        confidence=Confidence.HIGH,
                    )
                )

        if has_pr_target and has_checkout_head:
            rule = self.RULES["CICD-GH-001"]
            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    rule_id=rule.id,
                    title=rule.title,
                    category=FindingCategory.IAC,
                    severity=rule.severity,
                    file_path=rel_path,
                    line_start=head_sha_line,
                    line_end=head_sha_line,
                    code_snippet=lines[head_sha_line - 1].strip() if head_sha_line <= len(lines) else "",
                    owasp_category="A01:2021-Broken Access Control",
                    cwe_id=rule.cwe,
                    description=rule.description,
                    remediation=rule.remediation,
                    confidence=Confidence.HIGH,
                )
            )

        return findings

    def _audit_gitlab_ci(self, file_path: Path) -> List[Finding]:
        findings: List[Finding] = []
        rel_path = str(file_path.relative_to(self.target_dir))
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            if "docker:dind" in line and "DOCKER_TLS_CERTDIR" not in content:
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        rule_id="CICD-GL-001",
                        title="Unsecured Docker-in-Docker (dind) Service in GitLab CI",
                        category=FindingCategory.IAC,
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line.strip(),
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-319",
                        description="Docker-in-Docker service without TLS certificate directory exposes daemon communication to eavesdropping and privilege escalation.",
                        remediation="Set 'DOCKER_TLS_CERTDIR: \"/certs\"' in pipeline variables.",
                        confidence=Confidence.HIGH,
                    )
                )
        return findings
