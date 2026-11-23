from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import List, Optional, Set

from secureship.models import Confidence, Finding, FindingCategory, Severity
from secureship.scanners.base import BaseScanner
from secureship.scorer import IgnoreMatcher


class IaCScanner(BaseScanner):
    """Scanner for Dockerfile, docker-compose.yml, and Kubernetes YAML security misconfigurations."""

    category = FindingCategory.IAC
    name = "Container & IaC Security Scanner"

    SENSITIVE_PORTS = {"22", "3306", "5432", "6379", "27017"}

    @property
    def supported_extensions(self) -> Set[str]:
        return {".dockerfile", ".yml", ".yaml", ".tf"}

    def can_scan(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        if "dockerfile" in name:
            return True
        if name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            return True
        if file_path.suffix.lower() in (".yml", ".yaml", ".tf"):
            return True
        return False

    def scan_file(self, file_path: Path, relative_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        name = file_path.name.lower()
        ext = file_path.suffix.lower()

        if "dockerfile" in name or ext == ".dockerfile":
            findings.extend(self._scan_dockerfile(file_path, relative_path, content))
        elif name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            findings.extend(self._scan_docker_compose(file_path, relative_path, content))
        elif ext in (".yml", ".yaml"):
            # Could be K8s manifest or compose
            if any(k in content for k in ("apiVersion:", "kind: Deployment", "kind: Pod", "kind: StatefulSet", "kind: DaemonSet")):
                findings.extend(self._scan_k8s_manifest(file_path, relative_path, content))
            elif "services:" in content:
                findings.extend(self._scan_docker_compose(file_path, relative_path, content))
        elif ext == ".tf":
            findings.extend(self._scan_terraform(file_path, relative_path, content))

        return findings

    # =========================================================================
    # DOCKERFILE SCANNER
    # =========================================================================

    def _scan_dockerfile(self, file_path: Path, relative_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        has_user_directive = False
        from_line = 1

        for idx, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#"):
                continue

            if IgnoreMatcher.is_line_suppressed(line):
                continue

            # Track USER directive
            if re.match(r"^USER\s+", line_stripped, re.IGNORECASE):
                has_user_directive = True

            # Track base image tag
            from_match = re.match(r"^FROM\s+([^\s]+)", line_stripped, re.IGNORECASE)
            if from_match:
                from_line = idx
                image = from_match.group(1)
                # Check for :latest or unpinned tag
                if ":" not in image or image.endswith(":latest"):
                    if not IgnoreMatcher.is_line_suppressed(line, "IAC-DOCKER-002"):
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                rule_id="IAC-DOCKER-002",
                                title="Unpinned Base Image Tag (:latest)",
                                category=FindingCategory.IAC,
                                severity=Severity.MEDIUM,
                                file_path=relative_path,
                                line_start=idx,
                                line_end=idx,
                                code_snippet=line_stripped,
                                owasp_category="A05:2021-Security Misconfiguration",
                                cwe_id="CWE-1188",
                                description="Base image relies on unpinned or :latest tag, leading to unpredictable, non-reproducible builds.",
                                remediation="Pin base image to an exact immutable version tag or SHA256 digest: FROM python:3.11.9-slim",
                                auto_fix_hint="FROM python:3.11-slim",
                            )
                        )

            # Check ADD instruction
            if re.match(r"^ADD\s+", line_stripped, re.IGNORECASE):
                if not IgnoreMatcher.is_line_suppressed(line, "IAC-DOCKER-004"):
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            rule_id="IAC-DOCKER-004",
                            title="Dangerous ADD Instruction in Dockerfile",
                            category=FindingCategory.IAC,
                            severity=Severity.MEDIUM,
                            file_path=relative_path,
                            line_start=idx,
                            line_end=idx,
                            code_snippet=line_stripped,
                            owasp_category="A05:2021-Security Misconfiguration",
                            cwe_id="CWE-829",
                            description="ADD automatically uncompresses archives and fetches remote URLs. Use COPY for predictable, secure local file copying.",
                            remediation="Replace ADD with COPY unless remote archive unpacking is strictly intended.",
                            auto_fix_hint="COPY src dest",
                            confidence=Confidence.HIGH,
                        )
                    )

            # Check curl/wget piped to shell
            if re.search(r"(?:curl|wget)\s+[^|]+\|\s*(?:sh|bash|ash|zsh)", line_stripped, re.IGNORECASE):
                if not IgnoreMatcher.is_line_suppressed(line, "IAC-DOCKER-005"):
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            rule_id="IAC-DOCKER-005",
                            title="Insecure Pipe to Shell (curl/wget | sh)",
                            category=FindingCategory.IAC,
                            severity=Severity.HIGH,
                            file_path=relative_path,
                            line_start=idx,
                            line_end=idx,
                            code_snippet=line_stripped,
                            owasp_category="A03:2021-Injection",
                            cwe_id="CWE-78",
                            description="Piping remote scripts from curl/wget directly to a shell runs untrusted, unverified code during container build.",
                            remediation="Download the script first, verify its cryptographic hash or GPG signature, and then execute it.",
                            auto_fix_hint="Download script and verify checksum before execution",
                            confidence=Confidence.HIGH,
                        )
                    )

            # Check for secrets in ENV or ARG
            secret_match = re.match(
                r"^(?:ENV|ARG)\s+([A-Za-z0-9_]+)\s*[:=]?\s*['\"]?([^'\"\s]+)['\"]?",
                line_stripped,
                re.IGNORECASE,
            )
            if secret_match:
                var_name = secret_match.group(1).lower()
                val = secret_match.group(2) if len(secret_match.groups()) > 1 else ""
                if any(k in var_name for k in ("secret", "password", "token", "key", "api_key", "auth")):
                    if val and val not in ("''", '""') and not IgnoreMatcher.is_line_suppressed(line, "IAC-DOCKER-003"):
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                rule_id="IAC-DOCKER-003",
                                title="Sensitive Credential in Dockerfile ENV/ARG",
                                category=FindingCategory.IAC,
                                severity=Severity.CRITICAL,
                                file_path=relative_path,
                                line_start=idx,
                                line_end=idx,
                                code_snippet=line_stripped,
                                owasp_category="A07:2021-Identification and Authentication Failures",
                                cwe_id="CWE-798",
                                description="Sensitive environment variable or argument hardcoded in Dockerfile. Value persists in image metadata layers.",
                                remediation="Use BuildKit secrets mount (RUN --mount=type=secret) or runtime environment injection.",
                                auto_fix_hint="Inject credentials dynamically at container runtime.",
                            )
                        )

        # If no USER directive found in Dockerfile, flag root execution
        if not has_user_directive and lines:
            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    rule_id="IAC-DOCKER-001",
                    title="Container Running as Root (Missing USER Instruction)",
                    category=FindingCategory.IAC,
                    severity=Severity.HIGH,
                    file_path=relative_path,
                    line_start=from_line,
                    line_end=len(lines),
                    code_snippet="USER nonroot (missing)",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-250",
                    description="Dockerfile has no USER directive; container processes will run with root privileges inside the container.",
                    remediation="Create a dedicated unprivileged user and switch to it before ENTRYPOINT: RUN adduser -D appuser && USER appuser",
                    auto_fix_hint="USER appuser",
                )
            )

        return findings

    # =========================================================================
    # DOCKER-COMPOSE SCANNER
    # =========================================================================

    def _scan_docker_compose(self, file_path: Path, relative_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#"):
                continue
            if IgnoreMatcher.is_line_suppressed(line):
                continue

            # Check privileged: true
            if re.search(r"privileged\s*:\s*true", line_stripped, re.IGNORECASE):
                if not IgnoreMatcher.is_line_suppressed(line, "IAC-COMPOSE-001"):
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            rule_id="IAC-COMPOSE-001",
                            title="Privileged Container Execution",
                            category=FindingCategory.IAC,
                            severity=Severity.CRITICAL,
                            file_path=relative_path,
                            line_start=idx,
                            line_end=idx,
                            code_snippet=line_stripped,
                            owasp_category="A05:2021-Security Misconfiguration",
                            cwe_id="CWE-250",
                            description="Container configured with privileged: true has full host device and kernel access, allowing container escapes.",
                            remediation="Remove privileged: true and grant only explicit Linux capabilities via cap_add if required.",
                            auto_fix_hint="privileged: false",
                        )
                    )

            # Check docker socket mount
            if "/var/run/docker.sock" in line_stripped:
                if not IgnoreMatcher.is_line_suppressed(line, "IAC-COMPOSE-003"):
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            rule_id="IAC-COMPOSE-003",
                            title="Docker Daemon Socket Mounted Inside Container",
                            category=FindingCategory.IAC,
                            severity=Severity.CRITICAL,
                            file_path=relative_path,
                            line_start=idx,
                            line_end=idx,
                            code_snippet=line_stripped,
                            owasp_category="A05:2021-Security Misconfiguration",
                            cwe_id="CWE-250",
                            description="Mounting /var/run/docker.sock gives the container full administrative control over the host Docker daemon, allowing root host takeover.",
                            remediation="Avoid mounting docker.sock into containers. Use isolated Docker-in-Docker or dedicated build agents.",
                            auto_fix_hint="Remove /var/run/docker.sock volume mount",
                            confidence=Confidence.HIGH,
                        )
                    )

            # Check host network mode
            if re.search(r"network_mode\s*:\s*['\"]?host['\"]?", line_stripped, re.IGNORECASE):
                if not IgnoreMatcher.is_line_suppressed(line, "IAC-COMPOSE-004"):
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            rule_id="IAC-COMPOSE-004",
                            title="Host Network Mode Enabled",
                            category=FindingCategory.IAC,
                            severity=Severity.HIGH,
                            file_path=relative_path,
                            line_start=idx,
                            line_end=idx,
                            code_snippet=line_stripped,
                            owasp_category="A05:2021-Security Misconfiguration",
                            cwe_id="CWE-668",
                            description="network_mode: 'host' disables container network isolation and exposes host network services directly.",
                            remediation="Use bridge or user-defined overlay networks with specific port mappings.",
                            auto_fix_hint="network_mode: bridge",
                            confidence=Confidence.HIGH,
                        )
                    )

            # Check sensitive ports exposed to 0.0.0.0
            port_match = re.search(r"""(?:["']?)(?:0\.0\.0\.0:)?(\d{2,5}):(\d{2,5})""", line_stripped)
            if port_match:
                host_port = port_match.group(1)
                container_port = port_match.group(2)
                if host_port in self.SENSITIVE_PORTS or container_port in self.SENSITIVE_PORTS:
                    # If not explicitly bound to 127.0.0.1
                    if "127.0.0.1:" not in line_stripped and not IgnoreMatcher.is_line_suppressed(line, "IAC-COMPOSE-002"):
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                rule_id="IAC-COMPOSE-002",
                                title=f"Exposed Sensitive Service Port ({container_port})",
                                category=FindingCategory.IAC,
                                severity=Severity.HIGH,
                                file_path=relative_path,
                                line_start=idx,
                                line_end=idx,
                                code_snippet=line_stripped,
                                owasp_category="A05:2021-Security Misconfiguration",
                                cwe_id="CWE-200",
                                description=f"Database / internal service port {container_port} is bound to all host interfaces without loopback restriction.",
                                remediation=f"Bind port to localhost only: '127.0.0.1:{host_port}:{container_port}' or use internal Docker network.",
                                auto_fix_hint=f"'127.0.0.1:{host_port}:{container_port}'",
                            )
                        )

        return findings

    # =========================================================================
    # KUBERNETES MANIFEST SCANNER
    # =========================================================================

    def _scan_k8s_manifest(self, file_path: Path, relative_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        has_containers = "containers:" in content
        has_resources = "resources:" in content and ("limits:" in content or "requests:" in content)

        if has_containers and not has_resources:
            # Missing resource limits
            first_container_line = 1
            for idx, line in enumerate(lines, start=1):
                if "containers:" in line:
                    first_container_line = idx
                    break

            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    rule_id="IAC-K8S-001",
                    title="Missing Pod Resource Limits (CPU/Memory)",
                    category=FindingCategory.IAC,
                    severity=Severity.MEDIUM,
                    file_path=relative_path,
                    line_start=first_container_line,
                    line_end=first_container_line,
                    code_snippet="containers: (no resources.limits defined)",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-400",
                    description="Kubernetes containers without resource limits can cause Denial of Service (DoS) and starve neighboring workloads.",
                    remediation="Define resources.limits.cpu and resources.limits.memory for each container.",
                    auto_fix_hint="resources:\n  limits:\n    cpu: '500m'\n    memory: '512Mi'",
                )
            )

        for idx, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if IgnoreMatcher.is_line_suppressed(line):
                continue

            if "privileged: true" in line_stripped:
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        rule_id="IAC-K8S-002",
                        title="Privileged Pod Security Context",
                        category=FindingCategory.IAC,
                        severity=Severity.CRITICAL,
                        file_path=relative_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line_stripped,
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-250",
                        description="Pod securityContext has privileged: true, allowing pod root to execute host operations.",
                        remediation="Set privileged: false and drop unnecessary capabilities.",
                        auto_fix_hint="privileged: false",
                        confidence=Confidence.HIGH,
                    )
                )

            if "allowPrivilegeEscalation: true" in line_stripped:
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        rule_id="IAC-K8S-003",
                        title="Container Privilege Escalation Allowed",
                        category=FindingCategory.IAC,
                        severity=Severity.HIGH,
                        file_path=relative_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line_stripped,
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-250",
                        description="allowPrivilegeEscalation: true allows container processes to gain more privileges than their parent process via setuid binaries.",
                        remediation="Set securityContext.allowPrivilegeEscalation: false.",
                        auto_fix_hint="allowPrivilegeEscalation: false",
                        confidence=Confidence.HIGH,
                    )
                )

            if "readOnlyRootFilesystem: false" in line_stripped:
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        rule_id="IAC-K8S-004",
                        title="Writable Container Root Filesystem",
                        category=FindingCategory.IAC,
                        severity=Severity.MEDIUM,
                        file_path=relative_path,
                        line_start=idx,
                        line_end=idx,
                        code_snippet=line_stripped,
                        owasp_category="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-250",
                        description="Container root filesystem is writable, allowing malicious software or payloads to be written to disk.",
                        remediation="Set securityContext.readOnlyRootFilesystem: true and use emptyDir mounts for temporary write directories.",
                        auto_fix_hint="readOnlyRootFilesystem: true",
                        confidence=Confidence.HIGH,
                    )
                )

        return findings

    # =========================================================================
    # TERRAFORM SCANNER
    # =========================================================================

    def _scan_terraform(self, file_path: Path, relative_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#") or line_stripped.startswith("//"):
                continue

            # IAC-TF-001: Public S3 Bucket ACL
            if not IgnoreMatcher.is_line_suppressed(line_stripped, "IAC-TF-001"):
                if re.search(r'acl\s*=\s*["\'](public-read|public-read-write)["\']', line_stripped, re.IGNORECASE):
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            rule_id="IAC-TF-001",
                            title="Publicly Accessible S3 Bucket ACL",
                            category=FindingCategory.IAC,
                            severity=Severity.CRITICAL,
                            file_path=relative_path,
                            line_start=idx,
                            line_end=idx,
                            code_snippet=line_stripped,
                            owasp_category="A01:2021-Broken Access Control",
                            cwe_id="CWE-284",
                            description="Terraform config sets S3 bucket ACL to public-read or public-read-write, exposing all bucket data to the public internet.",
                            remediation="Set acl = 'private' and enable aws_s3_bucket_public_access_block.",
                            auto_fix_hint="acl = \"private\"",
                            confidence=Confidence.HIGH,
                        )
                    )

            # IAC-TF-002: Ingress from 0.0.0.0/0 on sensitive ports
            if not IgnoreMatcher.is_line_suppressed(line_stripped, "IAC-TF-002"):
                if re.search(r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']\s*\]', line_stripped) and any(p in content for p in ('from_port = 22', 'from_port = 3389', 'from_port = 3306', 'from_port = 5432')):
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            rule_id="IAC-TF-002",
                            title="Security Group Ingress Open to 0.0.0.0/0 on Sensitive Port",
                            category=FindingCategory.IAC,
                            severity=Severity.HIGH,
                            file_path=relative_path,
                            line_start=idx,
                            line_end=idx,
                            code_snippet=line_stripped,
                            owasp_category="A01:2021-Broken Access Control",
                            cwe_id="CWE-284",
                            description="Terraform security group opens sensitive port (SSH 22, RDP 3389, DB) to the entire public internet (0.0.0.0/0).",
                            remediation="Restrict ingress cidr_blocks to specific trusted corporate IP blocks or VPN CIDRs.",
                            auto_fix_hint="cidr_blocks = [\"10.0.0.0/16\"]",
                            confidence=Confidence.HIGH,
                        )
                    )

            # IAC-TF-003: Unencrypted EBS volume or RDS database
            if not IgnoreMatcher.is_line_suppressed(line_stripped, "IAC-TF-003"):
                if re.search(r'(encrypted|storage_encrypted)\s*=\s*false\b', line_stripped, re.IGNORECASE):
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            rule_id="IAC-TF-003",
                            title="Unencrypted Cloud Storage or Database Volume",
                            category=FindingCategory.IAC,
                            severity=Severity.HIGH,
                            file_path=relative_path,
                            line_start=idx,
                            line_end=idx,
                            code_snippet=line_stripped,
                            owasp_category="A02:2021-Cryptographic Failures",
                            cwe_id="CWE-311",
                            description="Terraform configuration explicitly disables encryption at rest on storage volume or relational database instance.",
                            remediation="Enable encryption at rest (encrypted = true, storage_encrypted = true) using AWS KMS.",
                            auto_fix_hint="encrypted = true",
                            confidence=Confidence.HIGH,
                        )
                    )

        return findings
