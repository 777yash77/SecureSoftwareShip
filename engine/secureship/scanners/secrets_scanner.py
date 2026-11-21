from __future__ import annotations

import math
import re
import uuid
from collections import Counter
from pathlib import Path
from typing import List, Optional, Set, Tuple

from secureship.models import Finding, FindingCategory, Severity
from secureship.scanners.base import BaseScanner
from secureship.scorer import IgnoreMatcher


def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = Counter(data)
    for count in counts.values():
        p_x = count / length
        entropy += -p_x * math.log2(p_x)
    return entropy


class SecretsScanner(BaseScanner):
    """Scanner for detecting hardcoded secrets, tokens, credentials, and exposed .env files."""

    category = FindingCategory.SECRETS
    name = "Secret & Credential Scanner"

    SAFE_PLACEHOLDERS = {
        "example", "changeme", "placeholder", "test", "dummy", "fake",
        "sample", "xxxx", "your-key", "my-secret", "secret123", "password123",
        "todo", "replace_me", "none", "null", "undefined", "<secret>"
    }

    # Common binary or asset extensions to skip
    EXCLUDED_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
        ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".tar", ".gz", ".exe", ".dll",
        ".so", ".dylib", ".bin", ".pdf", ".lock"
    }

    RULES = [
        {
            "id": "SEC-001",
            "title": "Hardcoded AWS Access Key ID",
            "regex": re.compile(r"(?:^|[^A-Z0-9])((?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})(?:[^A-Z0-9]|$)", re.IGNORECASE),
            "severity": Severity.CRITICAL,
            "description": "Hardcoded AWS access key detected. An attacker can use this key to access cloud resources.",
            "remediation": "Store the AWS credentials in environment variables (AWS_ACCESS_KEY_ID) or use AWS IAM Roles/AWS Secrets Manager.",
            "auto_fix": "os.environ.get('AWS_ACCESS_KEY_ID')",
        },
        {
            "id": "SEC-002",
            "title": "Hardcoded GitHub Personal Access Token",
            "regex": re.compile(r"(gh[pousr]_[A-Za-z0-9_]{36,255})"),
            "severity": Severity.CRITICAL,
            "description": "Hardcoded GitHub personal access token detected. This could grant write or admin access to repositories.",
            "remediation": "Revoke the token immediately and inject it at runtime using GitHub Actions secrets or environment variables.",
            "auto_fix": "os.environ.get('GITHUB_TOKEN')",
        },
        {
            "id": "SEC-003",
            "title": "Hardcoded Private RSA/SSH/PGP Key",
            "regex": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
            "severity": Severity.CRITICAL,
            "description": "Asymmetric private cryptographic key found committed directly in code.",
            "remediation": "Remove the private key from the repository, rotate the key pair, and load keys from a secure vault or file outside the repo.",
            "auto_fix": "Load private key from secret vault or secure filesystem path.",
        },
        {
            "id": "SEC-004",
            "title": "Database Connection String with Embedded Password",
            "regex": re.compile(r"(?:postgres|postgresql|mysql|mongodb|redis|mssql):\/\/[^\s:]+:([^\s@]+)@[^\s\/]+", re.IGNORECASE),
            "severity": Severity.HIGH,
            "description": "Database connection URI contains an embedded plain-text password.",
            "remediation": "Extract the database password or the entire connection URI into an environment variable (DATABASE_URL).",
            "auto_fix": "os.environ.get('DATABASE_URL')",
        },
        {
            "id": "SEC-005",
            "title": "Exposed Hardcoded JWT Token",
            "regex": re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
            "severity": Severity.HIGH,
            "description": "Hardcoded JSON Web Token (JWT) detected. May expose session tokens or sensitive claims.",
            "remediation": "Generate tokens dynamically at runtime and do not hardcode authorization tokens.",
            "auto_fix": "Generate dynamically at runtime",
        },
        {
            "id": "SEC-006",
            "title": "High-Entropy API Key / Secret Assignment",
            "regex": re.compile(
                r"""(?i)(?:api[_-]?key|secret|token|auth[_-]?key|client[_-]?secret)\s*[:=]\s*["']([A-Za-z0-9_\-+=/.]{16,})["']"""
            ),
            "severity": Severity.HIGH,
            "description": "High-entropy secret or API key assignment detected via heuristic analysis.",
            "remediation": "Move secrets to an external configuration manager, environment variables, or a KMS.",
            "auto_fix": "os.environ.get('API_KEY')",
        },
    ]

    @property
    def supported_extensions(self) -> Set[str]:
        # Empty means inspect any text file not in excluded list
        return set()

    def can_scan(self, file_path: Path) -> bool:
        if file_path.suffix.lower() in self.EXCLUDED_EXTENSIONS:
            return False
        return True

    def scan_file(self, file_path: Path, relative_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []

        # Check for tracked .env files
        file_name = file_path.name.lower()
        if file_name == ".env" or (file_name.startswith(".env.") and not file_name.endswith(".example")):
            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    rule_id="SEC-000",
                    title="Tracked Environment File (.env)",
                    category=FindingCategory.SECRETS,
                    severity=Severity.HIGH,
                    file_path=relative_path,
                    line_start=1,
                    line_end=1,
                    code_snippet=f"# File: {file_name}",
                    owasp_category="A07:2021-Identification and Authentication Failures",
                    cwe_id="CWE-798",
                    description=f"The environment file '{file_name}' appears to be tracked in version control, potentially leaking secrets.",
                    remediation="Add .env files to .gitignore and provide a template .env.example with dummy values instead.",
                    auto_fix_hint="Add .env to .gitignore and remove from repository history",
                )
            )

        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            if IgnoreMatcher.is_line_suppressed(line):
                continue

            for rule in self.RULES:
                rule_id = rule["id"]
                if IgnoreMatcher.is_line_suppressed(line, rule_id):
                    continue

                pattern: re.Pattern = rule["regex"]
                matches = pattern.finditer(line)
                for match in matches:
                    secret_candidate = match.group(1) if match.groups() else match.group(0)

                    # Check safe placeholders
                    candidate_lower = secret_candidate.lower()
                    if any(placeholder in candidate_lower for placeholder in self.SAFE_PLACEHOLDERS):
                        continue

                    # For generic high-entropy rule, verify entropy threshold
                    if rule_id == "SEC-006":
                        entropy = calculate_shannon_entropy(secret_candidate)
                        if entropy < 3.2:
                            continue

                    # Determine auto-fix hint based on language
                    auto_fix = rule.get("auto_fix")
                    if relative_path.endswith((".js", ".ts", ".jsx", ".tsx")):
                        if auto_fix and "os.environ.get" in auto_fix:
                            auto_fix = "process.env.API_KEY"

                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            rule_id=rule_id,
                            title=rule["title"],
                            category=FindingCategory.SECRETS,
                            severity=rule["severity"],
                            file_path=relative_path,
                            line_start=idx,
                            line_end=idx,
                            code_snippet=line.strip(),
                            owasp_category="A07:2021-Identification and Authentication Failures",
                            cwe_id="CWE-798",
                            description=rule["description"],
                            remediation=rule["remediation"],
                            auto_fix_hint=auto_fix,
                        )
                    )

        return findings
