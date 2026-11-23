from __future__ import annotations

import math
import re
import uuid
from collections import Counter
from pathlib import Path
from typing import List, Optional, Set, Tuple

from secureship.models import Confidence, Finding, FindingCategory, Severity
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
        "todo", "replace_me", "none", "null", "undefined", "<secret>",
        "mock", "fixture", "mysecretkey",
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
            "confidence": Confidence.HIGH,
        },
        {
            "id": "SEC-002",
            "title": "Hardcoded GitHub Personal Access Token",
            "regex": re.compile(r"(gh[pousr]_[A-Za-z0-9_]{36,255})"),
            "severity": Severity.CRITICAL,
            "description": "Hardcoded GitHub personal access token detected. This could grant write or admin access to repositories.",
            "remediation": "Revoke the token immediately and inject it at runtime using GitHub Actions secrets or environment variables.",
            "auto_fix": "os.environ.get('GITHUB_TOKEN')",
            "confidence": Confidence.HIGH,
        },
        {
            "id": "SEC-003",
            "title": "Hardcoded Private RSA/SSH/PGP Key",
            "regex": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
            "severity": Severity.CRITICAL,
            "description": "Asymmetric private cryptographic key found committed directly in code.",
            "remediation": "Remove the private key from the repository, rotate the key pair, and load keys from a secure vault or file outside the repo.",
            "auto_fix": "Load private key from secret vault or secure filesystem path.",
            "confidence": Confidence.HIGH,
        },
        {
            "id": "SEC-004",
            "title": "Database Connection String with Embedded Password",
            "regex": re.compile(r"(?:postgres|postgresql|mysql|mongodb|redis|mssql):\/\/[^\s:]+:([^\s@]+)@[^\s\/]+", re.IGNORECASE),
            "severity": Severity.HIGH,
            "description": "Database connection URI contains an embedded plain-text password.",
            "remediation": "Extract the database password or the entire connection URI into an environment variable (DATABASE_URL).",
            "auto_fix": "os.environ.get('DATABASE_URL')",
            "confidence": Confidence.HIGH,
        },
        {
            "id": "SEC-005",
            "title": "Exposed Hardcoded JWT Token",
            "regex": re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
            "severity": Severity.HIGH,
            "description": "Hardcoded JSON Web Token (JWT) detected. May expose session tokens or sensitive claims.",
            "remediation": "Generate tokens dynamically at runtime and do not hardcode authorization tokens.",
            "auto_fix": "Generate dynamically at runtime",
            "confidence": Confidence.HIGH,
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
            "confidence": Confidence.MEDIUM,
        },
        {
            "id": "SEC-007",
            "title": "Hardcoded AI Platform API Key (OpenAI / Anthropic / HuggingFace)",
            "regex": re.compile(r"(?:sk-(?:proj-)?[a-zA-Z0-9_\-]{20,}|sk-ant-[a-zA-Z0-9_\-]{20,}|hf_[a-zA-Z0-9]{20,})"),
            "severity": Severity.CRITICAL,
            "description": "Hardcoded OpenAI, Anthropic Claude, or Hugging Face API key detected. Enables unauthorized LLM consumption and data exfiltration.",
            "remediation": "Store AI platform API keys in environment variables (OPENAI_API_KEY, ANTHROPIC_API_KEY) or cloud KMS.",
            "auto_fix": "os.environ.get('OPENAI_API_KEY')",
            "confidence": Confidence.HIGH,
        },
        {
            "id": "SEC-008",
            "title": "Exposed Slack Incoming Webhook URL",
            "regex": re.compile(r"https:\/\/hooks\.slack\.com\/services\/T[0-9A-Za-z]{8,}\/B[0-9A-Za-z]{8,}\/[0-9a-zA-Z]{24}"),
            "severity": Severity.HIGH,
            "description": "Hardcoded Slack webhook URL exposed. Attackers can spam internal channels or execute social engineering / phishing campaigns.",
            "remediation": "Store webhook URLs in encrypted environment secrets.",
            "auto_fix": "os.environ.get('SLACK_WEBHOOK_URL')",
            "confidence": Confidence.HIGH,
        },
        {
            "id": "SEC-009",
            "title": "Hardcoded Stripe Secret / Restricted Key",
            "regex": re.compile(r"(?:sk|rk)_live_[0-9a-zA-Z]{24,}"),
            "severity": Severity.CRITICAL,
            "description": "Live production Stripe secret key detected. Allows unauthorized charge generation, balance exfiltration, and customer data access.",
            "remediation": "Rotate this key immediately in the Stripe Dashboard and load keys via STRIPE_SECRET_KEY env var.",
            "auto_fix": "os.environ.get('STRIPE_SECRET_KEY')",
            "confidence": Confidence.HIGH,
        },
        {
            "id": "SEC-010",
            "title": "Hardcoded Google Cloud / Firebase API Key",
            "regex": re.compile(r"AIza[0-9A-Za-z\-_]{30,40}"),
            "severity": Severity.HIGH,
            "description": "Google Cloud / Firebase API key detected. If unconstrained, attackers can invoke GCP billable APIs using your project quota.",
            "remediation": "Apply HTTP referrer and API service restrictions in Google Cloud Console, or inject at runtime.",
            "auto_fix": "os.environ.get('GCP_API_KEY')",
            "confidence": Confidence.HIGH,
        },
        {
            "id": "SEC-011",
            "title": "Hardcoded Plaintext Password Assignment",
            "regex": re.compile(r"""(?i)(?:password|passwd|db_pass|db_password)\s*[:=]\s*["']([^"'\s]{6,})["']"""),
            "severity": Severity.HIGH,
            "description": "Hardcoded plain-text password detected in variable assignment.",
            "remediation": "Move passwords out of source code into secure secrets storage or environment variables.",
            "auto_fix": "os.environ.get('PASSWORD')",
            "confidence": Confidence.MEDIUM,
        },
        {
            "id": "SEC-012",
            "title": "Hardcoded Slack Bot OAuth Token",
            "regex": re.compile(r"(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,})"),
            "severity": Severity.CRITICAL,
            "description": "Hardcoded Slack Bot token detected. Grants unauthorized read/write access to Slack workspace channels and direct messages.",
            "remediation": "Revoke the token in Slack App Management and inject via SLACK_BOT_TOKEN env variable.",
            "auto_fix": "os.environ.get('SLACK_BOT_TOKEN')",
            "confidence": Confidence.HIGH,
        },
        {
            "id": "SEC-013",
            "title": "Hardcoded Slack User OAuth Token",
            "regex": re.compile(r"(xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,})"),
            "severity": Severity.CRITICAL,
            "description": "Hardcoded Slack User token detected. Enables impersonating real team members across internal communications.",
            "remediation": "Revoke the user token immediately.",
            "auto_fix": "os.environ.get('SLACK_USER_TOKEN')",
            "confidence": Confidence.HIGH,
        },
        {
            "id": "SEC-014",
            "title": "Hardcoded Twilio Account Credentials",
            "regex": re.compile(r"(AC[a-zA-Z0-9]{32}|SK[a-zA-Z0-9]{32})"),
            "severity": Severity.HIGH,
            "description": "Hardcoded Twilio Account SID or API Key detected. Allows sending unapproved SMS and initiating unauthorized VoIP calls.",
            "remediation": "Store TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN in environment variables.",
            "auto_fix": "os.environ.get('TWILIO_AUTH_TOKEN')",
            "confidence": Confidence.HIGH,
        },
        {
            "id": "SEC-015",
            "title": "Hardcoded SendGrid API Key",
            "regex": re.compile(r"(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})"),
            "severity": Severity.CRITICAL,
            "description": "Hardcoded SendGrid API Key detected. Allows sending mass phishing emails from your verified domain.",
            "remediation": "Revoke and rotate the SendGrid API key, and configure SENDGRID_API_KEY environment variable.",
            "auto_fix": "os.environ.get('SENDGRID_API_KEY')",
            "confidence": Confidence.HIGH,
        },
        {
            "id": "SEC-016",
            "title": "Hardcoded Mailgun Private API Key",
            "regex": re.compile(r"(key-[0-9a-zA-Z]{32})"),
            "severity": Severity.HIGH,
            "description": "Hardcoded Mailgun API Key detected. Compromises email routing and transactional deliverability.",
            "remediation": "Rotate Mailgun key and inject via environment variables.",
            "auto_fix": "os.environ.get('MAILGUN_API_KEY')",
            "confidence": Confidence.HIGH,
        },
        {
            "id": "SEC-017",
            "title": "Hardcoded Postman API Key",
            "regex": re.compile(r"(PMAK-[a-zA-Z0-9]{24}-[a-zA-Z0-9]{34})"),
            "severity": Severity.HIGH,
            "description": "Hardcoded Postman API access key detected. Exposes API schemas, mock servers, and environment credentials.",
            "remediation": "Revoke key in Postman account settings.",
            "auto_fix": "os.environ.get('POSTMAN_API_KEY')",
            "confidence": Confidence.HIGH,
        },
        {
            "id": "SEC-018",
            "title": "Hardcoded Discord Bot Token",
            "regex": re.compile(r"([MN][A-Za-z0-9]{23,26}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})"),
            "severity": Severity.HIGH,
            "description": "Discord Bot token detected. Allows unauthorized bot control and server member access.",
            "remediation": "Regenerate token in Discord Developer Portal.",
            "auto_fix": "os.environ.get('DISCORD_BOT_TOKEN')",
            "confidence": Confidence.HIGH,
        },
        {
            "id": "SEC-019",
            "title": "Hardcoded Telegram Bot Token",
            "regex": re.compile(r"([0-9]{9,10}:[a-zA-Z0-9_-]{35})"),
            "severity": Severity.HIGH,
            "description": "Telegram Bot token detected. Allows attackers to read bot messages and send unauthorized broadcasts.",
            "remediation": "Revoke bot token with BotFather and store in environment variables.",
            "auto_fix": "os.environ.get('TELEGRAM_BOT_TOKEN')",
            "confidence": Confidence.HIGH,
        },
        {
            "id": "SEC-020",
            "title": "Azure Storage Account Connection String with Key",
            "regex": re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=([a-zA-Z0-9+/=]{80,})"),
            "severity": Severity.CRITICAL,
            "description": "Azure Storage Account connection string containing master account key detected.",
            "remediation": "Switch to Azure Managed Identities or rotate Storage Account access keys.",
            "auto_fix": "os.environ.get('AZURE_STORAGE_CONNECTION_STRING')",
            "confidence": Confidence.HIGH,
        },
        {
            "id": "SEC-021",
            "title": "Hardcoded Stripe Webhook Signing Secret",
            "regex": re.compile(r"(whsec_[0-9a-zA-Z]{32,})"),
            "severity": Severity.HIGH,
            "description": "Stripe webhook endpoint signing secret detected. Attackers can forge signed payment event webhooks.",
            "remediation": "Move webhook secret to STRIPE_WEBHOOK_SECRET environment variable.",
            "auto_fix": "os.environ.get('STRIPE_WEBHOOK_SECRET')",
            "confidence": Confidence.HIGH,
        },
        {
            "id": "SEC-022",
            "title": "MongoDB Cloud Cluster URI with Credentials",
            "regex": re.compile(r"mongodb\+srv:\/\/[^\s:]+:([^\s@]+)@[^\s\/]+"),
            "severity": Severity.HIGH,
            "description": "MongoDB Atlas connection URI with embedded user credentials detected.",
            "remediation": "Store MongoDB URI in MONGODB_URI environment variable.",
            "auto_fix": "os.environ.get('MONGODB_URI')",
            "confidence": Confidence.HIGH,
        },
        {
            "id": "SEC-023",
            "title": "Redis Connection URI with Embedded Authentication",
            "regex": re.compile(r"redis:\/\/(?::([^\s@]+)@)[^\s\/]+"),
            "severity": Severity.HIGH,
            "description": "Redis connection URI containing plain-text authentication token.",
            "remediation": "Store REDIS_URL in environment variables and enforce TLS.",
            "auto_fix": "os.environ.get('REDIS_URL')",
            "confidence": Confidence.HIGH,
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

        is_test_file = any(part in relative_path.lower() for part in ("/test", "/tests", "test_", "_test.", ".spec.", ".test.", "/fixtures/", "/mocks/"))

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
                    if rule_id == "SEC-011":
                        if candidate_lower in ("placeholder", "changeme", "example", "xxxx", "test", "dummy", "fake", "none", "null", "undefined", "<password>"):
                            continue
                    else:
                        if any(placeholder in candidate_lower for placeholder in self.SAFE_PLACEHOLDERS):
                            continue

                    # High accuracy: ignore UUIDs and git/checksum hashes
                    if re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", secret_candidate):
                        continue
                    if re.match(r"^[0-9a-f]{32,64}$", secret_candidate) and any(h in line.lower() for h in ("commit", "sha", "hash", "md5", "etag")):
                        continue

                    conf = rule.get("confidence", Confidence.HIGH)

                    # For generic high-entropy rule, verify entropy threshold
                    if rule_id == "SEC-006":
                        entropy = calculate_shannon_entropy(secret_candidate)
                        if entropy < 3.2:
                            continue
                        conf = Confidence.HIGH if entropy >= 4.0 else Confidence.MEDIUM

                    if is_test_file:
                        conf = Confidence.LOW

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
                            confidence=conf,
                        )
                    )

        return findings
