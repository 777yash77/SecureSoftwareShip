# 🛡️ SecureShip — Shift-Left DevSecOps Security Platform

> **Developer-First Shift-Left Security Platform:** Real-time VS Code diagnostics, automated Git pre-commit and pre-push gates, standalone CI/CD CLI, and an interactive cybersecurity dashboard powered by a high-performance Python 3.10+ multi-threaded engine.

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-50%2F50%20passed-brightgreen.svg)]()
[![Code Format](https://img.shields.io/badge/SARIF-v2.1.0%20OASIS-orange.svg)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)]()

---

## 📑 Table of Contents
- [Why SecureShip?](#-why-secureship)
- [System Architecture](#-system-architecture)
- [Installation & Quick Start](#-installation--quick-start)
  - [1. Quick Portable Installation (Release Package)](#1-quick-portable-installation-release-package)
  - [2. Manual Environment Variables (PATH) Setup](#2-manual-environment-variables-path-setup)
  - [3. Installing the VS Code Extension](#3-installing-the-vs-code-extension)
  - [4. Developer Setup (From Source Repository)](#4-developer-setup-from-source-repository)
- [Core Engine Mechanics & How It Works](#-core-engine-mechanics--how-it-works)
  - [Recursive Tree Traversal & Parallel Worker Pool](#recursive-tree-traversal--parallel-worker-pool)
  - [AST-Level SQL Injection Detection & Remediation](#ast-level-sql-injection-detection--remediation)
  - [4-Tier Security Inspection Domains (35+ Rules)](#4-tier-security-inspection-domains-35-rules)
  - [High-Accuracy Confidence & False-Positive Elimination](#high-accuracy-confidence--false-positive-elimination)
  - [Objective Security Scoring (0–100) & Gate Verdicts](#objective-security-scoring-0100--gate-verdicts)
  - [Custom Quality Gates & Strict Zero-Tolerance Policies](#custom-quality-gates--strict-zero-tolerance-policies)
  - [Automated Shift-Left Git Pre-Commit & Pre-Push Gates](#automated-shift-left-git-pre-commit--pre-push-gates)
  - [Audited Emergency Production Bypass](#audited-emergency-production-bypass)
  - [Persistent SQLite Scan History](#persistent-sqlite-scan-history)
  - [Exploit Intelligence & Patch Guidance Engine](#exploit-intelligence--patch-guidance-engine)
  - [Multi-Format Reporting & Executive Ship Certificates](#multi-format-reporting--executive-ship-certificates)
  - [Seamless Self-Updating from GitHub](#seamless-self-updating-from-github)
- [CLI Reference Manual](#-cli-reference-manual)
- [VS Code IDE Integration](#-vs-code-ide-integration)
- [Interactive Cybersecurity Dashboard](#-interactive-cybersecurity-dashboard)
- [Vulnerability Verification Matrix](#-vulnerability-verification-matrix)
- [Testing & Quality Assurance](#-testing--quality-assurance)
- [License](#-license)

---

## 💡 Why SecureShip?

Modern engineering velocity demands that security checks happen *before* code leaves developer machines. Traditional scanners are slow, cloud-dependent, noisy with false positives, and detached from the day-to-day coding workflow.

We engineered **SecureShip** as an offline-capable, developer-centric DevSecOps gate that:
- **Recursively analyzes whole codebases**: Walks every directory, nested subfolder, and file down the full folder tree in sub-second times.
- **Understands real code syntax via AST**: Evaluates Python Abstract Syntax Trees and JavaScript syntax structures to identify real vulnerabilities (like SQL injection, command injection, and deserialization) while ignoring harmless static string literals.
- **Blocks bad code at the Git gate**: Integrates seamlessly with `git commit` and `git push`, halting high-risk commits before they reach remote repositories.
- **Protects credentials with Shannon entropy**: Detects leaked API keys, database connection strings, and cloud tokens with high mathematical accuracy.
- **Provides instant copy-paste patches**: Explains the exact exploitation scenario and delivers defensive remediation code on demand.

---

## 🏛️ System Architecture

SecureShip operates around a unified Python core engine that serves as the single source of truth for the terminal CLI, Git hooks, VS Code extension, and Web Dashboard.

```mermaid
flowchart TD
    subgraph Interfaces ["Developer Interfaces"]
        IDE["VS Code Extension\n(Real-time Diagnostics & Quick Fixes)"]
        GIT["Git Shift-Left Gates\n(pre-commit & pre-push hooks)"]
        CLI["Terminal CLI\n(secureship scan, config, update)"]
        DASH["Web Dashboard\n(React 18 + Vite + Tailwind CSS)"]
    end

    subgraph ServiceLayer ["Service Layer"]
        API["FastAPI REST Service\n(http://127.0.0.1:8787)"]
    end

    subgraph CoreEngine ["SecureShip Core Engine (Python 3.10+)"]
        ORCH["Parallel Orchestrator\n(ThreadPoolExecutor)"]
        SCORER["Scoring & Quality Gate Algorithm\n(0–100 Score | READY / REVIEW / BLOCKED)"]
        CONF["Confidence & False-Positive Filter\n(High / Medium / Low)"]
        SQLITE[("SQLite Audit Store\n(~/.secureship/history.db)")]
        ADVISOR["Exploit Intelligence Engine\n(Adversary Scenarios & Patches)"]

        subgraph ModularScanners ["4 Security Inspection Domains (35+ Rules)"]
            S1["Secrets & Tokens\n(Shannon Entropy + Pattern Matchers)"]
            S2["SAST Code Analysis\n(Python AST + JS/Node AST)"]
            S3["Dependency / SCA\n(OSV.dev Batch API + Offline CVE DB)"]
            S4["Container & IaC\n(Dockerfile, Compose, Kubernetes)"]
        end
    end

    IDE -->|"HTTP /api/scan/content"| API
    DASH -->|"HTTP /api/scans & /api/history"| API
    GIT -->|"CLI Execution"| CLI
    CLI -->|"Direct Internal Call"| ORCH
    API -->|"Direct Internal Call"| ORCH

    ORCH --> S1
    ORCH --> S2
    ORCH --> S3
    ORCH --> S4

    ModularScanners --> CONF
    CONF --> SCORER
    SCORER --> SQLITE
    SCORER --> ADVISOR
    SCORER -->|"ScanResult & Metrics"| ORCH
```

---

## 📦 Installation & Quick Start

### 1. Quick Portable Installation (Release Package)

We package SecureShip as a standalone portable release archive: `SecureShip-v1.0.0-release.zip`. The code is pre-compiled into optimized Python bytecode (`.pyc`) with raw `.py` sources omitted to protect intellectual property.

1. Download and extract `SecureShip-v1.0.0-release.zip` into any directory on your computer (e.g. `C:\SecureShip`).
2. Run our automated setup script:
   - **Windows Command Prompt:** Double-click `install.bat`.
   - **PowerShell:** Right-click `setup.ps1` $\rightarrow$ **Run with PowerShell** (or run `powershell -ExecutionPolicy Bypass -File .\setup.ps1`).
3. Open a **new** terminal window and verify:
   ```bash
   secureship --help
   secureship version
   ```

#### What `install.bat` Does Under the Hood:
- Automatically detects Python installations in your system `PATH`, `%USERPROFILE%\Python311`, `%LOCALAPPDATA%`, or the Windows Python Launcher (`py.exe`).
- Installs necessary engine runtime dependencies (`typer`, `rich`, `pydantic`, `fastapi`, `uvicorn`, `httpx`, `pyyaml`).
- Registers `bin\` and the Python Scripts directory into your **Windows User Environment Variables (`PATH`)** so `secureship` is instantly available anywhere.

---

### 2. Manual Environment Variables (PATH) Setup

If you prefer to configure your environment variables manually:
1. Extract the release folder to your preferred destination (e.g. `C:\SecureShip`).
2. Press <kbd>Win</kbd> + <kbd>R</kbd>, type `sysdm.cpl`, and hit <kbd>Enter</kbd>.
3. In **System Properties**, open the **Advanced** tab and click **Environment Variables...**.
4. In **User variables**, select `Path` and click **Edit...**.
5. Click **New** and add the path to the `bin` directory:
   ```text
   C:\SecureShip\bin
   ```
6. Click **OK** on all open dialogs.
7. Open a new terminal and run `secureship --help`.

---

### 3. Installing the VS Code Extension

The release package includes the compiled extension package: `secureship-vscode-1.0.0.vsix`.

#### Via VS Code GUI:
1. Open **Visual Studio Code**.
2. Go to **Extensions** (<kbd>Ctrl</kbd> + <kbd>Shift</kbd> + <kbd>X</kbd>).
3. Click the **`...` (Views and More Actions)** button at the top-right corner of the Extensions pane.
4. Select **"Install from VSIX..."**.
5. Select `secureship-vscode-1.0.0.vsix` and click **Install**.

#### Via Terminal:
```bash
code --install-extension secureship-vscode-1.0.0.vsix
```

---

### 4. Developer Setup (From Source Repository)

To contribute or run from source:

```bash
# Clone the repository
git clone https://github.com/777yash77/SecureSoftwareShip.git
cd SecureSoftwareShip

# Install the Python engine in editable mode
cd engine
pip install -e .

# Launch Web Dashboard
cd ../dashboard
npm install
npm run dev

# Compile VS Code Extension
cd ../vscode-extension
npm install
npm run compile
```

---

## ⚙️ Core Engine Mechanics & How It Works

### Recursive Tree Traversal & Parallel Worker Pool
SecureShip does not limit inspection to the top-level folder. When scanning a project:
- Uses `os.walk()` to recursively discover all directories, subfolders, and source files across the entire file tree.
- Automatically respects `.gitignore` and `.secureshipignore` patterns, ignoring build artifacts, virtual environments (`.venv/`, `env/`), `node_modules/`, and Git metadata.
- Distributes files across a multi-threaded worker pool:
  $$\text{max\_workers} = \min(32, \max(4, \text{cpu\_count} \times 2))$$
- Performs binary inspection on initial byte headers to skip non-text assets (> 5MB or containing `\x00` null bytes), keeping scan times below a second even on extensive codebases.

---

### AST-Level SQL Injection Detection & Remediation

SQL Injection (`SAST-PY-001`, `SAST-JS-003`) is one of the most critical web vulnerabilities (CWE-89 / OWASP A03:2021). SecureShip detects it with high precision using compiler Abstract Syntax Tree analysis:

#### 1. Python AST Parser
Instead of relying on naive regular expressions that miss context, our scanner inspects Python AST nodes (`ast.Call`) invoking `execute()`:
- **f-strings (`ast.JoinedStr`)**:
  ```python
  # FLAGGED (Critical):
  cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
  ```
- **Modulo string formatting (`ast.BinOp` with `Mod`)**:
  ```python
  # FLAGGED (Critical):
  cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
  ```
- **`.format()` method calls (`ast.Call`)**:
  ```python
  # FLAGGED (Critical):
  cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))
  ```
- **Dynamic string concatenation (`ast.BinOp` with `Add`)**:
  ```python
  # FLAGGED (Critical):
  cursor.execute("SELECT * FROM users WHERE id = " + user_id)
  ```
- **AST Constant Propagation**: Static literals (e.g. `cursor.execute("SELECT 1")` or `cursor.execute("SELECT * FROM users WHERE role = 'admin'")`) are recognized as immutable constants and are **never** flagged, eliminating false positives.

#### 2. JavaScript / TypeScript Detection
Detects string concatenation and ES6 template literals inside database calls:
```javascript
// FLAGGED (Critical):
db.query(`SELECT * FROM users WHERE id = ${userId}`);
client.query("SELECT * FROM users WHERE id = " + userId);
```

#### 3. Automatic Remediation Guidance
Every finding reports the exact line number, code snippet, and parameterized replacement:
```python
# SecureShip Remediation:
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

---

### 4-Tier Security Inspection Domains (35+ Rules)

SecureShip audits code across 4 specialized security vectors:

#### Domain 1: Secrets & Credentials (`secrets_scanner.py`)
- **Shannon Entropy Analysis**:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
  Calculates character entropy to identify high-randomness tokens ($H > 3.2$).
- **Rules**:
  - `SEC-000`: Tracked `.env` files exposing production credentials.
  - `SEC-001`: AWS Access Key IDs (`AKIA[0-9A-Z]{16}`).
  - `SEC-002`: GitHub Personal Access Tokens (`ghp_[a-zA-Z0-9]{36}`).
  - `SEC-003`: Generic high-entropy secret tokens and API keys.
  - `SEC-004`: Plaintext RSA, OpenSSH, and EC Private Keys.
  - `SEC-005`: Database connection URIs containing credentials (`postgres://user:pass@host`).
  - `SEC-007`: AI Platform keys (OpenAI `sk-proj-`, Anthropic `sk-ant-`, HuggingFace `hf_`).
  - `SEC-008`: Exposed Slack Incoming Webhook URLs.
  - `SEC-009`: Stripe live secret keys (`sk_live_[0-9a-zA-Z]{24,}`).
  - `SEC-010`: Google Cloud & Firebase API keys (`AIza[0-9A-Za-z\\-_]{35}`).
  - `SEC-011`: Plaintext hardcoded passwords in variable assignments.

#### Domain 2: Static Application Security Testing — SAST (`sast_scanner.py`)
- **Python**:
  - `SAST-PY-001`: SQL Injection via dynamic formatting in `execute()`.
  - `SAST-PY-002`: Command Injection via `os.system()` with dynamic input.
  - `SAST-PY-003`: Command Injection via `subprocess` with `shell=True`.
  - `SAST-PY-004`: Insecure Deserialization via `pickle.loads()`.
  - `SAST-PY-005`: Insecure YAML deserialization via `yaml.load()` without SafeLoader.
  - `SAST-PY-006`: Dynamic arbitrary code execution via `eval()` or `exec()`.
  - `SAST-PY-007`: Broken cryptographic hashes (`hashlib.md5`, `hashlib.sha1`).
  - `SAST-PY-008`: Production debug mode enabled (`DEBUG = True`).
  - `SAST-PY-009`: Service bound to all interfaces (`0.0.0.0`).
  - `SAST-PY-010`: Server-Side Request Forgery (SSRF) via dynamic `requests`/`httpx` URLs.
  - `SAST-PY-011`: Path Traversal / Arbitrary File Read in `open()` or `send_file()`.
  - `SAST-PY-012`: Insecure Deserialization via `marshal` or `shelve`.
  - `SAST-PY-014`: Insecure XML parsing vulnerable to XML External Entity (XXE).
- **JavaScript & Node.js**:
  - `SAST-JS-001`: Code execution via `eval()`.
  - `SAST-JS-002`: Cross-Site Scripting (XSS) in `innerHTML` or `dangerouslySetInnerHTML`.
  - `SAST-JS-003`: SQL Injection via string concatenation in `query()`.
  - `SAST-JS-004`: Command Injection via `child_process.exec()`.
  - `SAST-JS-005`: Disabled TLS verification (`rejectUnauthorized: false`).
  - `SAST-JS-006`: Hardcoded JWT secret key in `jwt.sign()`.
  - `SAST-JS-007`: Server-Side Request Forgery (SSRF) via dynamic `axios`/`fetch` URLs.
  - `SAST-JS-008`: Path Traversal / Arbitrary File Read in `fs.readFile()`.
  - `SAST-JS-009`: Prototype Pollution via unconstrained `Object.assign` or deep merge.
  - `SAST-JS-010`: Permissive Wildcard CORS configuration (`origin: '*'`).
  - `SAST-JS-011`: Insecure Cookies missing `httpOnly` or `secure` flags.

#### Domain 3: Dependency / Software Composition Analysis — SCA (`sca_scanner.py`)
- Analyzes `package.json`, `requirements.txt`, and `pom.xml`.
- Queries the **OSV.dev batch API** and includes a **built-in offline CVE database** covering critical CVEs:
  - `CVE-2021-44228`: Log4Shell RCE in `log4j-core < 2.15.0`.
  - `CVE-2022-22965`: Spring4Shell RCE in `spring-beans < 5.3.18`.
  - `CVE-2020-8203`: Lodash Prototype Pollution in `lodash < 4.17.21`.
  - `CVE-2022-23529`: RCE in `jsonwebtoken < 9.0.0`.
  - `CVE-2024-34064`: HTML Attribute Injection in `jinja2 < 3.1.4`.
  - `CVE-2024-34069`: Predictable Debugger PIN in `werkzeug < 3.0.3`.
  - `CVE-2023-50447`: Arbitrary Code Execution in `pillow < 10.0.1`.
  - `CVE-2023-38325`: Timing attack in `cryptography < 41.0.2`.
  - `CVE-2023-48795`: Terrapin SSH attack in `paramiko < 3.4.0`.

#### Domain 4: Container & IaC Security (`iac_scanner.py`)
- **Dockerfile**: Checks for execution as `root` (missing `USER`), unpinned base image tags (`:latest`), embedded secrets in `ENV`/`ARG`, dangerous `ADD` instructions, and insecure `curl ... | sh` commands.
- **Docker Compose**: Identifies `privileged: true` containers, open database ports (`5432`, `3306`, `6379`) bound to `0.0.0.0`, `/var/run/docker.sock` socket mounts, and `host` network mode.
- **Kubernetes Manifests**: Detects missing CPU/Memory limits, privileged `securityContext`, `allowPrivilegeEscalation: true`, and writable root filesystems.

---

### High-Accuracy Confidence & False-Positive Elimination

Every finding is tagged with an accuracy rating:
- **`HIGH`**: Definitive pattern match (e.g. AWS key prefix, unpinned Docker tag, AST f-string in SQL).
- **`MEDIUM`**: Heuristic pattern match (e.g. high-entropy unknown token).
- **`LOW`**: Informational warning.

#### Built-in False-Positive Filters
- Automatically filters out GUIDs (`12345678-1234-1234-1234-123456789abc`) and SHA-256 digests.
- Ignores documentation placeholders (`example.com`, `placeholder`, `changeme`, `dummy_key`).
- Use the high-accuracy filter for zero-noise audits:
  ```bash
  secureship scan --confidence high
  ```

---

### Objective Security Scoring (0–100) & Gate Verdicts

The Security Score starts at **100 points** and subtracts weighted penalties based on findings:

$$\text{Security Score} = \max\left(0, 100 - \sum \text{Penalties}\right)$$

| Severity | Weight | Deduction per Finding |
| :--- | :---: | :---: |
| **CRITICAL** | 4 | **-25 points** |
| **HIGH** | 3 | **-15 points** |
| **MEDIUM** | 2 | **-5 points** |
| **LOW** | 1 | **-2 points** |

#### Ship-Readiness Verdicts
- <span style="color:#10b981;font-weight:bold;">READY TO SHIP</span>: Score $\ge \text{threshold}$ (default: 80) **AND** 0 Critical issues.
- <span style="color:#f59e0b;font-weight:bold;">NEEDS REVIEW</span>: Score between 50 and 79 **AND** 0 Critical issues.
- <span style="color:#ef4444;font-weight:bold;">BLOCKED</span>: Score $< 50$ **OR** $\ge 1$ Critical issue detected.

---

### Custom Quality Gates & Strict Zero-Tolerance Policies

#### Adjusting Passing Thresholds (`--modify-score`)
Customize the required gate score to match project milestones:
```bash
# Allow any score >= 65% to pass
secureship scan --modify-score 65

# Supports percentages with '%' symbol
secureship scan --modify-score 70%
```

#### Enforcing Strict Category Blockers
Block releases if a specific category has even a single finding, regardless of the overall score:
```bash
# Block push if ANY dependency vulnerability exists (even with a 99/100 score)
secureship scan --strict-sca

# Block push if ANY Docker/K8s misconfiguration exists
secureship scan --strict-iac

# Block push if ANY hardcoded secret exists
secureship scan --strict-sec

# Block push if ANY SAST code vulnerability exists
secureship scan --strict-sast
```

#### Persisting Repository Policy (`.secureshiprc`)
Save settings into `.secureshiprc` so every developer and CI runner follows the same rules:
```bash
secureship config --min-score 70 --strict-sca --min-confidence high
secureship config --show
```

---

### Automated Shift-Left Git Pre-Commit & Pre-Push Gates

Install native Git security gates with one command:
```bash
secureship install-hook
```

#### 1. Pre-Commit Hook (`.git/hooks/pre-commit`)
- Triggers automatically when running `git commit`.
- Scans only staged lines (`--staged`). If secrets or critical flaws are detected in staged files, the commit is rejected immediately.

#### 2. Pre-Push Hook (`.git/hooks/pre-push`)
- Triggers automatically when running `git push`.
- Audits the entire codebase against repository gate policies. If the verdict is **BLOCKED** or strict category violations exist, the push to remote is blocked.

#### 3. Automatic .gitignore Secret Immunization (Secret Shield)
- Before pushing or committing, SecureShip automatically scans your repository and ensures `.env`, database files, certificates, private keys, and cloud credentials are added to `.gitignore`.
- If a sensitive credential file was accidentally staged in Git (`git add .env`), SecureShip automatically and safely un-stages it (`git rm --cached`) so secrets are never pushed to GitHub or remote repositories!

Manual immunization command:
```bash
# Auto-protect repository .gitignore from secret leaks
secureship protect .
```

Protected pattern categories:
- **Environment files**: `.env`, `.env.*`, `*.env`, `.env.local`, `.env.production`
- **Database & Data stores**: `*.db`, `*.sqlite`, `*.sqlite3`, `secureship.db`
- **Cloud & API Credentials**: `credentials.json`, `service-account*.json`, `client_secret*.json`, `.aws/`
- **Private Keys & Certificates**: `*.pem`, `*.key`, `*.pfx`, `*.pkcs12`, `id_rsa`, `id_ed25519`
- **Audit tokens & caches**: `*.token`, `.secureship/`, `.secureshiprc`

---

### Audited Emergency Production Bypass

When a critical production hotfix must be deployed immediately:
```bash
secureship bypass --push --reason "Hotfix for production database outage #104"
```
SecureShip records the developer username, timestamp, and audit justification in `.git/secureship-bypass.token`, allows the push, and immediately invalidates the token.

---

### Persistent SQLite Scan History

Every scan records its metrics in a local SQLite database (`~/.secureship/history.db`).
- Tracks timestamps, target paths, scores, findings counts, and gate verdicts.
- Wrapped in safe database transactions so SQLite issues never break scans.
- Query scan trajectories anytime:
  ```bash
  secureship history --limit 5
  ```

---

### Exploit Intelligence & Patch Guidance Engine

Run `secureship explain <RULE_ID>` to inspect any rule:
```bash
secureship explain SAST-PY-001
secureship explain SEC-007
secureship explain IAC-DOCKER-001
```
Renders 3 structured analysis panels:
1. **Vulnerability Analysis**: Root cause, CWE ID, and OWASP category.
2. **Adversary Exploitation Scenario**: Real-world demonstration of how attackers exploit the vulnerability.
3. **Remediation Strategy & Defensive Patch**: Copy-paste, syntax-highlighted code patches.

---

### 🔧 Automated Auto-Remediation Engine (`secureship fix`)

SecureShip can automatically and safely remediate detected code flaws and IaC misconfigurations without breaking application architecture:

```bash
# Preview remediation diffs without touching source files (Dry Run)
secureship fix ./my-project --dry-run

# Apply safe code and container fixes in-place
secureship fix ./my-project --apply

# Remediate specific vulnerability rules only
secureship fix ./my-project --apply --rule IAC-DOCKER-001 --rule SAST-PY-006
```

#### Supported Auto-Fixes:
- **Dockerfiles**: Automatically pins unpinned `:latest` base images to `:pinned-stable`, injects non-root `USER nonroot` before container entrypoints, and swaps unvalidated `ADD` for `COPY`.
- **Docker Compose & K8s**: Automatically flips `privileged: true` to `privileged: false`, disables container `hostNetwork`, and restricts security contexts.
- **Python SAST**: Upgrades weak `hashlib.md5`/`sha1` to `hashlib.sha256`, replaces `tempfile.mktemp()` with `tempfile.NamedTemporaryFile()`, turns off Flask debug mode (`debug=False`), and binds wildcards (`0.0.0.0` $\rightarrow$ `127.0.0.1`).
- **JavaScript**: Removes wildcard CORS policies (`origin: '*'`).

---

### 📦 Software Bill of Materials (SBOM) Generation (`secureship sbom`)

Comply with executive cybersecurity mandates (US Executive Order 14028, NIST SSDF) by generating standardized machine-readable SBOMs:

```bash
# Generate CycloneDX v1.5 JSON (OWASP & Enterprise standard)
secureship sbom ./my-project --format cyclonedx -o sbom-cyclonedx.json

# Generate SPDX v2.3 JSON (Linux Foundation standard)
secureship sbom ./my-project --format spdx -o sbom-spdx.json
```
- Discovers dependencies across Python (`requirements.txt`), Node.js (`package.json`), Maven (`pom.xml`), and Go (`go.mod`).
- Assigns canonical Package URLs (`purl`), version pins, and ecosystem metadata to every component.

---

### 🛡️ Regulatory & Compliance Benchmarking (`secureship compliance`)

Evaluate codebases against international regulatory security frameworks with executive scoring (0–100%):

```bash
# Audit against OWASP Top 10 (2021)
secureship compliance ./my-project --standard owasp

# Audit against Payment Card Industry (PCI-DSS v4.0)
secureship compliance ./my-project --standard pci-dss

# Audit against SOC 2 Type II Trust Services Criteria
secureship compliance ./my-project --standard soc2

# Audit against NIST SP 800-218 Secure Software Development Framework (SSDF)
secureship compliance ./my-project --standard nist
```

---

### 🚀 Shift-Left CI/CD Pipeline Generator (`secureship init-ci`)

Set up automated shift-left security enforcement in your repository's CI/CD pipeline in seconds:

```bash
# Generate GitHub Actions workflow (.github/workflows/secureship.yml)
secureship init-ci --platform github

# Generate GitLab CI DevSecOps stage (.gitlab-ci.yml)
secureship init-ci --platform gitlab

# Generate Azure DevOps pipeline (azure-pipelines.yml)
secureship init-ci --platform azure

# Generate all supported CI templates at once
secureship init-ci --all
```

---

### Multi-Format Reporting & Executive Ship Certificates

Export findings in formats suited for developers, CI/CD pipelines, and leadership:
```bash
# Terminal Rich Table (default)
secureship scan .

# Standalone Print-Ready HTML Report
secureship scan . --format html -o report.html

# OASIS SARIF v2.1.0 (for GitHub Security tab & CI/CD)
secureship scan . --format sarif -o report.sarif

# Machine-Readable JSON
secureship scan . --format json -o report.json

# Executive Ship Readiness Audit Certificate
secureship certificate ./my-app -o Ship-Certificate.html
```

---

### Seamless Self-Updating from GitHub

SecureShip updates itself directly from the official repository:
```bash
# Check if updates are available
secureship update --check

# Apply latest update
secureship update

# Update from a private GitHub repository using a Personal Access Token (PAT)
secureship update --token ghp_YourGitHubTokenHere

# Or save the token permanently into .secureshiprc:
secureship config --github-token ghp_YourGitHubTokenHere
```

---

## 💻 CLI Reference Manual

| Command / Option | Description & Practical Usage |
| :--- | :--- |
| `secureship scan` | Full scan of current folder across all categories |
| `secureship scan ./my-project` | Scan a specific project folder |
| `secureship scan --modify-score 65` | Override passing gate score to 65% (default: 80) |
| `secureship scan --strict-sca` | Block push if ANY dependency vulnerability is detected |
| `secureship scan --strict-iac` | Block push if ANY Docker/K8s misconfiguration is detected |
| `secureship scan --strict-sec` | Block push if ANY secret/token is detected |
| `secureship scan --strict-sast` | Block push if ANY SAST code vulnerability is detected |
| `secureship scan --confidence high` | Filter findings to high-accuracy zero-false-positive risks |
| `secureship scan --sec` | Scan **ONLY Secrets** |
| `secureship scan --iac` | Scan **ONLY Container & IaC** |
| `secureship scan --sast` | Scan **ONLY SAST code flaws** |
| `secureship scan --sca` | Scan **ONLY Dependencies** |
| `secureship scan --staged` | Scan only Git staged lines (pre-commit mode) |
| `secureship scan --fail-on high` | Exit code 1 if findings equal or exceed High severity |
| `secureship scan --format html -o report.html` | Export standalone HTML audit report |
| `secureship scan --format sarif -o report.sarif`| Export SARIF v2.1.0 for GitHub Security tab |
| `secureship config --min-score 70` | Persist custom 70% threshold into `.secureshiprc` |
| `secureship config --strict-sca` | Persist strict zero-tolerance SCA blocker |
| `secureship config --min-confidence high` | Persist high-accuracy gate in `.secureshiprc` |
| `secureship config --show` | Display current repository quality gate rules |
| `secureship rules` | List all 35+ built-in detection rules with CWE/OWASP IDs |
| `secureship rules --category SECRETS` | Filter rules catalog by category |
| `secureship explain <RULE_ID>` | View exploit scenario and defensive code patch |
| `secureship history` | Display persistent SQLite scan audit history and scores |
| `secureship certificate ./my-app` | Generate print-ready Executive Audit Certificate |
| `secureship install-hook` | Install automated Git pre-commit & pre-push gates |
| `secureship bypass --push` | Issue audited emergency bypass token and execute `git push` |
| `secureship update` | Fetch & install latest updates from GitHub |
| `secureship update --token <PAT>` | Fetch updates from private GitHub repository |
| `secureship serve --port 8787` | Launch Web Security Dashboard & REST API backend |
| `secureship version` | Display installed software version |

#### Direct Quick Options
Flags can be passed directly to `secureship` without typing `scan`:
```bash
secureship --modify-score 65
secureship --strict-sca
secureship --confidence high
secureship --update
secureship --version
```

---

## 🧩 VS Code IDE Integration

The VS Code extension provides in-editor security feedback as you code:

1. **Inline Squiggly Diagnostics**: Highlights vulnerable lines with severity colors (Critical in Red, High in Orange, Medium in Yellow, Low in Blue).
2. **Auto-Scan on Save**: Evaluates documents on save in under 50ms.
3. **Activity Bar View ("SecureShip Findings")**: Dedicated sidebar grouping findings by Severity and File. Click any finding to jump directly to the offending line.
4. **Status Bar Quality Gate**: Displays `$(shield) SecureShip: 85/100` with one-click access to full reports.
5. **Quick Fix Code Actions (<kbd>Ctrl</kbd> + <kbd>.</kbd>)**:
   - Replaces MD5 with SHA-256 (`SAST-PY-007`).
   - Extracts hardcoded secrets into `os.environ.get(...)` (`SEC-001`).
   - Inserts `USER appuser` into Dockerfiles (`IAC-DOCKER-001`).
   - Inserts inline suppression comments (`# secureship-ignore: <RULE_ID>`).

---

## 🌐 Interactive Cybersecurity Dashboard

Run:
```bash
secureship serve --port 8787
```
Open **`http://localhost:8787`** in your browser.
- **Live Score Gauge**: Circular visual indicator of repository ship status.
- **Interactive Threshold Slider**: Adjust passing gate % in real time.
- **Repository Auditing Modes**: Scan local paths, public GitHub repository URLs, or uploaded `.zip` files.
- **Interactive Findings Explorer**: Search, filter by category/severity/confidence, and view exploit analyses.
- **One-Click Exports**: Export HTML, JSON, SARIF, or Executive Certificates directly from the browser.

---

## 🧪 Vulnerability Verification Matrix

We verify our detection engine against the [demo-vulnerable-app/](file:///c:/Users/yaswanth/Downloads/SecureShip/demo-vulnerable-app) test fixture:

| Target File | Vulnerability Description | Rule ID | Severity | Confidence | Status |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `app.py` | Hardcoded AWS Access Key (`AKIA...`) | `SEC-001` | CRITICAL | HIGH | Detected |
| `app.py` | OpenAI API Secret Key (`sk-proj-...`) | `SEC-007` | CRITICAL | HIGH | Detected |
| `app.py` | Stripe Live Secret Key (`sk_live_...`) | `SEC-009` | CRITICAL | HIGH | Detected |
| `app.py` | SQL Injection in `execute(f"SELECT ...")` | `SAST-PY-001` | CRITICAL | HIGH | Detected |
| `app.py` | Command Injection in `os.system(...)` | `SAST-PY-002` | CRITICAL | HIGH | Detected |
| `app.py` | Command Injection in `subprocess(shell=True)`| `SAST-PY-003` | CRITICAL | HIGH | Detected |
| `app.py` | Insecure Deserialization in `pickle.loads` | `SAST-PY-004` | CRITICAL | HIGH | Detected |
| `app.py` | Arbitrary Code Execution in `eval()` | `SAST-PY-006` | CRITICAL | HIGH | Detected |
| `app.py` | Broken Hash Function (`hashlib.md5`) | `SAST-PY-007` | MEDIUM | HIGH | Detected |
| `app.py` | Flask `DEBUG = True` in Production | `SAST-PY-008` | HIGH | HIGH | Detected |
| `app.py` | Bound to All Network Interfaces (`0.0.0.0`) | `SAST-PY-009` | LOW | HIGH | Detected |
| `server.js` | Command Injection in `child_process.exec` | `SAST-JS-004` | CRITICAL | HIGH | Detected |
| `server.js` | Arbitrary Code Execution in `eval()` | `SAST-JS-001` | CRITICAL | HIGH | Detected |
| `server.js` | SQL Injection via String Concatenation | `SAST-JS-003` | CRITICAL | HIGH | Detected |
| `server.js` | Cross-Site Scripting (XSS) in `innerHTML` | `SAST-JS-002` | HIGH | HIGH | Detected |
| `server.js` | Disabled TLS (`rejectUnauthorized: false`)| `SAST-JS-005` | HIGH | HIGH | Detected |
| `server.js` | Hardcoded Secret in `jwt.sign(...)` | `SAST-JS-006` | HIGH | HIGH | Detected |
| `.env` | Tracked `.env` File with DB Password | `SEC-000` | HIGH | HIGH | Detected |
| `package.json` | Lodash Prototype Pollution (`CVE-2020-8203`) | `SCA-*` | HIGH | HIGH | Detected |
| `package.json` | Axios SSRF Vulnerability (`CVE-2020-28168`) | `SCA-*` | HIGH | HIGH | Detected |
| `requirements.txt` | Jinja2 HTML Injection (`CVE-2024-34064`) | `SCA-*` | HIGH | HIGH | Detected |
| `requirements.txt` | Werkzeug Debugger PIN Leak (`CVE-2024-34069`)| `SCA-*` | HIGH | HIGH | Detected |
| `requirements.txt` | Pillow Arbitrary Code Execution (`CVE-2023-50447`)| `SCA-*` | HIGH | HIGH | Detected |
| `pom.xml` | Log4Shell RCE (`CVE-2021-44228`) | `SCA-*` | CRITICAL | HIGH | Detected |
| `Dockerfile` | Container Running as Root (Missing `USER`)| `IAC-DOCKER-001`| HIGH | HIGH | Detected |
| `Dockerfile` | Unpinned Base Image (`FROM python:latest`)| `IAC-DOCKER-002`| MEDIUM | HIGH | Detected |
| `Dockerfile` | Dangerous `ADD` Instead of `COPY` | `IAC-DOCKER-004`| MEDIUM | HIGH | Detected |
| `docker-compose.yml` | Privileged Container Mode (`privileged: true`)| `IAC-COMPOSE-001`| CRITICAL | HIGH | Detected |
| `docker-compose.yml` | Sensitive Database Port (`5432`) Bound to 0.0.0.0 | `IAC-COMPOSE-002`| HIGH | HIGH | Detected |
| `k8s-pod.yaml` | Missing Pod Resource Limits (CPU/Memory) | `IAC-K8S-001` | MEDIUM | HIGH | Detected |

---

## 🛡️ Testing & Quality Assurance

Our test suite covers every scanner, confidence filter, quality gate, CLI command, and REST API endpoint:

```bash
pytest engine/tests -v
```

All **50 unit and integration tests pass** with zero errors:
```text
======================= 50 passed, 1 warning in 22.21s ========================
```

---

## 📄 License

SecureShip is open-source software licensed under the [MIT License](LICENSE).
