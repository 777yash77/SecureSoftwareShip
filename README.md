# 🛡️ SecureShip — Shift-Left DevSecOps Security Platform

> **Comprehensive Shift-Left Security Platform:** Real-time VS Code Extension, Standalone CI/CD Gate CLI, and Interactive Dark-Theme Web Dashboard powered by a high-performance Python 3.11+ Core Engine.

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-50%2F50%20passed-brightgreen.svg)]()
[![Code Format](https://img.shields.io/badge/SARIF-v2.1.0%20OASIS-orange.svg)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)]()

---

## 📑 Table of Contents
- [Architecture & Tech Stack](#-architecture--tech-stack)
- [How to Run on Any Computer (Including Another Person's Computer)](#-how-to-run-on-any-computer-including-another-persons-computer)
  - [Method 1: 1-Click Portable Release Package (Recommended)](#method-1-1-click-portable-release-package-recommended)
  - [How `install.bat` Works Behind the Scenes](#how-installbat-works-behind-the-scenes)
  - [Manual Windows Environment Variables (PATH) Configuration](#manual-windows-environment-variables-path-configuration)
  - [Installing the VS Code Extension (`.vsix`)](#installing-the-vs-code-extension-vsix)
  - [Method 2: Developer Mode (From Git Source)](#method-2-developer-mode-from-git-source)
- [How the Application Works (Engine Architecture & Deep Dive)](#-how-the-application-works-engine-architecture--deep-dive)
  - [1. Multi-Threaded Parallel Scanning Engine](#1-multi-threaded-parallel-scanning-engine)
  - [2. 4-Tier Security Detection Modules](#2-4-tier-security-detection-modules)
  - [3. High-Accuracy Confidence Scoring & False-Positive Elimination](#3-high-accuracy-confidence-scoring--false-positive-elimination)
  - [4. Security Scoring & Ship-Readiness Gate (0–100)](#4-security-scoring--ship-readiness-gate-0100)
  - [5. Automated Shift-Left Git Pre-Commit & Pre-Push Gates](#5-automated-shift-left-git-pre-commit--pre-push-gates)
  - [6. Persistent SQLite Audit Storage & Trend Tracking](#6-persistent-sqlite-audit-storage--trend-tracking)
  - [7. AI & Expert DevSecOps Security Advisor](#7-ai--expert-devsecops-security-advisor)
  - [8. Multi-Format Reporting & Executive Audit Certificates](#8-multi-format-reporting--executive-audit-certificates)
  - [9. Automated GitHub Self-Updater (Public & Private Repos)](#9-automated-github-self-updater-public--private-repos)
- [Complete CLI Command Reference](#-complete-cli-command-reference)
- [VS Code Extension Features & Quick Fixes](#-vs-code-extension-features--quick-fixes)
- [Web Security Dashboard](#-web-security-dashboard)
- [Demo Vulnerable App Verification Matrix](#-demo-vulnerable-app-verification-matrix)
- [Automated Tests & Quality Assurance](#-automated-tests--quality-assurance)

---

## 🏛️ Architecture & Tech Stack

SecureShip implements a unified scanning model where the **Core Python Engine** acts as the single source of truth across all developer touchpoints: terminal CLI, Git pre-commit & pre-push hooks, automated CI/CD pipelines, VS Code IDE extension, and the interactive Web Dashboard.

```mermaid
flowchart TD
    subgraph ClientInterfaces ["Shift-Left Developer Interfaces"]
        IDE["VS Code Extension\n(TypeScript API + Diagnostics)"]
        CLI["SecureShip CLI / Git Gate\n(Typer + Rich Engine)"]
        DASH["Web Security Dashboard\n(React 18 + Vite + Tailwind)"]
    end

    subgraph ServiceLayer ["API & Service Layer"]
        API["FastAPI Local REST Service\n(http://127.0.0.1:8787)"]
    end

    subgraph CoreEngine ["SecureShip Engine (Python 3.10+)"]
        ORCH["Multi-Threaded Scanner Orchestrator\n(ThreadPoolExecutor)"]
        SCORER["Security Scoring & Quality Gate\n(0-100 Score | READY / REVIEW / BLOCKED)"]
        CONF["Confidence & False-Positive Filter\n(High / Medium / Low Accuracy)"]
        SQLITE[("Persistent History DB\n(~/.secureship/history.db)")]
        ADVISOR["AI / DevSecOps Advisor\n(Exploit Analysis & Patches)"]

        subgraph ModularScanners ["4 Core Security Domains (35+ Rules)"]
            S1["Secrets & Credentials\n(Entropy + Pattern Matcher)"]
            S2["SAST Code Analysis\n(Python AST + JS/Node Engine)"]
            S3["Dependency / SCA\n(OSV.dev Batch API + Offline CVE DB)"]
            S4["Container & IaC\n(Dockerfile, Compose, K8s)"]
        end
    end

    subgraph Targets ["Target Project / Repository"]
        CODE["Target Files & Manifests\n(Python, JS/TS, Docker, K8s, package.json, requirements.txt, .env)"]
    end

    IDE -->|"HTTP /api/scan/content"| API
    DASH -->|"HTTP /api/scans & /api/history"| API
    CLI -->|"Direct Execution"| ORCH
    API -->|"Direct Execution"| ORCH

    ORCH --> S1
    ORCH --> S2
    ORCH --> S3
    ORCH --> S4

    ModularScanners --> CODE
    ModularScanners --> CONF
    CONF --> SCORER
    SCORER --> SQLITE
    SCORER --> ADVISOR
    SCORER -->|"ScanResult & Metrics"| ORCH
```

---

## 🚀 How to Run on Any Computer (Including Another Person's Computer)

### Method 1: 1-Click Portable Release Package (Recommended)

You can share SecureShip as a single compressed zip file: `SecureShip-v1.0.0-release.zip`. The code inside the package is **protected and compiled into optimized Python bytecode (`.pyc`)**, with all raw source `.py` files removed.

#### Step 1: Send the Zip
Share `SecureShip-v1.0.0-release.zip` with any user.

#### Step 2: Extract Anywhere
The user extracts `SecureShip-v1.0.0-release.zip` to any folder on their computer (e.g. `C:\SecureShip` or `C:\Users\<Name>\SecureShip`).

#### Step 3: Run the 1-Click Installer
Inside the extracted folder:
- **Windows Command Prompt (CMD):** Double-click `install.bat`.
- **Windows PowerShell:** Right-click `setup.ps1` -> **Run with PowerShell** (or run `powershell -ExecutionPolicy Bypass -File .\setup.ps1`).

#### Step 4: Verify from Any Terminal
Open a **new** Command Prompt or PowerShell window anywhere and run:
```bash
secureship --help
```
You are ready to scan!

---

### How `install.bat` Works Behind the Scenes

The `install.bat` script handles the entire machine setup automatically:

1. **Python Detection:** Scans the target computer for active Python installations in `%PATH%`, checking standard locations:
   - Python in system `PATH`
   - `%USERPROFILE%\Python311\python.exe`
   - `%LOCALAPPDATA%\Programs\Python\Python311\python.exe`
   - Windows Python Launcher (`py.exe -3`)
2. **Dependency Resolution:** Installs required runtime dependencies (`typer`, `rich`, `pydantic`, `fastapi`, `uvicorn`, `httpx`, `pyyaml`) silently into the user's Python environment.
3. **Environment Variable Registration:** Dynamically resolves the absolute path of the `bin\` folder and uses `setx PATH "%PATH%;<bin_path>"` (or registry modification) to add `bin\` and the Python Scripts directory to the user's permanent **User Environment Variables (`PATH`)**.
4. **Instant Terminal Access:** Creates `secureship.cmd` and `secureship.ps1` runners so running `secureship` works seamlessly in both `cmd.exe` and `powershell.exe`.

---

### Manual Windows Environment Variables (PATH) Configuration

If the user prefers to add the `bin` directory to their environment variables manually:

1. Extract the release zip to a permanent location (e.g. `C:\SecureShip`).
2. Press <kbd>Win</kbd> + <kbd>R</kbd>, type `sysdm.cpl`, and hit <kbd>Enter</kbd>.
3. In the **System Properties** dialog, switch to the **Advanced** tab and click **Environment Variables...**.
4. In the top section (**User variables for &lt;YourUsername&gt;**), select the `Path` variable and click **Edit...**.
5. Click **New**, paste the absolute path to the `bin` folder:
   ```text
   C:\SecureShip\bin
   ```
6. Click **OK** on all dialogs to save.
7. Open a **new** Command Prompt or PowerShell terminal and run:
   ```bash
   secureship version
   ```

---

### Installing the VS Code Extension (`.vsix`)

The portable release package includes the compiled VS Code extension: `secureship-vscode-1.0.0.vsix`.

#### Option A: Via VS Code User Interface (Recommended)
1. Open **Visual Studio Code**.
2. Click the **Extensions** icon on the left sidebar (<kbd>Ctrl</kbd> + <kbd>Shift</kbd> + <kbd>X</kbd>).
3. Click the **`...` (Views and More Actions)** button at the top-right of the Extensions pane.
4. Select **"Install from VSIX..."**.
5. Browse to the extracted folder, select `secureship-vscode-1.0.0.vsix`, and click **Install**.
6. A notification will appear: *"Completed installing SecureShip extension from VSIX"*.

#### Option B: Via Command Prompt / PowerShell
Run:
```bash
code --install-extension secureship-vscode-1.0.0.vsix
```

---

### Method 2: Developer Mode (From Git Source)

If you are developing or contributing to SecureShip directly:

```bash
# 1. Clone the repository
git clone https://github.com/777yash77/SecureSoftwareShip.git
cd SecureSoftwareShip

# 2. Install Core Engine in editable mode
cd engine
pip install -e .

# 3. Build & run Web Dashboard
cd ../dashboard
npm install
npm run dev

# 4. Compile VS Code Extension
cd ../vscode-extension
npm install
npm run compile
```

---

## ⚙️ How the Application Works (Engine Architecture & Deep Dive)

SecureShip operates on an objective, deterministic DevSecOps evaluation model built on 9 core architectural pillars:

### 1. Multi-Threaded Parallel Scanning Engine
- Files inside the target directory are collected while respecting `.gitignore` and `.secureshipignore`.
- Scans execute in parallel across a thread pool:
  $$\text{max\_workers} = \min(32, \max(4, \text{cpu\_count} \times 2))$$
- Bypasses large binary assets (> 5MB) and inspects initial byte headers for null bytes (`\x00`) to prevent corrupting text scanners, achieving sub-second scans on large repositories.

---

### 2. 4-Tier Security Detection Modules

SecureShip inspects 4 independent security domains with over **35+ specialized detection rules**:

#### Domain A: Secrets & Credentials (`secrets_scanner.py`)
- **Shannon Entropy Analysis**:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
  Identifies high-randomness string literals ($H > 3.2$) representing API tokens, credentials, and cryptographic keys.
- **Rules Covered**:
  - `SEC-000`: Tracked `.env` files exposing production credentials.
  - `SEC-001`: AWS Access Key IDs (`AKIA[0-9A-Z]{16}`).
  - `SEC-002`: GitHub Personal Access Tokens (`ghp_[a-zA-Z0-9]{36}`).
  - `SEC-003`: Generic high-entropy secret tokens.
  - `SEC-004`: Plaintext RSA, OpenSSH, or EC Private Keys.
  - `SEC-005`: Database connection URIs containing credentials (`postgres://user:pass@host`).
  - `SEC-007`: AI Platform API keys (OpenAI `sk-proj-`, Anthropic `sk-ant-`, HuggingFace `hf_`).
  - `SEC-008`: Slack Incoming Webhook URLs (`https://hooks.slack.com/services/...`).
  - `SEC-009`: Stripe live secret keys (`sk_live_[0-9a-zA-Z]{24,}`).
  - `SEC-010`: Google Cloud & Firebase API keys (`AIza[0-9A-Za-z\\-_]{35}`).
  - `SEC-011`: Plaintext hardcoded passwords in variable assignments (`password = "..."`).

#### Domain B: Static Application Security Testing — SAST (`sast_scanner.py`)
- **Python AST Engine**: Parses code directly into Abstract Syntax Trees.
  - AST Constant Propagation: Differentiates static queries (`execute("SELECT 1")`) from dynamic variable interpolations (`execute(f"SELECT * FROM users WHERE id = {user_id}")`).
  - `SAST-PY-001`: SQL Injection via dynamic f-strings, `.format()`, or `%` formatting.
  - `SAST-PY-002`: Command Injection via `os.system()` with dynamic input.
  - `SAST-PY-003`: Command Injection via `subprocess` with `shell=True`.
  - `SAST-PY-004`: Remote Code Execution via `pickle.loads()` deserialization.
  - `SAST-PY-005`: Insecure YAML deserialization via `yaml.load()` without SafeLoader.
  - `SAST-PY-006`: Dynamic arbitrary code execution via `eval()` or `exec()`.
  - `SAST-PY-007`: Broken cryptographic hashes (`hashlib.md5`, `hashlib.sha1`).
  - `SAST-PY-008`: Production debug mode enabled (`DEBUG = True`).
  - `SAST-PY-009`: Service bound to all interfaces (`0.0.0.0`).
  - `SAST-PY-010`: Server-Side Request Forgery (SSRF) via dynamic `requests` or `httpx` URLs.
  - `SAST-PY-011`: Path Traversal / Arbitrary File Read in `open()` or `send_file()`.
  - `SAST-PY-012`: Insecure Deserialization via `marshal` or `shelve`.
  - `SAST-PY-014`: Insecure XML parsing vulnerable to XML External Entity (XXE).
- **JavaScript & Node.js Engine**:
  - `SAST-JS-001`: Code execution via `eval()`.
  - `SAST-JS-002`: Cross-Site Scripting (XSS) via `innerHTML` or `dangerouslySetInnerHTML`.
  - `SAST-JS-003`: SQL Injection via string concatenation in `query()`.
  - `SAST-JS-004`: Command Injection via `child_process.exec()`.
  - `SAST-JS-005`: Disabled TLS verification (`rejectUnauthorized: false`).
  - `SAST-JS-006`: Hardcoded JWT signing secret in `jwt.sign()`.
  - `SAST-JS-007`: Server-Side Request Forgery (SSRF) via `axios`/`fetch` with dynamic URLs.
  - `SAST-JS-008`: Path Traversal / Arbitrary File Read in `fs.readFile()`.
  - `SAST-JS-009`: Prototype Pollution via unconstrained `Object.assign` or deep merge.
  - `SAST-JS-010`: Permissive Wildcard CORS configuration (`origin: '*'`).
  - `SAST-JS-011`: Insecure Cookies missing `httpOnly` or `secure` flags.

#### Domain C: Dependency / Software Composition Analysis — SCA (`sca_scanner.py`)
- Analyzes `package.json`, `requirements.txt`, and `pom.xml`.
- Queries the **OSV.dev batch API** (`https://api.osv.dev/v1/querybatch`) for up-to-date CVE records.
- Includes a **built-in offline CVE database** so dependency scanning functions reliably in isolated, air-gapped environments without internet access:
  - `CVE-2021-44228`: Log4j RCE (Log4Shell) in `log4j-core < 2.15.0`.
  - `CVE-2022-22965`: Spring Framework RCE (Spring4Shell) in `spring-beans < 5.3.18`.
  - `CVE-2020-8203`: Lodash Prototype Pollution in `lodash < 4.17.21`.
  - `CVE-2022-23529`: Remote Code Execution in `jsonwebtoken < 9.0.0`.
  - `CVE-2024-34064`: HTML Attribute Injection in `jinja2 < 3.1.4`.
  - `CVE-2024-34069`: Predictable Debugger PIN in `werkzeug < 3.0.3`.
  - `CVE-2023-50447`: Arbitrary Code Execution in `pillow < 10.0.1`.
  - `CVE-2023-38325`: Timing attack in `cryptography < 41.0.2`.
  - `CVE-2023-48795`: Terrapin SSH attack in `paramiko < 3.4.0`.

#### Domain D: Container & IaC Security (`iac_scanner.py`)
- **Dockerfile**:
  - `IAC-DOCKER-001`: Container executing as root (missing `USER` directive).
  - `IAC-DOCKER-002`: Unpinned base image tag (`:latest` or untagged).
  - `IAC-DOCKER-003`: Embedded secrets in `ENV` or `ARG` directives.
  - `IAC-DOCKER-004`: Dangerous `ADD` instruction instead of `COPY`.
  - `IAC-DOCKER-005`: Insecure pipe from `curl`/`wget` to shell (`curl ... | sh`).
- **Docker Compose**:
  - `IAC-COMPOSE-001`: Service running with `privileged: true` (host takeover risk).
  - `IAC-COMPOSE-002`: Sensitive database ports (`5432`, `3306`, `6379`, `27017`) exposed to `0.0.0.0`.
  - `IAC-COMPOSE-003`: Docker daemon socket (`/var/run/docker.sock`) mounted inside container.
  - `IAC-COMPOSE-004`: Host Network Mode (`network_mode: 'host'`) enabled.
- **Kubernetes Manifests**:
  - `IAC-K8S-001`: Pod containers missing CPU or Memory resource limits (DoS risk).
  - `IAC-K8S-002`: Pod running with privileged `securityContext`.
  - `IAC-K8S-003`: Container allows privilege escalation (`allowPrivilegeEscalation: true`).
  - `IAC-K8S-004`: Container root filesystem is writable (`readOnlyRootFilesystem: false`).

---

### 3. High-Accuracy Confidence Scoring & False-Positive Elimination

Every finding is tagged with an accuracy `Confidence`:
- **`HIGH`**: Definitive pattern match with zero ambiguity (e.g. valid AWS key format, unpinned Docker tag, AST f-string in SQL).
- **`MEDIUM`**: Heuristic pattern match (e.g. unknown API token with high entropy).
- **`LOW`**: Informational warning.

#### Eliminating False Positives
SecureShip uses contextual heuristics to exclude noise:
- GUIDs (`12345678-1234-1234-1234-123456789abc`) and SHA-256 hashes are automatically detected and suppressed from Secrets scanning.
- Documentation placeholders (`example.com`, `placeholder`, `changeme`, `dummy_token`, `your_api_key`) are excluded.
- Static queries inside `execute()` without string interpolation are recognized as safe by AST constant folding.
- To run zero-false-positive audits:
  ```bash
  secureship scan --confidence high
  ```

---

### 4. Security Scoring & Ship-Readiness Gate (0–100)

The Security Score starts at **100 points** and subtracts weighted penalties based on verified severity:

$$\text{Security Score} = \max\left(0, 100 - \sum \text{Severity Deductions}\right)$$

| Severity | Weight | Deduction per Finding |
| :--- | :---: | :---: |
| **CRITICAL** | 4 | **-25 points** |
| **HIGH** | 3 | **-15 points** |
| **MEDIUM** | 2 | **-5 points** |
| **LOW** | 1 | **-2 points** |

#### Ship-Readiness Verdicts
- <span style="color:#10b981;font-weight:bold;">READY TO SHIP</span>: Score $\ge \text{threshold}$ (default: 80) **AND** 0 Critical findings.
- <span style="color:#f59e0b;font-weight:bold;">NEEDS REVIEW</span>: Score is between 50 and 79 **AND** 0 Critical findings.
- <span style="color:#ef4444;font-weight:bold;">BLOCKED</span>: Score $< 50$ **OR** $\ge 1$ Critical finding detected.

#### User-Level Score Customization (`--modify-score`)
Teams can adjust the passing threshold to match their staging phase:
```bash
# Allow any score >= 65% to pass
secureship scan --modify-score 65

# Accepts percentages with '%' symbol
secureship scan --modify-score 70%
```

#### Strict Zero-Tolerance Category Policies
Enforce a hard blocker on specific categories regardless of overall score:
```bash
# Block push if ANY dependency vulnerability exists (even with score 99/100)
secureship scan --strict-sca

# Block push if ANY Docker/K8s misconfiguration exists
secureship scan --strict-iac

# Block push if ANY hardcoded secret exists
secureship scan --strict-sec

# Block push if ANY SAST code vulnerability exists
secureship scan --strict-sast
```

---

### 5. Automated Shift-Left Git Pre-Commit & Pre-Push Gates

SecureShip installs native Git security gates into your repository with one command:
```bash
secureship install-hook
```

#### Gate 1: Git Pre-Commit Hook (`.git/hooks/pre-commit`)
- Triggers automatically when a developer runs `git commit`.
- Fast diff mode (`--staged`): Scans **only lines added or modified** in the Git index.
- Rejects the commit immediately if high-severity code flaws or secrets are detected.

#### Gate 2: Git Pre-Push Hook (`.git/hooks/pre-push`)
- Triggers automatically when a developer runs `git push`.
- Audits the entire project against repository quality gate policies.
- Blocks the push if the Ship-Readiness verdict is **BLOCKED** or strict category violations exist.

#### Audited Emergency Bypass (`secureship bypass --push`)
In production emergency situations, authorized engineers can bypass the gate:
```bash
secureship bypass --push --reason "Hotfix for production outage #1042"
```
SecureShip logs the timestamp, reason, and username to `.git/secureship-bypass.token`, allows the push, and immediately revokes the token.

---

### 6. Persistent SQLite Audit Storage & Trend Tracking

Every scan is recorded in a local SQLite database (`~/.secureship/history.db`).
- Tracks timestamps, scanned targets, scores, findings breakdowns, and ship verdicts.
- Wrapped in safe database transactions so SQLite operations never crash scans.
- View history anytime:
  ```bash
  secureship history --limit 5
  ```

---

### 7. AI & Expert DevSecOps Security Advisor

SecureShip includes built-in exploit intelligence for every rule ID:
```bash
secureship explain SAST-PY-001
secureship explain SEC-007
secureship explain IAC-DOCKER-001
```
Renders 3 structured analysis panels:
1. **Vulnerability Analysis & Real-World Impact**: Explains the root flaw, CWE ID, and OWASP category.
2. **Adversary Exploitation Scenario**: Demonstrates how an attacker exploits the flaw in production.
3. **Remediation Strategy & Defensive Patch**: Provides copy-paste syntax-highlighted patched code.

---

### 8. Multi-Format Reporting & Executive Audit Certificates

SecureShip generates reports for both developers and executives:
```bash
# Rich Terminal Table (default)
secureship scan .

# Standalone Print-Ready HTML Report
secureship scan . --format html -o report.html

# OASIS SARIF v2.1.0 (for GitHub Code Scanning & CI/CD)
secureship scan . --format sarif -o report.sarif

# Machine-Readable JSON
secureship scan . --format json -o report.json

# Executive Ship Readiness Audit Certificate
secureship certificate ./my-project -o Ship-Certificate.html
```

---

### 9. Automated GitHub Self-Updater (Public & Private Repos)

SecureShip can update itself directly from your GitHub repository:
```bash
# Check for updates without applying
secureship update --check

# Apply latest update from public repository
secureship update

# Update from a private GitHub repository using a Personal Access Token (PAT)
secureship update --token ghp_YourGitHubTokenHere

# Or save your token once into .secureshiprc:
secureship config --github-token ghp_YourGitHubTokenHere
```

---

## 💻 Complete CLI Command Reference

| Command / Option | Description & Example |
| :--- | :--- |
| `secureship scan` | Scan current folder across all 4 categories |
| `secureship scan ./my-app` | Scan specific directory or file |
| `secureship scan --modify-score 65` | Override passing gate score to 65% (default: 80) |
| `secureship scan --strict-sca` | Block push if ANY dependency vulnerability is found |
| `secureship scan --strict-iac` | Block push if ANY Docker/K8s misconfiguration is found |
| `secureship scan --strict-sec` | Block push if ANY secret/token is found |
| `secureship scan --strict-sast` | Block push if ANY SAST code vulnerability is found |
| `secureship scan --confidence high` | Filter findings to high-accuracy zero-false-positive risks |
| `secureship scan --sec` | Scan **ONLY Secrets** |
| `secureship scan --iac` | Scan **ONLY Container & IaC** |
| `secureship scan --sast` | Scan **ONLY SAST code flaws** |
| `secureship scan --sca` | Scan **ONLY Dependencies** |
| `secureship scan --staged` | Scan only Git staged lines (pre-commit mode) |
| `secureship scan --fail-on high` | Exit code 1 if findings equal or exceed High severity |
| `secureship scan --format html -o report.html` | Export printable standalone HTML audit report |
| `secureship scan --format sarif -o report.sarif`| Export SARIF v2.1.0 for GitHub Security tab |
| `secureship config --min-score 70` | Persist custom 70% threshold into `.secureshiprc` |
| `secureship config --strict-sca` | Persist strict zero-tolerance SCA blocker |
| `secureship config --min-confidence high` | Persist high-accuracy gate in `.secureshiprc` |
| `secureship config --show` | Display current repository quality gate rules |
| `secureship rules` | List all 35+ built-in detection rules with CWE/OWASP IDs |
| `secureship rules --category SECRETS` | Filter rules catalog by category |
| `secureship explain <RULE_ID>` | Get AI / Expert exploit scenario and patched code fix |
| `secureship history` | Display persistent SQLite scan audit history and scores |
| `secureship certificate ./my-app` | Generate print-ready Executive Audit Certificate |
| `secureship install-hook` | Install automated Git pre-commit & pre-push gates |
| `secureship bypass --push` | Issue audited emergency bypass token and execute `git push` |
| `secureship update` | Fetch & install latest updates from GitHub |
| `secureship update --token <PAT>` | Fetch updates from private GitHub repository |
| `secureship serve --port 8787` | Launch Web Security Dashboard & REST API backend |
| `secureship version` | Display installed software version |

#### Direct Quick Options
Options can also be passed directly to `secureship` without typing `scan`:
```bash
secureship --modify-score 65
secureship --strict-sca
secureship --confidence high
secureship --update
secureship --version
```

---

## 🧩 VS Code Extension Features & Quick Fixes

The VS Code Extension provides real-time in-editor security diagnostics:

1. **Inline Squiggly Diagnostics**:
   - Highlights vulnerable lines with severity colors: Critical (Red), High (Orange), Medium (Yellow), Low (Blue).
   - Tooltips show Rule ID, severity, CWE ID, OWASP category, and remediation advice.
2. **Auto-Scan on Save**:
   - Analyzes documents on save in under 50ms via `onDidSaveTextDocument`.
3. **Activity Bar View ("SecureShip Findings")**:
   - Dedicated sidebar grouping all workspace findings by Severity and File.
   - Click any finding to jump directly to the offending line.
4. **Status Bar Quality Gate**:
   - Displays `$(shield) SecureShip: 85/100` in the status bar with one-click access to full reports.
5. **Quick Fix Code Actions (<kbd>Ctrl</kbd> + <kbd>.</kbd> / <kbd>Cmd</kbd> + <kbd>.</kbd>)**:
   - **`SAST-PY-007`**: Replaces `hashlib.md5(...)` with `hashlib.sha256(...)`.
   - **`SEC-001`**: Extracts hardcoded secrets into `os.environ.get("AWS_ACCESS_KEY_ID")`.
   - **`IAC-DOCKER-001`**: Inserts `USER appuser` into Dockerfiles.
   - **Inline Suppression**: Inserts `# secureship-ignore: <RULE_ID>`.

---

## 🌐 Web Security Dashboard

SecureShip includes an interactive cybersecurity dashboard built with React 18, Vite, and Tailwind CSS:

```bash
secureship serve --port 8787
```
Open **`http://localhost:8787`** in your browser.

- **Live Score Gauge**: Circular visual indicator of repository ship status.
- **Interactive Threshold Slider**: Adjust passing gate % in real time.
- **Repository Auditing Modes**: Scan local paths, public GitHub repository URLs, or uploaded `.zip` archives.
- **Interactive Findings Explorer**: Search, filter by category/severity/confidence, and view exploit analyses.
- **One-Click Exports**: Export HTML, JSON, SARIF, or Executive Certificates directly from the browser.

---

## 🧪 Demo Vulnerable App Verification Matrix

The [demo-vulnerable-app/](file:///c:/Users/yaswanth/Downloads/SecureShip/demo-vulnerable-app) fixture verifies detection across all 4 categories:

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

## 🛡️ Automated Tests & Quality Assurance

Run the comprehensive unit and integration test suite covering every scanner, accuracy filter, quality gate, CLI command, and REST API endpoint:

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
