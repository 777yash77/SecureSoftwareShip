#!/usr/bin/env python3
"""SecureShip Distribution Packager
Builds a protected, production-ready release zip archive:
1. Compiles all Python source code to bytecode (.pyc) and removes .py source files
2. Includes portable CLI runners (bin/), installer scripts (install.bat, setup.ps1)
3. Bundles VS Code Extension (.vsix) and demo testing suite (demo-vulnerable-app/)
4. Generates a comprehensive README.txt and README.md with clear instructions
5. Archives into SecureShip-v1.0.0-release.zip
"""

import compileall
import os
import shutil
import zipfile
from pathlib import Path


def build_release_package():
    repo_root = Path(__file__).resolve().parent
    dist_dir = repo_root / "dist"
    staging_dir = dist_dir / "SecureShip-v1.0.0-release"
    zip_output = repo_root / "SecureShip-v1.0.0-release.zip"

    print("=" * 60)
    print("  SecureShip Protected Release Packager")
    print("=" * 60)

    # 1. Clean previous staging
    if staging_dir.exists():
        shutil.rmtree(staging_dir, ignore_errors=True)
    if zip_output.exists():
        zip_output.unlink()

    staging_dir.mkdir(parents=True, exist_ok=True)
    print("[*] Staging directory created:", staging_dir)

    # 2. Copy bin/
    shutil.copytree(repo_root / "bin", staging_dir / "bin")
    print("[+] Copied bin/ runners (secureship.cmd, secureship.ps1)")

    # 3. Copy install.bat and setup.ps1
    shutil.copy2(repo_root / "install.bat", staging_dir / "install.bat")
    shutil.copy2(repo_root / "setup.ps1", staging_dir / "setup.ps1")
    print("[+] Copied install.bat and setup.ps1")

    # 4. Copy VS Code extension
    vsix_src = repo_root / "secureship-vscode-1.0.0.vsix"
    if vsix_src.exists():
        shutil.copy2(vsix_src, staging_dir / "secureship-vscode-1.0.0.vsix")
        print("[+] Copied secureship-vscode-1.0.0.vsix")

    # 5. Copy demo-vulnerable-app
    demo_src = repo_root / "demo-vulnerable-app"
    if demo_src.exists():
        shutil.copytree(
            demo_src,
            staging_dir / "demo-vulnerable-app",
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", "node_modules"),
        )
        print("[+] Copied demo-vulnerable-app for instant testing")

    # 6. Copy engine and protect code (compile to bytecode .pyc and strip .py)
    target_engine = staging_dir / "engine"
    shutil.copytree(
        repo_root / "engine",
        target_engine,
        ignore=shutil.ignore_patterns(
            "tests", ".pytest_cache", "__pycache__", "*.pyc", "*.egg-info", "dist", "build"
        ),
    )

    print("[*] Protecting code: Compiling engine to optimized Python bytecode (.pyc)...")
    compileall.compile_dir(str(target_engine / "secureship"), force=True, legacy=True, optimize=2)

    # Remove all .py source files inside secureship package
    py_removed = 0
    for root, dirs, files in os.walk(target_engine / "secureship"):
        for f in files:
            if f.endswith(".py"):
                (Path(root) / f).unlink()
                py_removed += 1

    print(f"[+] Code protected: compiled all modules to .pyc and removed {py_removed} .py source files.")

    # 7. Generate README.txt & README.md for end user
    readme_content = """================================================================================
  🛡️ SECURESHIP — Shift-Left DevSecOps Security Gate & Scanner Platform
================================================================================

Thank you for downloading SecureShip v1.0.0!

This portable release package contains the complete SecureShip DevSecOps engine,
compiled and optimized for high-performance security scanning, secrets detection,
SAST code flaw analysis, vulnerable dependency scanning (SCA), and Infrastructure
as Code (IaC) compliance.

--------------------------------------------------------------------------------
TABLE OF CONTENTS
--------------------------------------------------------------------------------
1. Quick 1-Click Installation (Recommended)
2. Moving 'bin' to Environment Variables (Manual Setup)
3. Running SecureShip Anywhere
4. Custom Passing Score (--modify-score) & Strict Category Enforcers
5. Launching the Web Dashboard
6. Installing the VS Code Extension
7. Automated Git Security Gates (pre-commit & pre-push)

================================================================================
1. QUICK 1-CLICK INSTALLATION (RECOMMENDED)
================================================================================
PREREQUISITE:
  - Python 3.10+ installed from https://python.org.

TO INSTALL AUTOMATICALLY:
  - On Windows Command Prompt (CMD):
      Double-click "install.bat" (or run: install.bat in CMD)

  - On Windows PowerShell:
      Right-click "setup.ps1" -> Run with PowerShell
      (or run: powershell -ExecutionPolicy Bypass -File .\\setup.ps1)

WHAT THIS DOES:
  1. Verifies your Python installation.
  2. Installs the engine dependencies.
  3. Automatically adds the 'bin' directory and your Python Scripts folder to
     your Windows User Environment Variables (PATH) so 'secureship' works
     from ANY command prompt or PowerShell window on your machine!

================================================================================
2. MOVING 'BIN' TO ENVIRONMENT VARIABLES (MANUAL SETUP)
================================================================================
If you prefer to configure your PATH manually:

STEP 1: Extract this folder to a permanent location, e.g.:
        C:\\SecureShip
        (So that bin is at: C:\\SecureShip\\bin)

STEP 2: Open Windows Environment Variables:
        - Press Win + R on your keyboard.
        - Type: sysdm.cpl and press Enter.
        - Go to the "Advanced" tab and click "Environment Variables...".

STEP 3: Add to User PATH:
        - Under "User variables for <YourName>", find and select "Path".
        - Click "Edit...".
        - Click "New" and paste: C:\\SecureShip\\bin
        - Click "OK" on all open windows.

STEP 4: Verify:
        Open a new Command Prompt or PowerShell window and type:
        secureship --help

================================================================================
3. RUNNING SECURESHIP ANYWHERE
================================================================================
Run directly from any project repository:

  # 1. Scan current directory (all categories: Secrets, SAST, SCA, IaC)
  secureship scan

  # 2. Scan a specific project folder
  secureship scan "C:\\path\\to\\project"

  # 3. Scan ONLY specific security domains:
  secureship scan --sec      # Scan ONLY secrets, tokens, private keys
  secureship scan --sast     # Scan ONLY static application code flaws
  secureship scan --sca      # Scan ONLY vulnerable dependencies (CVEs)
  secureship scan --iac      # Scan ONLY Docker / Compose / K8s misconfigs

  # 4. Generate standalone reports:
  secureship scan --format html -o report.html
  secureship scan --format sarif -o report.sarif
  secureship scan --format json -o report.json

  # 5. Generate executive Ship-Readiness Certificate:
  secureship certificate ./my-project

================================================================================
4. CUSTOM PASSING SCORE & STRICT CATEGORY ENFORCERS
================================================================================
You can customize the required ship gate score (default: 80%):

  # Allow any score >= 65% to pass:
  secureship scan --modify-score 65

  # Accepts any custom percentage with or without '%':
  secureship scan --modify-score 70%
  secureship scan --modify-score 85

STRICT ZERO-TOLERANCE CATEGORY ENFORCEMENT:
Even if your security score is 99/100, you can make specific categories strictly
fail the build or git push:

  # Block push if ANY dependency vulnerability exists:
  secureship scan --strict-sca

  # Block push if ANY Docker/K8s misconfiguration exists:
  secureship scan --strict-iac

  # Block push if ANY hardcoded secret or token exists:
  secureship scan --strict-sec

  # Block push if ANY SAST code flaw exists:
  secureship scan --strict-sast

  # High-accuracy scan (filters out false positives):
  secureship scan --confidence high

SAVE AS PERMANENT REPO POLICY (.secureshiprc or ~/.secureship/config.json):
  secureship config --min-score 70 --strict-sca --min-confidence high
  secureship config --global --min-score 60
  secureship config --show

AUTOMATED REMEDIATION & ENTERPRISE TOOLS:
  # Auto-protect repository .gitignore from secret leaks & unstage credentials:
  secureship protect .

  # Automated STRIDE threat modeling & risk matrix:
  secureship threat-model ./my-project
  secureship threat-model ./my-project --format json -o threat-model.json

  # Audit git commit history for leaked secrets & purge guidance:
  secureship git-history ./my-project --commits 50

  # Migrate discovered hardcoded secrets to .env.example, HashiCorp Vault, & K8s:
  secureship vault ./my-project -o ./vault-output

  # Generate dynamic SVG security status badge for repository README:
  secureship badge ./my-project -o security-badge.svg

  # Deep container & Dockerfile security inspection:
  secureship container ./Dockerfile
  secureship container ./my-project

  # Safe auto-remediation (preview dry-run diffs):
  secureship fix ./my-project --dry-run
  # Apply code and IaC fixes in-place:
  secureship fix ./my-project --apply

  # Generate CycloneDX v1.5 or SPDX v2.3 Software Bill of Materials (SBOM):
  secureship sbom ./my-project --format cyclonedx -o sbom.json
  secureship sbom ./my-project --format spdx -o sbom-spdx.json

  # Audit against OWASP Top 10, PCI-DSS, SOC 2, and NIST SSDF compliance:
  secureship compliance ./my-project --standard owasp
  secureship compliance ./my-project --standard pci-dss

  # Generate automated CI/CD pipeline workflows:
  secureship init-ci --platform github
  secureship init-ci --platform gitlab
  secureship init-ci --all

AUTO-UPDATE FROM GITHUB:
  # Check for updates:
  secureship update --check

  # Apply latest update:
  secureship update

  # Update from private GitHub repository with token:
  secureship update --token ghp_YourPATHere

================================================================================
5. LAUNCHING THE WEB DASHBOARD
================================================================================
SecureShip includes a local cybersecurity web dashboard:

  secureship serve --port 8787

Then open your browser to: http://127.0.0.1:8787
Features:
  - Interactive Security Score Gauge & Ship Verdict
  - Local Path, GitHub URL, and Zip Archive Upload auditing
  - Interactive Gate Threshold % slider
  - Exploit scenarios and AI Remediation Advisor

================================================================================
6. INSTALLING THE VS CODE EXTENSION
================================================================================
The VS Code extension package is included in this zip:
"secureship-vscode-1.0.0.vsix"

TO INSTALL IN VS CODE:
  1. Open Visual Studio Code.
  2. Press Ctrl + Shift + P to open the Command Palette.
  3. Type and select: "Extensions: Install from VSIX..."
  4. Browse to and select "secureship-vscode-1.0.0.vsix".
  5. Click Install!

You now get real-time security squiggles, quick fix code actions, sidebar
findings tree, and status bar score in VS Code.

================================================================================
7. AUTOMATED GIT SECURITY GATES (PRE-COMMIT & PRE-PUSH)
================================================================================
To protect your remote GitHub / GitLab repositories:

  cd "C:\\path\\to\\your-git-repo"
  secureship install-hook

Gates Installed:
  - pre-commit: Fast diff scan on staged code. Blocks committing secrets & flaws.
  - pre-push:   Full repository quality gate audit. Blocks unapproved code push.

Emergency Override (Audited Hotfix):
  secureship bypass --push
  (OR: git push --no-verify)
================================================================================
"""

    (staging_dir / "README.txt").write_text(readme_content, encoding="utf-8")
    if (repo_root / "README.md").exists():
        shutil.copy2(repo_root / "README.md", staging_dir / "README.md")
    else:
        (staging_dir / "README.md").write_text(readme_content, encoding="utf-8")
    print("[+] Generated README.txt and copied comprehensive README.md inside package")

    # 8. Create Zip Archive
    print(f"[*] Compressing {staging_dir.name} into {zip_output.name}...")
    with zipfile.ZipFile(zip_output, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(staging_dir):
            for file in files:
                full_path = Path(root) / file
                rel_path = full_path.relative_to(staging_dir.parent)
                zf.write(full_path, arcname=str(rel_path))

    size_mb = zip_output.stat().st_size / (1024 * 1024)
    print(f"\n========================================================")
    print(f"  [SUCCESS] Created release archive:")
    print(f"  Path: {zip_output}")
    print(f"  Size: {size_mb:.2f} MB")
    print(f"========================================================\n")


if __name__ == "__main__":
    build_release_package()
