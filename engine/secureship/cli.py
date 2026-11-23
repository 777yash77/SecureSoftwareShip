from __future__ import annotations

import datetime
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import List, Optional


import typer
import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax

from secureship.advisor import EXPERT_KNOWLEDGE_BASE, SecurityAdvisor
from secureship.badge import BadgeGenerator
from secureship.ci_generator import CIGenerator
from secureship.ci_cd_auditor import CICDAuditor
from secureship.compliance import ComplianceEngine
from secureship.config import load_config, save_config
from secureship.container_auditor import ContainerAuditor
from secureship.db import HistoryDB
from secureship.git_scanner import GitHistoryScanner
from secureship.license_checker import LicenseAuditor
from secureship.models import Confidence, Finding, FindingCategory, Severity, ShipStatus
from secureship.protector import SecretProtector
from secureship.remediator import RemediationEngine
from secureship.reporters.certificate_reporter import render_certificate_report
from secureship.reporters.console_reporter import render_console_report
from secureship.reporters.html_reporter import render_html_report
from secureship.reporters.json_reporter import render_json_report
from secureship.reporters.sarif_reporter import render_sarif_report
from secureship.sbom import SBOMGenerator
from secureship.scanner import SecureShipEngine
from secureship.taint_analyzer import TaintAnalyzer
from secureship.threat_model import ThreatModelingEngine
from secureship.updater import run_self_update
from secureship.vault import VaultMigrator

console = Console()

CLI_DESCRIPTION = """[bold cyan]🛡️ SecureShip[/bold cyan] — [bold white]Shift-Left DevSecOps Security Gate & Scanner Platform[/bold white]

Audit and evaluate codebases for hardcoded secrets, AST-based SAST code flaws, vulnerable dependencies (SCA), and Docker / K8s misconfigurations (IaC) directly in your terminal before shipping to production.

[bold yellow]QUICK EXAMPLES & POPULAR COMMANDS:[/bold yellow]
  [cyan]secureship scan[/cyan]                               Scan current folder (all categories)
  [cyan]secureship scan ./my-project[/cyan]                  Scan a specific project folder
  [cyan]secureship scan --modify-score <N>[/cyan]             Set custom passing score threshold to N% (e.g. 50, 65, 75, 85, 90; default: 80)
  [cyan]secureship scan --modify-score 70%[/cyan]             Supports percentages with or without '%' symbol
  [cyan]secureship scan --strict-sca[/cyan]                   Block push if ANY dependency vulnerability exists (even with 99 score)
  [cyan]secureship scan --strict-iac[/cyan]                   Block push if ANY Docker/K8s misconfiguration is detected
  [cyan]secureship scan --strict-sec[/cyan]                   Block push if ANY hardcoded secret/token is detected
  [cyan]secureship scan --strict-sast[/cyan]                  Block push if ANY SAST code vulnerability is detected
  [cyan]secureship scan --confidence high[/cyan]              High-accuracy filter (filters out false positives)
  [cyan]secureship scan --sec[/cyan]                         Scan [bold red]ONLY Secrets[/bold red] (AWS keys, GitHub tokens, .env, Stripe, Slack)
  [cyan]secureship scan --iac[/cyan]                         Scan [bold red]ONLY Container & IaC[/bold red] (Dockerfile, Compose, K8s)
  [cyan]secureship scan --sast[/cyan]                        Scan [bold red]ONLY SAST code flaws[/bold red] (SQLi, SSRF, XSS, RCE, Path Traversal)
  [cyan]secureship scan --sca[/cyan]                         Scan [bold red]ONLY Dependencies[/bold red] (CVEs in package.json, requirements, pom.xml)
  [cyan]secureship scan --fail-on high[/cyan]                Enforce Shift-Left Gate (exit 1 if High/Critical findings exist)
  [cyan]secureship scan --ignore[/cyan]                      [bold yellow]Emergency Override:[/bold yellow] ignore quality gate for git push
  [cyan]secureship scan --format html -o report.html[/cyan]  Generate printable standalone HTML report
  [cyan]secureship scan --format sarif -o report.sarif[/cyan] Generate SARIF v2.1.0 report for GitHub Code Scanning
  [cyan]secureship scan --staged[/cyan]                      Pre-commit mode: scan only Git staged lines
  [cyan]secureship config --min-score 70[/cyan]              Persist custom 70% threshold into .secureshiprc for Git hooks
  [cyan]secureship config --strict-sca[/cyan]                Persist strict zero-tolerance SCA policy in .secureshiprc
  [cyan]secureship config --min-confidence high[/cyan]       Persist high-accuracy gate in .secureshiprc
  [cyan]secureship config --show[/cyan]                       Display current quality gate settings
  [cyan]secureship rules[/cyan]                              List all 35+ built-in security detection rules
  [cyan]secureship rules --category SECRETS[/cyan]           Filter rules by category (SECRETS, SAST, SCA, IAC)
  [cyan]secureship explain SAST-PY-001[/cyan]                Get AI / Expert exploit analysis & patch for a rule
  [cyan]secureship history[/cyan]                            View previous scans & security score trends from SQLite
  [cyan]secureship certificate ./my-project[/cyan]           Generate executive Ship Readiness Certificate
  [cyan]secureship install-hook[/cyan]                       Install automated Git [bold green]pre-commit[/bold green] & [bold green]pre-push[/bold green] gates
  [cyan]secureship bypass --push[/cyan]                       Authorize emergency bypass token & execute git push
  [cyan]secureship update[/cyan]                             Fetch & install latest software updates from GitHub
  [cyan]secureship update --token ghp_...[/cyan]            Fetch update from private GitHub repository with PAT
  [cyan]secureship update --check[/cyan]                     Check for remote updates without applying
  [cyan]secureship fix ./my-project[/cyan]                  Auto-remediate vulnerabilities (safe code hardening)
  [cyan]secureship sbom ./my-project[/cyan]                 Generate CycloneDX 1.5 / SPDX 2.3 Software Bill of Materials
  [cyan]secureship compliance ./my-project[/cyan]           Audit OWASP Top 10, PCI-DSS, SOC 2, and NIST compliance
  [cyan]secureship init-ci --platform github[/cyan]         Generate automated CI/CD pipeline workflow (GitHub/GitLab/Azure)
  [cyan]secureship protect[/cyan]                           Auto-protect .env, DB credentials & keys in .gitignore
  [cyan]secureship threat-model ./my-project[/cyan]          Generate STRIDE attack surface & threat vector matrix
  [cyan]secureship git-history[/cyan]                       Scan past Git commits for leaked credentials & API keys
  [cyan]secureship vault ./my-project -o ./vault[/cyan]     Migrate secrets to .env.example, HashiCorp Vault, & K8s
  [cyan]secureship badge -o badge.svg[/cyan]                Generate shields-compliant SVG security badge for README
  [cyan]secureship container ./Dockerfile[/cyan]            Deep container audit: multi-stage, SUID, ARG secrets
  [cyan]secureship serve --port 8787[/cyan]                  Launch Web Security Dashboard on port 8787
  [cyan]secureship version[/cyan]                            Display installed SecureShip version
"""


def parse_score_threshold(val: Optional[Any]) -> Optional[int]:
    """Parse custom score threshold from integer or percentage string e.g. 65, 75%, '90'."""
    if val is None:
        return None
    val_str = str(val).strip().rstrip("%").strip()
    try:
        score_int = int(val_str)
        if score_int < 0 or score_int > 100:
            typer.secho(
                f"Error: Invalid score threshold '{val}'. Must be a percentage between 0 and 100 (e.g. 50, 65, 75, 80).",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=2)
        return score_int
    except ValueError:
        typer.secho(
            f"Error: Invalid score threshold '{val}'. Must be a valid number or percentage (e.g. 65, 75, 80%).",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)

app = typer.Typer(
    name="secureship",
    help=CLI_DESCRIPTION,
    add_completion=False,
    rich_markup_mode="rich",
)


@app.command()
def scan(
    path: str = typer.Argument(".", help="Path to project directory or file to scan"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, html, or sarif"),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Fail with non-zero exit code if findings equal or exceed severity: critical, high, medium, low",
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save report to file path"),
    min_severity: Optional[str] = typer.Option(
        None, "--min-severity", help="Filter minimum severity to include: critical, high, medium, low"
    ),
    staged: bool = typer.Option(
        False, "--staged", "--diff", help="Only scan Git staged added/modified lines (fast pre-commit mode)"
    ),
    sec: bool = typer.Option(
        False, "--sec", "--secrets", help="Scan ONLY for hardcoded secrets, tokens, and credentials"
    ),
    iac: bool = typer.Option(
        False, "--iac", help="Scan ONLY for Infrastructure as Code (Dockerfile, Compose, K8s)"
    ),
    sast: bool = typer.Option(
        False, "--sast", help="Scan ONLY Static Application Security Testing (Code flaws in Python, JS/TS)"
    ),
    sca: bool = typer.Option(
        False, "--sca", help="Scan ONLY Software Composition Analysis (Vulnerable dependencies / CVEs)"
    ),
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="Filter by specific category: SECRETS, SAST, SCA, IAC"
    ),
    min_score: Optional[str] = typer.Option(
        None,
        "--modify-score",
        "--modify_score",
        "--min-score",
        "--modify-score-to",
        help="Custom quality gate passing score percentage (default: 80, e.g. 50, 65, 75, 85, 90 or 75%)",
    ),
    strict_sca: bool = typer.Option(
        False,
        "--strict-sca",
        "--strict-SCA",
        help="Strict policy: fail ship gate if ANY dependency/SCA vulnerability exists",
    ),
    strict_iac: bool = typer.Option(
        False,
        "--strict-iac",
        "--strict-IAC",
        "--strict-iat",
        "--strict-IAT",
        help="Strict policy: fail ship gate if ANY Docker/K8s/IaC vulnerability exists",
    ),
    strict_sec: bool = typer.Option(
        False,
        "--strict-sec",
        "--strict-SEC",
        help="Strict policy: fail ship gate if ANY hardcoded secret/token exists",
    ),
    strict_sast: bool = typer.Option(
        False,
        "--strict-sast",
        "--strict-SAST",
        help="Strict policy: fail ship gate if ANY SAST code vulnerability exists",
    ),
    strict: Optional[List[str]] = typer.Option(
        None,
        "--strict",
        help="Enforce strict zero-tolerance on specified categories (e.g. --strict SCA --strict SECRETS)",
    ),
    confidence: Optional[str] = typer.Option(
        None,
        "--confidence",
        "--min-confidence",
        "--accuracy",
        help="High-accuracy filter: 'high' (zero false-positives), 'medium', or 'low'",
    ),
    ignore_gate: bool = typer.Option(
        False, "--ignore", "--bypass", "--force-push", help="Emergency override: ignore quality gate and allow git push"
    ),
) -> None:
    """Run comprehensive security scan against a codebase or target file."""
    if ignore_gate:
        repo_path = Path(path).resolve()
        git_dir = repo_path / ".git"
        if git_dir.exists():
            token_file = git_dir / "secureship-bypass.token"
            token_file.write_text(json.dumps({"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), "reason": "CLI --ignore flag override"}, indent=2), encoding="utf-8")
        typer.secho("⚠️  [SECURESHIP GATE BYPASS ARMED] Next git push will be allowed through.", fg=typer.colors.YELLOW, bold=True)
        return

    raw_path = path.strip()
    target_path = Path(raw_path).resolve()

    if not target_path.exists():
        repo_root = Path(__file__).resolve().parent.parent.parent
        cleaned = raw_path.lstrip("./\\").strip()
        if (repo_root / cleaned).exists():
            target_path = (repo_root / cleaned).resolve()
        elif (repo_root / target_path.name).exists():
            target_path = (repo_root / target_path.name).resolve()

    if not target_path.exists():
        typer.secho(f"Error: Target path '{path}' does not exist on disk.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    min_sev_enum = None
    if min_severity:
        try:
            min_sev_enum = Severity(min_severity.upper())
        except ValueError:
            typer.secho(f"Error: Invalid --min-severity '{min_severity}'. Use critical, high, medium, or low.", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)

    # Determine category filters
    selected_categories: List[FindingCategory] = []
    if sec:
        selected_categories.append(FindingCategory.SECRETS)
    if iac:
        selected_categories.append(FindingCategory.IAC)
    if sast:
        selected_categories.append(FindingCategory.SAST)
    if sca:
        selected_categories.append(FindingCategory.SCA)
    if category:
        try:
            selected_categories.append(FindingCategory(category.upper()))
        except ValueError:
            typer.secho(f"Error: Invalid category '{category}'. Choose from SECRETS, SAST, SCA, IAC.", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)

    categories_to_pass = list(set(selected_categories)) if selected_categories else None

    # Determine strict categories
    strict_cat_enums: List[FindingCategory] = []
    if strict_sca:
        strict_cat_enums.append(FindingCategory.SCA)
    if strict_iac:
        strict_cat_enums.append(FindingCategory.IAC)
    if strict_sec:
        strict_cat_enums.append(FindingCategory.SECRETS)
    if strict_sast:
        strict_cat_enums.append(FindingCategory.SAST)
    if strict:
        for sc in strict:
            norm = "IAC" if sc.upper() == "IAT" else sc.upper()
            try:
                strict_cat_enums.append(FindingCategory(norm))
            except ValueError:
                typer.secho(f"Warning: Unknown strict category '{sc}'.", fg=typer.colors.YELLOW, err=True)

    min_conf_enum: Optional[Confidence] = None
    if confidence:
        try:
            min_conf_enum = Confidence(confidence.upper())
        except ValueError:
            typer.secho(f"Error: Invalid --confidence '{confidence}'. Choose from high, medium, or low.", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)

    strict_to_pass = list(set(strict_cat_enums)) if strict_cat_enums else None
    parsed_min_score = parse_score_threshold(min_score)
    engine = SecureShipEngine(target_path=str(target_path), categories=categories_to_pass)

    try:
        if staged:
            result = engine.scan_staged(
                min_severity=min_sev_enum,
                min_score=parsed_min_score,
                strict_categories=strict_to_pass,
                min_confidence=min_conf_enum,
            )
        else:
            result = engine.scan(
                min_severity=min_sev_enum,
                min_score=parsed_min_score,
                strict_categories=strict_to_pass,
                min_confidence=min_conf_enum,
            )
    except Exception as e:
        typer.secho(f"\n❌ Error during security scan execution: {e}\n", fg=typer.colors.RED, bold=True, err=True)
        raise typer.Exit(code=1)

    # Render according to requested format
    fmt = format.lower()
    report_text = ""

    try:
        if fmt == "json":
            report_text = render_json_report(result)
            if not output:
                print(report_text)
        elif fmt == "html":
            report_text = render_html_report(result)
            if not output:
                print(report_text)
        elif fmt == "sarif":
            report_text = render_sarif_report(result)
            if not output:
                print(report_text)
        else:  # default table / console
            render_console_report(result)
    except Exception as e:
        typer.secho(f"Error rendering scan report: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    # Write to file if requested
    if output:
        try:
            out_path = Path(output).resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if fmt == "table":
                out_path.write_text(render_json_report(result), encoding="utf-8")
            else:
                out_path.write_text(report_text, encoding="utf-8")
            typer.secho(f"Report saved to: {out_path}", fg=typer.colors.GREEN)
        except (OSError, PermissionError) as e:
            typer.secho(f"Error: Unable to save report to '{output}': {e}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)

    # Check strict category violations
    if result.summary.strict_violations:
        typer.secho(
            "\n❌ [STRICT POLICY ENFORCEMENT VIOLATION]: Push and build blocked! Findings detected in strict categories:\n"
            + "\n".join(f"   • {v}" for v in result.summary.strict_violations)
            + "\n",
            fg=typer.colors.RED,
            bold=True,
            err=True,
        )
        raise typer.Exit(code=1)

    # Check --fail-on condition
    if fail_on:
        if fail_on.upper() in ("GATE", "SHIP", "SHIP-STATUS"):
            if result.summary.ship_status != ShipStatus.READY_TO_SHIP:
                typer.secho(
                    f"\n❌ Build FAILED: Ship-readiness gate rejected (Status: {result.summary.ship_status.value}, Score: {result.summary.security_score}/{result.summary.min_score}).\n",
                    fg=typer.colors.RED,
                    bold=True,
                    err=True,
                )
                raise typer.Exit(code=1)
        else:
            try:
                threshold_sev = Severity(fail_on.upper())
                threshold_weight = threshold_sev.weight
                failing_findings = [f for f in result.findings if f.severity.weight >= threshold_weight]
                if failing_findings:
                    typer.secho(
                        f"\n❌ Build FAILED: Found {len(failing_findings)} finding(s) meeting or exceeding '{fail_on.upper()}' severity.\n",
                        fg=typer.colors.RED,
                        bold=True,
                        err=True,
                    )
                    raise typer.Exit(code=1)
            except ValueError:
                typer.secho(f"Error: Invalid --fail-on '{fail_on}'. Use critical, high, medium, low, or gate.", fg=typer.colors.RED, err=True)
                raise typer.Exit(code=2)

    if result.summary.ship_status == ShipStatus.BLOCKED and fail_on is not None:
        raise typer.Exit(code=1)


@app.command()
def config(
    path: str = typer.Option(".", "--path", "-p", help="Target project directory"),
    min_score: Optional[str] = typer.Option(
        None, "--modify-score", "--modify_score", "--min-score", help="Set custom required passing score percentage (0-100, e.g. 50, 65, 75, 90 or 75%)"
    ),
    strict_sca: bool = typer.Option(
        False, "--strict-sca", "--strict-SCA", help="Enable strict SCA dependency policy"
    ),
    strict_iac: bool = typer.Option(
        False, "--strict-iac", "--strict-IAC", "--strict-iat", "--strict-IAT", help="Enable strict IaC container policy"
    ),
    strict_sec: bool = typer.Option(
        False, "--strict-sec", "--strict-SEC", help="Enable strict Secret policy"
    ),
    strict_sast: bool = typer.Option(
        False, "--strict-sast", "--strict-SAST", help="Enable strict SAST code policy"
    ),
    github_token: Optional[str] = typer.Option(
        None, "--github-token", help="Store GitHub Personal Access Token in .secureshiprc for updates"
    ),
    min_confidence: Optional[str] = typer.Option(
        None, "--min-confidence", "--accuracy", help="Configure minimum accuracy confidence level: high, medium, low"
    ),
    global_cfg: bool = typer.Option(
        False, "--global", "-g", help="Apply configuration globally across all repositories (~/.secureship/config.json)"
    ),
    show: bool = typer.Option(False, "--show", "-s", help="Display current quality gate configuration"),
) -> None:
    """Configure or view repository quality gate rules (.secureshiprc)."""
    target = Path(path).resolve()
    current_cfg = load_config(target)

    no_args = min_score is None and not strict_sca and not strict_iac and not strict_sec and not strict_sast and github_token is None and min_confidence is None
    if show or no_args:
        from secureship.config import find_config_file
        cfg_file = find_config_file(target)
        source_label = str(cfg_file) if cfg_file else "system defaults"
        typer.secho(f"\n⚙️  SecureShip Quality Gate Configuration ({source_label}):", fg=typer.colors.CYAN, bold=True)
        typer.echo(f"   • Passing Score (min_score): {current_cfg.get('min_score', 80)} / 100")
        stricts = current_cfg.get("strict_categories", [])
        typer.echo(f"   • Strict Blocker Categories:  {', '.join(stricts) if stricts else 'None (default: Critical severity blocks)'}")
        typer.echo(f"   • Accuracy Confidence Gate:   {current_cfg.get('min_confidence', 'All Confidences')}")
        has_token = bool(current_cfg.get("github_token"))
        typer.echo(f"   • GitHub Private Token:       {'Configured (masked)' if has_token else 'Not set'}\n")
        return

    updates: dict = {}
    parsed_score = parse_score_threshold(min_score)
    if parsed_score is not None:
        updates["min_score"] = parsed_score

    if min_confidence is not None:
        try:
            valid_conf = Confidence(min_confidence.upper())
            updates["min_confidence"] = valid_conf.value
        except ValueError:
            typer.secho(f"Error: Invalid --min-confidence '{min_confidence}'. Choose from high, medium, or low.", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)

    if github_token is not None:
        if github_token.strip():
            updates["github_token"] = github_token.strip()
        else:
            updates.pop("github_token", None)

    current_stricts = set(current_cfg.get("strict_categories", []))
    if strict_sca:
        current_stricts.add("SCA")
    if strict_iac:
        current_stricts.add("IAC")
    if strict_sec:
        current_stricts.add("SECRETS")
    if strict_sast:
        current_stricts.add("SAST")

    updates["strict_categories"] = sorted(list(current_stricts))
    try:
        saved_path = save_config(target, updates, is_global=global_cfg)
    except Exception as e:
        typer.secho(f"Error saving configuration: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    typer.secho(f"\n✅ Updated SecureShip quality gate configuration in {saved_path}:", fg=typer.colors.GREEN, bold=True)
    if "min_score" in updates:
        typer.echo(f"   • Passing Score Threshold set to: {updates['min_score']}%")
    if "min_confidence" in updates:
        typer.echo(f"   • Accuracy Confidence Filter set to: {updates['min_confidence']}")
    if "github_token" in updates:
        typer.echo("   • GitHub Personal Access Token saved for private repository updates.")
    typer.echo(f"   • Strict Categories: {', '.join(updates['strict_categories']) if updates['strict_categories'] else 'None'}\n")


@app.command()
def update(
    repo: str = typer.Option(
        "https://github.com/777yash77/SecureSoftwareShip.git", "--repo", "-r", help="Target GitHub repository URL"
    ),
    branch: str = typer.Option("main", "--branch", "-b", help="Target branch name"),
    token: Optional[str] = typer.Option(
        None, "--token", "-t", help="GitHub Personal Access Token for private repository access"
    ),
    check: bool = typer.Option(False, "--check", "-c", help="Only check for updates without installing"),
) -> None:
    """Fetch and apply the latest SecureShip updates from GitHub (public or private)."""
    code = run_self_update(repo_url=repo, branch=branch, token=token, check_only=check)
    if code != 0:
        raise typer.Exit(code=code)


@app.command()
def rules(
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filter by category: SECRETS, SAST, SCA, IAC")
) -> None:
    """List all built-in DevSecOps detection rules, CWE IDs, and OWASP categories."""
    table = Table(title="🛡️ SecureShip Built-in Security Detection Rules", header_style="bold cyan", border_style="dim")
    table.add_column("Rule ID", style="bold yellow", width=16)
    table.add_column("Category", style="cyan", width=10)
    table.add_column("Target Tech", style="white", width=14)
    table.add_column("Description & Impact", style="white")
    table.add_column("CWE / OWASP", style="dim", width=24)

    rules_catalog = [
        ("SEC-000", "SECRETS", "Git / .env", "Tracked .env file exposing production environment variables", "CWE-798 / A07:2021"),
        ("SEC-001", "SECRETS", "AWS / Cloud", "Hardcoded AWS Access Key ID (AKIA...)", "CWE-798 / A07:2021"),
        ("SEC-002", "SECRETS", "GitHub API", "Hardcoded GitHub Personal Access Token (ghp_...)", "CWE-798 / A07:2021"),
        ("SEC-003", "SECRETS", "Generic API", "High Shannon-entropy unknown API key or secret token", "CWE-798 / A07:2021"),
        ("SEC-004", "SECRETS", "Crypto / SSH", "Unencrypted RSA, OpenSSH, or EC Private Key in plaintext", "CWE-312 / A02:2021"),
        ("SEC-005", "SECRETS", "Databases", "Database connection URI with embedded password", "CWE-798 / A07:2021"),
        ("SEC-007", "SECRETS", "AI Platform", "Hardcoded OpenAI, Anthropic, or HuggingFace API key", "CWE-798 / A07:2021"),
        ("SEC-008", "SECRETS", "Slack / Chat", "Exposed Slack Incoming Webhook URL", "CWE-798 / A07:2021"),
        ("SEC-009", "SECRETS", "Stripe / Payments", "Hardcoded Stripe live secret key (sk_live_...)", "CWE-798 / A07:2021"),
        ("SEC-010", "SECRETS", "Google Cloud", "Hardcoded Google Cloud / Firebase API key (AIza...)", "CWE-798 / A07:2021"),
        ("SEC-011", "SECRETS", "Credentials", "Hardcoded plain-text password in variable assignment", "CWE-798 / A07:2021"),
        ("SAST-PY-001", "SAST", "Python SQL", "SQL Injection via dynamic f-string or string formatting in execute()", "CWE-89 / A03:2021"),
        ("SAST-PY-002", "SAST", "Python OS", "Command Injection via os.system() with dynamic input", "CWE-78 / A03:2021"),
        ("SAST-PY-003", "SAST", "Python Subprocess", "Command Injection via subprocess with shell=True", "CWE-78 / A03:2021"),
        ("SAST-PY-004", "SAST", "Python Pickle", "Arbitrary Code Execution via untrusted pickle.loads deserialization", "CWE-502 / A08:2021"),
        ("SAST-PY-005", "SAST", "Python YAML", "Unsafe YAML loading via yaml.load() without SafeLoader", "CWE-502 / A08:2021"),
        ("SAST-PY-006", "SAST", "Python Code", "Arbitrary Code Execution via eval() or exec()", "CWE-95 / A03:2021"),
        ("SAST-PY-007", "SAST", "Python Crypto", "Weak cryptographic hash algorithm (MD5 / SHA1)", "CWE-328 / A02:2021"),
        ("SAST-PY-008", "SAST", "Python Flask/Django", "Production DEBUG mode enabled (DEBUG = True)", "CWE-489 / A05:2021"),
        ("SAST-PY-009", "SAST", "Python Network", "Service bound to all network interfaces (0.0.0.0)", "CWE-1327 / A05:2021"),
        ("SAST-PY-010", "SAST", "Python HTTP", "Server-Side Request Forgery (SSRF) via dynamic requests/httpx URL", "CWE-918 / A10:2021"),
        ("SAST-PY-011", "SAST", "Python Files", "Path Traversal / Arbitrary File Read in open() or send_file()", "CWE-22 / A01:2021"),
        ("SAST-PY-012", "SAST", "Python Marshal", "Insecure Deserialization via marshal or shelve", "CWE-502 / A08:2021"),
        ("SAST-PY-014", "SAST", "Python XML", "Insecure XML parsing vulnerable to XML External Entity (XXE)", "CWE-611 / A05:2021"),
        ("SAST-JS-001", "SAST", "JavaScript", "Code injection via eval()", "CWE-95 / A03:2021"),
        ("SAST-JS-002", "SAST", "JavaScript DOM", "Cross-Site Scripting (XSS) via unescaped innerHTML", "CWE-79 / A03:2021"),
        ("SAST-JS-003", "SAST", "JavaScript SQL", "SQL Injection via string concatenation in query()", "CWE-89 / A03:2021"),
        ("SAST-JS-004", "SAST", "Node.js ChildProc", "Command Injection via child_process.exec()", "CWE-78 / A03:2021"),
        ("SAST-JS-005", "SAST", "Node.js TLS", "Disabled TLS verification (rejectUnauthorized: false)", "CWE-295 / A02:2021"),
        ("SAST-JS-006", "SAST", "Node.js JWT", "Hardcoded JWT secret or weak signature key", "CWE-798 / A07:2021"),
        ("SAST-JS-007", "SAST", "Node.js HTTP", "Server-Side Request Forgery (SSRF) via axios/fetch with dynamic URL", "CWE-918 / A10:2021"),
        ("SAST-JS-008", "SAST", "Node.js Files", "Arbitrary File Read / Path Traversal in fs.readFile()", "CWE-22 / A01:2021"),
        ("SAST-JS-009", "SAST", "Node.js Objects", "Prototype Pollution via unconstrained Object.assign or deep merge", "CWE-1321 / A03:2021"),
        ("SAST-JS-010", "SAST", "Node.js Express", "Permissive Wildcard CORS Configuration (origin: '*')", "CWE-942 / A05:2021"),
        ("SAST-JS-011", "SAST", "Node.js Cookies", "Insecure Cookie Settings missing httpOnly or secure flags", "CWE-614 / A05:2021"),
        ("IAC-DOCKER-001", "IAC", "Dockerfile", "Container running as root (missing USER nonroot directive)", "CWE-250 / A05:2021"),
        ("IAC-DOCKER-002", "IAC", "Dockerfile", "Unpinned base image tag (:latest or untagged)", "CWE-1188 / A05:2021"),
        ("IAC-DOCKER-003", "IAC", "Dockerfile", "Secrets embedded in ENV or ARG build parameters", "CWE-798 / A07:2021"),
        ("IAC-DOCKER-004", "IAC", "Dockerfile", "Dangerous ADD instruction in Dockerfile instead of COPY", "CWE-829 / A05:2021"),
        ("IAC-DOCKER-005", "IAC", "Dockerfile", "Insecure pipe from curl or wget to shell (curl | sh)", "CWE-78 / A03:2021"),
        ("IAC-COMPOSE-001", "IAC", "Docker Compose", "Service running with privileged: true (host takeover risk)", "CWE-250 / A05:2021"),
        ("IAC-COMPOSE-002", "IAC", "Docker Compose", "Sensitive DB port (5432, 3306, 6379) bound to 0.0.0.0", "CWE-668 / A05:2021"),
        ("IAC-COMPOSE-003", "IAC", "Docker Compose", "Docker daemon socket (/var/run/docker.sock) mounted in container", "CWE-250 / A05:2021"),
        ("IAC-COMPOSE-004", "IAC", "Docker Compose", "Host Network Mode (network_mode: 'host') enabled", "CWE-668 / A05:2021"),
        ("IAC-K8S-001", "IAC", "Kubernetes", "Container missing CPU / Memory resource limits (DoS risk)", "CWE-770 / A05:2021"),
        ("IAC-K8S-002", "IAC", "Kubernetes", "Pod running with privileged securityContext (node escape)", "CWE-250 / A05:2021"),
        ("IAC-K8S-003", "IAC", "Kubernetes", "Container allows privilege escalation (allowPrivilegeEscalation: true)", "CWE-250 / A05:2021"),
        ("IAC-K8S-004", "IAC", "Kubernetes", "Container root filesystem is writable (readOnlyRootFilesystem: false)", "CWE-250 / A05:2021"),
        ("SCA-CVE20208203", "SCA", "npm:lodash", "Prototype Pollution in lodash < 4.17.21 (CVE-2020-8203)", "CWE-1321 / A06:2021"),
        ("SCA-CVE202223529", "SCA", "npm:jsonwebtoken", "Remote Code Execution in jsonwebtoken < 9.0.0 (CVE-2022-23529)", "CWE-502 / A06:2021"),
        ("SCA-CVE202434064", "SCA", "pypi:jinja2", "HTML Attribute Injection in Jinja2 < 3.1.4 (CVE-2024-34064)", "CWE-79 / A06:2021"),
        ("SCA-CVE202434069", "SCA", "pypi:werkzeug", "Predictable Debugger PIN in Werkzeug < 3.0.3 (CVE-2024-34069)", "CWE-330 / A06:2021"),
        ("SCA-CVE202350447", "SCA", "pypi:pillow", "Arbitrary Code Execution in Pillow < 10.0.1 (CVE-2023-50447)", "CWE-94 / A06:2021"),
    ]

    for rid, cat, tech, desc, cwe_owasp in rules_catalog:
        if category and cat.upper() != category.upper():
            continue
        table.add_row(rid, cat, tech, desc, cwe_owasp)

    console.print(table)
    console.print("\n[dim]To inspect a specific rule in detail: [cyan]secureship explain <RULE_ID>[/cyan][/dim]\n")


@app.command()
def explain(
    rule_id: str = typer.Argument(..., help="Rule ID to analyze (e.g. SAST-PY-001, SEC-001, IAC-DOCKER-001)")
) -> None:
    """Get expert AI / DevSecOps analysis, exploitation scenario, and code patch for a rule."""
    key = rule_id.upper()
    rule_data = EXPERT_KNOWLEDGE_BASE.get(key)

    if not rule_data:
        typer.secho(f"No specific knowledge-base entry found for '{rule_id}'. Run 'secureship rules' to see all IDs.", fg=typer.colors.YELLOW)
        return

    console.print(f"\n[bold cyan]🛡️  SecureShip Security Advisor — Deep Rule Analysis[/bold cyan]")
    console.print(f"[bold white]Rule ID:[/bold white] [bold yellow]{key}[/bold yellow]\n")

    # 1. Analysis Panel
    console.print(Panel(
        rule_data["analysis"],
        title="[bold red]1. Vulnerability Analysis & Real-World Impact[/bold red]",
        border_style="red",
    ))

    # 2. Exploitation Scenario
    console.print(Panel(
        rule_data["exploit_scenario"],
        title="[bold yellow]2. Adversary Exploitation Scenario[/bold yellow]",
        border_style="yellow",
    ))

    # 3. Remediation & Code Fix
    fix_text = Text()
    fix_text.append(f"{rule_data['remediation_strategy']}\n\n", style="white")
    fix_text.append("Patched Code Example:\n", style="bold green")

    console.print(Panel(
        fix_text,
        title="[bold green]3. Remediation Strategy & Defensive Patch[/bold green]",
        border_style="green",
    ))
    syntax = Syntax(rule_data["patched_code"], "python", theme="monokai", line_numbers=True)
    console.print(syntax)
    console.print("")


@app.command()
def history(
    limit: int = typer.Option(10, "--limit", "-n", help="Number of past scans to display")
) -> None:
    """Display past scan history and security score trajectory from local SQLite storage."""
    try:
        db = HistoryDB()
        recent = db.get_recent_scans(limit=limit)
    except Exception as e:
        typer.secho(f"Error accessing scan history database: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    if not recent:
        console.print("[dim]No scan history found in ~/.secureship/history.db. Run 'secureship scan' to create your first scan.[/dim]")
        return

    table = Table(title="📜 SecureShip Persistent Scan History", header_style="bold magenta")
    table.add_column("Scan ID", style="cyan", width=14)
    table.add_column("Timestamp", style="dim", width=22)
    table.add_column("Target Path", style="white")
    table.add_column("Score", style="bold", justify="center", width=10)
    table.add_column("Verdict", justify="center", width=16)
    table.add_column("Findings (C / H / M / L)", justify="center", width=24)

    for r in recent:
        s = r.summary
        color = "green" if s.ship_status == ShipStatus.READY_TO_SHIP else "red"
        findings_summary = f"[red]{s.critical_count}[/] / [dark_orange]{s.high_count}[/] / [yellow]{s.medium_count}[/] / [cyan]{s.low_count}[/]"
        table.add_row(
            r.scan_id[:12],
            r.timestamp[:19].replace("T", " "),
            r.target_path,
            f"[{color}]{s.security_score}/100[/]",
            f"[{color}]{s.ship_status.value}[/]",
            findings_summary,
        )

    console.print(table)


@app.command()
def certificate(
    path: str = typer.Argument(".", help="Path to project directory or file"),
    output: str = typer.Option("Ship-Readiness-Certificate.html", "--output", "-o", help="Output certificate HTML file path"),
) -> None:
    """Generate official print-ready Ship Readiness Executive Audit Certificate."""
    target_path = Path(path).resolve()
    if not target_path.exists():
        repo_root = Path(__file__).resolve().parent.parent.parent
        cleaned = path.strip().lstrip("./\\")
        if (repo_root / cleaned).exists():
            target_path = (repo_root / cleaned).resolve()

    if not target_path.exists():
        typer.secho(f"Error: Target path '{path}' does not exist on disk.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    try:
        engine = SecureShipEngine(target_path=str(target_path))
        result = engine.scan()
        cert_html = render_certificate_report(result)
    except Exception as e:
        typer.secho(f"Error generating audit certificate: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    try:
        out_file = Path(output).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(cert_html, encoding="utf-8")
        typer.secho(f"✅ Official Ship Readiness Certificate generated successfully!", fg=typer.colors.GREEN, bold=True)
        typer.secho(f"Path: {out_file}", fg=typer.colors.CYAN)
        typer.secho("Open this file in your browser and press Ctrl+P to save as PDF.", fg=typer.colors.WHITE)
    except (OSError, PermissionError) as e:
        typer.secho(f"Error: Unable to save certificate to '{output}': {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


@app.command()
def install_hook(
    path: str = typer.Option(".", "--path", "-p", help="Path to Git repository root where hook should be installed"),
    target_path: Optional[str] = typer.Argument(None, help="Positional repository path"),
) -> None:
    """Install automated Git pre-commit & pre-push security gates in the target repository."""
    repo_path = Path(target_path or path).resolve()
    git_dir = repo_path / ".git"

    if not git_dir.exists():
        typer.secho(f"Error: No .git directory found at '{repo_path}'. Run inside a valid Git repository.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    try:
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)

        # 1. Pre-Commit Hook (Scans staged changes fast and protects secrets)
        commit_hook = hooks_dir / "pre-commit"
        commit_content = """#!/usr/bin/env bash
# SecureShip Git Pre-Commit Hook (Automated Shift-Left Security Gate)
echo "🛡️  SecureShip: Immunizing secrets and scanning staged changes..."

if ! command -v secureship &> /dev/null; then
    echo "⚠️  SecureShip CLI not found in PATH. Skipping hook."
    exit 0
fi

# Automatically ensure .env, DB credentials, and private keys are in .gitignore
secureship protect . &> /dev/null

secureship scan --staged --fail-on high
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "❌ Commit rejected by SecureShip: High/Critical vulnerabilities detected in staged files."
    echo "Fix vulnerabilities before committing, or use inline suppression '# secureship-ignore'."
    exit 1
fi

echo "✅ SecureShip: Staged changes verified. Proceeding with commit."
exit 0
"""
        commit_hook.write_text(commit_content, encoding="utf-8")

        bat_commit = hooks_dir / "pre-commit.bat"
        bat_commit.write_text(
            "@echo off\n"
            "echo 🛡️  SecureShip: Immunizing secrets and scanning staged changes...\n"
            "call secureship protect . >nul 2>&1\n"
            "secureship scan --staged --fail-on high\n"
            "if %ERRORLEVEL% NEQ 0 (\n"
            "    echo ❌ Commit rejected by SecureShip.\n"
            "    exit /b 1\n"
            ")\n",
            encoding="utf-8"
        )

        # 2. Pre-Push Hook (Validates full project quality gate before git push)
        push_hook = hooks_dir / "pre-push"
        push_content = """#!/usr/bin/env bash
# SecureShip Git Pre-Push Hook (Automated Shift-Left Pipeline Gate)
echo "🛡️  SecureShip: Running Pre-Push Security Audit & Secret Immunization..."

BYPASS_FILE=".git/secureship-bypass.token"
if [ "$SECURESHIP_BYPASS" = "1" ] || [ "$SECURESHIP_FORCE_PUSH" = "1" ] || [ -f "$BYPASS_FILE" ]; then
    echo "⚠️  [WARNING] SecureShip: Emergency bypass active. Security gate bypassed by developer override."
    rm -f "$BYPASS_FILE" 2>/dev/null
    exit 0
fi

if ! command -v secureship &> /dev/null; then
    echo "⚠️  SecureShip CLI not found in PATH. Skipping pre-push gate."
    exit 0
fi

# Automatically ensure .env, DB credentials, and private keys are in .gitignore before push
secureship protect . &> /dev/null

secureship scan . --fail-on high
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "❌ [GIT PUSH BLOCKED] SecureShip DevSecOps Quality Gate Failed!"
    echo "High or Critical security vulnerabilities were detected in your repository."
    echo "Code violating ship-readiness policies cannot be pushed to remote."
    echo ""
    echo "Options to proceed:"
    echo "  1. Fix the vulnerabilities reported above."
    echo "  2. Add inline suppression: '# secureship-ignore' or '// secureship-ignore'"
    echo "  3. Emergency override / force push:"
    echo "       secureship bypass --push"
    echo "       OR"
    echo "       git push --no-verify"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    exit 1
fi

echo "✅ SecureShip: Quality gate approved. Code is ready to ship. Proceeding with push!"
exit 0
"""
        push_hook.write_text(push_content, encoding="utf-8")

        bat_push = hooks_dir / "pre-push.bat"
        bat_push.write_text(
            "@echo off\n"
            "echo 🛡️  SecureShip: Running Pre-Push Security Audit & Secret Immunization...\n"
            "if exist \".git\\secureship-bypass.token\" (\n"
            "    echo ⚠️  [WARNING] SecureShip: Emergency bypass active. Gate overridden.\n"
            "    del \".git\\secureship-bypass.token\" >nul 2>&1\n"
            "    exit /b 0\n"
            ")\n"
            "if \"%SECURESHIP_BYPASS%\"==\"1\" exit /b 0\n"
            "call secureship protect . >nul 2>&1\n"
            "secureship scan . --fail-on high\n"
            "if %ERRORLEVEL% NEQ 0 (\n"
            "    echo.\n"
            "    echo ==============================================================================\n"
            "    echo ❌ [GIT PUSH BLOCKED] High/Critical vulnerabilities detected!\n"
            "    echo To override in emergency: secureship bypass --push  OR  git push --no-verify\n"
            "    echo ==============================================================================\n"
            "    echo.\n"
            "    exit /b 1\n"
            ")\n"
            "echo ✅ SecureShip: Quality gate approved. Proceeding with push!\n"
            "exit /b 0\n",
            encoding="utf-8"
        )

        # Chmod executable on POSIX
        for h in [commit_hook, push_hook]:
            try:
                current_stat = os.stat(h)
                os.chmod(h, current_stat.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            except Exception:
                pass
    except (OSError, PermissionError) as e:
        typer.secho(f"Error installing Git hooks in '{repo_path}': {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    # Automatically immunize repository .gitignore right now
    protector = SecretProtector(str(repo_path))
    prot_res = protector.protect(repo_path)

    typer.secho(f"✅ SecureShip Git security gates successfully installed into: {hooks_dir}", fg=typer.colors.GREEN, bold=True)
    typer.secho("🛡️  Gate 1: pre-commit    (immunizes secrets & blocks committing vulnerabilities)", fg=typer.colors.CYAN)
    typer.secho("🛡️  Gate 2: pre-push      (auto-protects .env/credentials & blocks unapproved push)", fg=typer.colors.CYAN)
    typer.secho("🔒  Gate 3: secret-shield (automatically enforces .gitignore protection for .env & DBs)", fg=typer.colors.CYAN)
    if prot_res["patterns_added"]:
        typer.secho(f"   • Auto-protected {len(prot_res['patterns_added'])} sensitive credential patterns in .gitignore", fg=typer.colors.YELLOW)
    if prot_res["files_unstaged"]:
        typer.secho(f"   • Safely removed {len(prot_res['files_unstaged'])} sensitive file(s) from Git staging: {', '.join(prot_res['files_unstaged'])}", fg=typer.colors.YELLOW, bold=True)
    typer.secho("💡 Emergency Override: 'secureship bypass --push' or 'git push --no-verify'", fg=typer.colors.WHITE)


@app.command()
def protect(
    path: str = typer.Argument(".", help="Target repository directory"),
    unstage: bool = typer.Option(True, "--unstage/--no-unstage", help="Automatically remove staged secret files from Git index"),
) -> None:
    """Auto-protect repository: adds .env, DB credentials, private keys, and tokens to .gitignore before pushing."""
    target = Path(path).resolve()
    if not target.exists():
        typer.secho(f"Error: Target path '{path}' does not exist.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    protector = SecretProtector(str(target))
    res = protector.protect(target_dir=target, auto_unstage=unstage)

    typer.secho(f"\n🔒 SecureShip Secret Shield & .gitignore Immunizer", fg=typer.colors.CYAN, bold=True)
    typer.echo(f"   Target: {target}")
    typer.echo(f"   Config: {res['gitignore_path']}\n")

    if res["patterns_added"]:
        typer.secho(f"✅ Immunized .gitignore with {len(res['patterns_added'])} protected pattern(s):", fg=typer.colors.GREEN, bold=True)
        for p in res["patterns_added"]:
            typer.echo(f"   + {p}")
    else:
        typer.secho("✅ .gitignore already contains all critical credential and database protection patterns.", fg=typer.colors.GREEN)

    if res["files_unstaged"]:
        typer.secho(f"\n⚠️  CRITICAL: Safely un-staged {len(res['files_unstaged'])} sensitive file(s) from Git:", fg=typer.colors.YELLOW, bold=True)
        for uf in res["files_unstaged"]:
            typer.secho(f"   - {uf} (removed from Git staging index, local file preserved)", fg=typer.colors.YELLOW)

    if res["detected_sensitive_files"]:
        typer.echo(f"\n🛡️  Currently protected credential files on disk: {', '.join(res['detected_sensitive_files'])}\n")


@app.command()
def bypass(
    path: str = typer.Option(".", "--path", "-p", help="Target repository path"),
    push: bool = typer.Option(False, "--push", help="Automatically trigger 'git push' with authorized bypass"),
    reason: str = typer.Option("Emergency production hotfix / developer override", "--reason", "-r", help="Audit explanation for overriding security gate"),
) -> None:
    """Issue an audited emergency bypass token allowing the next Git push through the gate."""
    repo_path = Path(path).resolve()
    git_dir = repo_path / ".git"

    if not git_dir.exists():
        typer.secho(f"Error: No .git directory found at '{repo_path}'.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    try:
        token_file = git_dir / "secureship-bypass.token"
        token_data = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "reason": reason,
            "author": os.environ.get("USERNAME") or os.environ.get("USER") or "developer",
        }
        token_file.write_text(json.dumps(token_data, indent=2), encoding="utf-8")
    except (OSError, PermissionError) as e:
        typer.secho(f"Error writing emergency bypass token: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    typer.secho("\n⚠️  [SECURESHIP EMERGENCY BYPASS ARMED]", fg=typer.colors.YELLOW, bold=True)
    typer.secho(f"Reason:  {reason}", fg=typer.colors.WHITE)
    typer.secho(f"Author:  {token_data['author']}", fg=typer.colors.WHITE)
    typer.secho("Status:  Authorized for the next 'git push'.", fg=typer.colors.CYAN)
    typer.secho("Audit:   Security event logged for compliance verification.\n", dim=True)

    if push:
        typer.secho("🚀 Executing 'git push' with authorized bypass...\n", fg=typer.colors.GREEN, bold=True)
        env = os.environ.copy()
        env["SECURESHIP_BYPASS"] = "1"
        try:
            res = subprocess.run(["git", "push"], cwd=str(repo_path), env=env)
            if token_file.exists():
                token_file.unlink()
            raise typer.Exit(code=res.returncode)
        except FileNotFoundError:
            typer.secho("Error: 'git' command not found in system PATH.", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        except Exception as e:
            typer.secho(f"Error executing git push: {e}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)



@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Bind host"),
    port: int = typer.Option(8787, "--port", "-p", help="Bind port"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload for development"),
) -> None:
    """Start local SecureShip API service for VS Code Extension and Dashboard."""
    typer.secho(f"🛡️ Starting SecureShip Engine API on http://{host}:{port}", fg=typer.colors.CYAN, bold=True)
    try:
        uvicorn.run("secureship.server:app", host=host, port=port, reload=reload)
    except OSError as e:
        typer.secho(f"\n❌ Error: Unable to bind port {port} ({e}).", fg=typer.colors.RED, bold=True, err=True)
        typer.secho(f"The port might already be in use. Try: secureship serve --port {port + 1}\n", fg=typer.colors.YELLOW)
        raise typer.Exit(code=1)
    except Exception as e:
        typer.secho(f"\n❌ Unexpected error running API server: {e}\n", fg=typer.colors.RED, bold=True, err=True)
        raise typer.Exit(code=1)


@app.command()
def fix(
    path: str = typer.Argument(".", help="Target repository or file path to remediate"),
    dry_run: bool = typer.Option(False, "--dry-run", "-d", help="Preview unified diffs without modifying files"),
    apply: bool = typer.Option(False, "--apply", "-a", help="Apply code fixes directly in place"),
    rules: Optional[List[str]] = typer.Option(None, "--rule", "-r", help="Specific rule IDs to remediate (e.g. IAC-DOCKER-001, SAST-PY-006)"),
) -> None:
    """Automated security remediation engine: preview or apply safe fixes to source code and IaC configs."""
    target = Path(path).resolve()
    if not target.exists():
        typer.secho(f"Error: Target path '{path}' does not exist.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    should_apply = apply and not dry_run
    engine = RemediationEngine(str(target))
    typer.secho(f"\n🔧 SecureShip Auto-Remediation Engine ({'APPLY' if should_apply else 'DRY RUN'})", fg=typer.colors.CYAN, bold=True)
    typer.echo(f"   Target: {target}\n")

    res = engine.scan_and_remediate(target_dir=target, apply=should_apply, rules=rules)
    total_fixes = res["total_fixes"]
    remediated_files = res["remediated_files"]

    if total_fixes == 0:
        typer.secho("✅ No auto-remediable vulnerabilities detected. Codebase is in good shape!", fg=typer.colors.GREEN, bold=True)
        return

    # Print diffs
    for file_rel, diff_text in res["diffs"].items():
        typer.secho(f"─── Diff for {file_rel} ───", fg=typer.colors.YELLOW, bold=True)
        for line in diff_text.splitlines():
            if line.startswith("+"):
                typer.secho(line, fg=typer.colors.GREEN)
            elif line.startswith("-"):
                typer.secho(line, fg=typer.colors.RED)
            else:
                typer.echo(line)
        typer.echo()

    if should_apply:
        typer.secho(f"✅ Successfully applied {total_fixes} fix(es) across {remediated_files} file(s)!", fg=typer.colors.GREEN, bold=True)
    else:
        typer.secho(f"💡 Found {total_fixes} remediable issue(s) across {remediated_files} file(s).", fg=typer.colors.YELLOW, bold=True)
        typer.echo("   To apply these fixes automatically, re-run with: secureship fix --apply\n")


@app.command()
def sbom(
    path: str = typer.Argument(".", help="Target project directory"),
    format: str = typer.Option("cyclonedx", "--format", "-f", help="SBOM format: cyclonedx (CycloneDX 1.5 JSON) or spdx (SPDX 2.3 JSON)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save SBOM output to file path"),
) -> None:
    """Generate industry-standard Software Bill of Materials (SBOM) in CycloneDX v1.5 or SPDX v2.3 format."""
    target = Path(path).resolve()
    if not target.exists():
        typer.secho(f"Error: Target path '{path}' does not exist.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    gen = SBOMGenerator(str(target))
    components = gen.discover_components(target)

    # Render summary table
    table = Table(title=f"📦 SecureShip Software Bill of Materials (SBOM) — {target.name}", border_style="cyan")
    table.add_column("Package Name", style="bold white")
    table.add_column("Version", style="cyan")
    table.add_column("Ecosystem", style="yellow")
    table.add_column("Package URL (purl)", style="dim")

    for c in components[:30]:
        table.add_row(c.name, c.version, c.ecosystem, c.purl)

    console.print(table)
    if len(components) > 30:
        typer.echo(f"... and {len(components) - 30} more components.")

    typer.echo(f"\n📊 Total Dependencies Discovered: {len(components)}")

    sbom_data = gen.generate(target, format=format)
    json_output = json.dumps(sbom_data, indent=2)

    if output:
        out_file = Path(output).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(json_output, encoding="utf-8")
        typer.secho(f"✅ SBOM saved to: {out_file} ({format.upper()})", fg=typer.colors.GREEN, bold=True)
    else:
        typer.echo(f"💡 Use -o sbom.json to save full {format.upper()} document.")


@app.command()
def compliance(
    path: str = typer.Argument(".", help="Target project directory"),
    standard: str = typer.Option("owasp", "--standard", "-s", help="Benchmark: owasp (OWASP Top 10), pci (PCI-DSS), soc2 (SOC 2), nist (NIST SSDF)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save compliance report to file path"),
) -> None:
    """Map scan findings against international security standards (OWASP Top 10, PCI-DSS, SOC 2, NIST SSDF)."""
    target = Path(path).resolve()
    if not target.exists():
        typer.secho(f"Error: Target path '{path}' does not exist.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    engine = SecureShipEngine(str(target))
    result = engine.scan()

    comp_engine = ComplianceEngine()
    rep = comp_engine.evaluate(result.findings, standard=standard)

    table = Table(title=f"🛡️  Compliance Audit: {rep.standard_name}", border_style="cyan")
    table.add_column("Control ID", style="bold white", width=12)
    table.add_column("Control Name", style="white")
    table.add_column("Status", width=10)
    table.add_column("Violations", justify="right", width=12)

    for c in rep.controls:
        status_color = "[green]PASSED[/green]" if c.status == "PASSED" else "[bold red]VIOLATED[/bold red]"
        viol_count = str(len(c.violations)) if c.violations else "-"
        table.add_row(c.control_id, c.name, status_color, viol_count)

    console.print(table)

    score_color = typer.colors.GREEN if rep.compliance_score >= 80 else typer.colors.RED
    typer.secho(f"\n📊 Compliance Readiness Score: {rep.compliance_score}% ({rep.passed_controls}/{rep.total_controls} Controls Passed)\n", fg=score_color, bold=True)

    if output:
        out_file = Path(output).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(json.dumps(ComplianceEngine.report_to_dict(rep), indent=2), encoding="utf-8")
        typer.secho(f"✅ Compliance audit saved to: {out_file}", fg=typer.colors.GREEN)


@app.command(name="init-ci")
def init_ci(
    path: str = typer.Option(".", "--path", "-p", help="Target repository directory"),
    platform: Optional[str] = typer.Option(None, "--platform", help="Target CI platform: github, gitlab, azure, bitbucket, jenkins"),
    all_ci: bool = typer.Option(False, "--all", help="Generate all supported CI pipeline workflow templates"),
    overwrite: bool = typer.Option(False, "--overwrite", help="Overwrite existing pipeline configuration files"),
) -> None:
    """Generate automated Shift-Left DevSecOps CI/CD pipeline workflows for GitHub, GitLab, Azure, Bitbucket, or Jenkins."""
    target = Path(path).resolve()
    gen = CIGenerator(str(target))

    if all_ci:
        results = gen.generate_all(target_dir=target, overwrite=overwrite)
        for r in results:
            if r.get("created"):
                typer.secho(f"✅ Generated {r['platform'].upper()} workflow: {r['file_path']}", fg=typer.colors.GREEN)
            else:
                typer.secho(f"⚠️  Skipped {r['platform'].upper()} (exists): {r['file_path']}", fg=typer.colors.YELLOW)
        return

    plat = (platform or "github").lower()
    try:
        r = gen.generate(plat, target_dir=target, overwrite=overwrite)
        if r.get("created"):
            typer.secho(f"✅ Successfully created {plat.upper()} DevSecOps workflow into: {r['file_path']}", fg=typer.colors.GREEN, bold=True)
        else:
            typer.secho(f"⚠️  {r.get('reason')} Use --overwrite to replace it.", fg=typer.colors.YELLOW)
    except ValueError as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)


@app.command(name="threat-model")
def threat_model(
    path: str = typer.Argument(".", help="Target repository directory to analyze"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table or json"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save threat model report to file path"),
) -> None:
    """Generate STRIDE threat model matrix and attack surface analysis."""
    target = Path(path).resolve()
    engine = ThreatModelingEngine(str(target))
    rep = engine.analyze(target)

    if format.lower() == "json":
        data = ThreatModelingEngine.report_to_dict(rep)
        json_str = json.dumps(data, indent=2)
        if output:
            Path(output).write_text(json_str, encoding="utf-8")
            typer.secho(f"✅ Threat model report saved to: {output}", fg=typer.colors.GREEN)
        else:
            print(json_str)
        return

    # Render rich summary
    typer.secho(f"\n🧠 STRIDE Threat Model & Attack Surface: {rep.project_name}", fg=typer.colors.CYAN, bold=True)
    typer.echo(f"   • Discovered Entrypoints:   {len(rep.entrypoints)}")
    typer.echo(f"   • Connected Datastores:     {', '.join(rep.datastores) if rep.datastores else 'None detected'}")
    typer.echo(f"   • Exposed Network Ports:    {', '.join(rep.exposed_ports) if rep.exposed_ports else 'None exposed'}\n")

    table = Table(title="STRIDE Threat Vector Matrix", border_style="cyan")
    table.add_column("Category", style="bold yellow", width=22)
    table.add_column("Threat Title", style="bold white")
    table.add_column("Risk", width=10)
    table.add_column("Affected Asset", style="cyan")

    for t in rep.threats:
        risk_color = "[bold red]CRITICAL[/bold red]" if t.risk_level == "CRITICAL" else "[red]HIGH[/red]" if t.risk_level == "HIGH" else "[yellow]MEDIUM[/yellow]"
        table.add_row(t.category, t.title, risk_color, t.affected_asset)

    console.print(table)
    typer.secho(f"\n📊 Threat Summary: {rep.total_threats} Total Threat Vectors ({rep.high_risk_count} High/Critical Risk)\n", fg=typer.colors.YELLOW if rep.high_risk_count > 0 else typer.colors.GREEN, bold=True)

    if output:
        out_file = Path(output).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(json.dumps(ThreatModelingEngine.report_to_dict(rep), indent=2), encoding="utf-8")
        typer.secho(f"✅ Threat model saved to: {out_file}", fg=typer.colors.GREEN)


@app.command(name="git-history")
def git_history(
    path: str = typer.Argument(".", help="Target Git repository directory"),
    commits: int = typer.Option(50, "--commits", "-n", help="Number of historical commits to inspect"),
    branch: Optional[str] = typer.Option(None, "--branch", "-b", help="Specific Git branch to inspect"),
) -> None:
    """Scan Git commit history for leaked secrets, API keys, and passwords."""
    target = Path(path).resolve()
    scanner = GitHistoryScanner(str(target))

    typer.secho(f"\n🔍 SecureShip: Auditing Git commit history ({commits} commits)...", fg=typer.colors.CYAN, bold=True)
    findings = scanner.scan_history(repo_dir=target, max_commits=commits, branch=branch)

    if not findings:
        typer.secho(f"✅ No historical secrets or credentials detected across the last {commits} commits!", fg=typer.colors.GREEN, bold=True)
        return

    table = Table(title="⚠️  Detected Historical Secret Leaks in Git Log", border_style="red")
    table.add_column("Commit", style="bold yellow", width=10)
    table.add_column("Author", style="white", width=18)
    table.add_column("Rule & Type", style="cyan")
    table.add_column("File & Line", style="white")
    table.add_column("Redacted Secret", style="bold red")

    for f in findings:
        table.add_row(f.commit_sha, f.author[:18], f"{f.rule_id}\n{f.secret_type}", f"{f.file_path}:{f.line_number}", f.redacted_secret[:30])

    console.print(table)
    typer.secho(f"\n❌ [CRITICAL]: Found {len(findings)} leaked secret(s) in commit history!", fg=typer.colors.RED, bold=True)
    typer.echo("Remediation: Purge credentials from git history using 'git filter-repo' or BFG Repo-Cleaner:")
    for f in findings[:3]:
        typer.echo(f"   • {f.remediation_cmd}")
    typer.echo()


@app.command()
def vault(
    path: str = typer.Argument(".", help="Target repository directory"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Directory to export sanitized .env.example, vault.json, and k8s secrets"),
) -> None:
    """Extract hardcoded secrets and generate .env.example, HashiCorp Vault, and K8s Secret payloads."""
    target = Path(path).resolve()
    engine = SecureShipEngine(str(target), categories=[FindingCategory.SECRETS])
    result = engine.scan()

    migrator = VaultMigrator(str(target))
    data = migrator.export(result.findings, out_dir=Path(output) if output else target)

    typer.secho(f"\n🔐 SecureShip Secret Vault & Environment Migrator", fg=typer.colors.CYAN, bold=True)
    typer.echo(f"   Target: {target}")
    typer.echo(f"   Secrets Extracted: {data['secret_count']}\n")

    if data["secret_count"] == 0:
        typer.secho("✅ No hardcoded secrets detected to migrate.", fg=typer.colors.GREEN)
        return

    if output:
        out_dir = Path(output).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / ".env.example").write_text(data["env_example"], encoding="utf-8")
        (out_dir / "vault-secrets.json").write_text(json.dumps(data["vault_json"], indent=2), encoding="utf-8")
        (out_dir / "k8s-secret.yaml").write_text(data["k8s_yaml"], encoding="utf-8")
        typer.secho(f"✅ Generated vault artifacts in: {out_dir}", fg=typer.colors.GREEN, bold=True)
        typer.echo("   • .env.example (Sanitized 12-factor template)")
        typer.echo("   • vault-secrets.json (HashiCorp Vault KV payload)")
        typer.echo("   • k8s-secret.yaml (Kubernetes Secret manifest)")
    else:
        typer.secho("─── Generated .env.example ───", fg=typer.colors.YELLOW)
        print(data["env_example"])
        typer.echo("💡 Pass -o ./vault-export to save HashiCorp Vault JSON and K8s YAML manifests.\n")


@app.command()
def badge(
    path: str = typer.Argument(".", help="Target repository directory"),
    output: str = typer.Option("security-badge.svg", "--output", "-o", help="Output SVG badge file path"),
) -> None:
    """Generate dynamic Shields-compliant SVG security status badge for repository README."""
    target = Path(path).resolve()
    engine = SecureShipEngine(str(target))
    res = engine.scan()

    svg_content = BadgeGenerator.generate_svg(res.summary.security_score, res.summary.ship_status.value)
    out_file = Path(output).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(svg_content, encoding="utf-8")

    score_color = typer.colors.GREEN if res.summary.security_score >= 80 else typer.colors.RED
    typer.secho(f"\n🛡️  Generated Security Badge: {out_file}", fg=score_color, bold=True)
    typer.echo(f"   Score: {res.summary.security_score}/100 | Status: {res.summary.ship_status.value}")
    typer.echo(f"   Embed in README.md: ![{res.summary.ship_status.value}]({output})\n")


@app.command()
def container(
    path: str = typer.Argument(".", help="Target Dockerfile or directory containing Dockerfiles"),
) -> None:
    """Deep container security inspection: multi-stage builds, SUID permissions, ARG secrets, and cache bloat."""
    target = Path(path).resolve()
    auditor = ContainerAuditor(str(target))

    if target.is_file():
        content = target.read_text(encoding="utf-8", errors="replace")
        findings = auditor.audit_file(target, target.name, content)
    else:
        findings = auditor.audit_directory(target)

    typer.secho(f"\n🐳 SecureShip Container Image Inspector: {target.name}", fg=typer.colors.CYAN, bold=True)

    if not findings:
        typer.secho("✅ Container configurations adhere to production hardening best practices!", fg=typer.colors.GREEN, bold=True)
        return

    table = Table(title="Container Security Hardening Findings", border_style="cyan")
    table.add_column("Rule ID", style="bold white", width=15)
    table.add_column("Title", style="white")
    table.add_column("Severity", width=10)
    table.add_column("File:Line", style="cyan")

    for f in findings:
        sev_color = "[red]HIGH[/red]" if f.severity == "HIGH" else "[yellow]MEDIUM[/yellow]" if f.severity == "MEDIUM" else "[dim]LOW[/dim]"
        table.add_row(f.rule_id, f.title, sev_color, f"{f.file_path}:{f.line_number}")

    console.print(table)
    typer.secho(f"\n💡 Detected {len(findings)} container hardening recommendation(s).\n", fg=typer.colors.YELLOW)


@app.command()
def license(
    path: str = typer.Argument(".", help="Target repository directory"),
    policy: str = typer.Option("commercial", "--policy", "-p", help="Policy: permissive, commercial, or strict"),
    format: str = typer.Option("rich", "--format", "-f", help="Output format: rich or json"),
) -> None:
    """Audit third-party dependencies for Open-Source License compliance and legal risks."""
    target = Path(path).resolve()
    auditor = LicenseAuditor(str(target))
    data = auditor.audit(policy=policy)

    if format.lower() == "json":
        typer.echo(json.dumps(data, indent=2))
        return

    typer.secho(f"\n📜 SecureShip Open-Source License Compliance: {target.name}", fg=typer.colors.CYAN, bold=True)
    typer.echo(f"   Target: {target}")
    typer.echo(f"   Policy: {policy.upper()} (Score: {data['compliance_score']}/100)")
    typer.echo(f"   Packages Audited: {data['total_packages']}  |  Violations: {data['violations_count']}\n")

    table = Table(title=f"License Compliance Audit ({policy.upper()} Policy)", border_style="cyan")
    table.add_column("Package", style="bold white")
    table.add_column("Version", width=12)
    table.add_column("License", style="cyan", width=16)
    table.add_column("Risk Tier", width=18)
    table.add_column("Status", width=14)

    for p in data["packages"]:
        status = "[green]COMPLIANT[/green]" if p["compliant"] else "[red]VIOLATION[/red]"
        risk_color = "[red]STRONG COPYLEFT[/red]" if p["risk"] == "STRONG_COPYLEFT" else "[green]PERMISSIVE[/green]" if p["risk"] == "PERMISSIVE" else "[yellow]NOTICE[/yellow]"
        table.add_row(p["package"], p["version"], p["license"], risk_color, status)

    console.print(table)
    if data["violations"]:
        typer.secho(f"\n❌ [LEGAL RISK]: Detected {len(data['violations'])} license policy violation(s)!", fg=typer.colors.RED, bold=True)
        for v in data["violations"][:3]:
            typer.echo(f"   • {v['package']} ({v['license']}): {v['remediation']}")
        typer.echo()
    else:
        typer.secho("\n✅ All third-party software dependencies comply with license risk policy!\n", fg=typer.colors.GREEN, bold=True)


@app.command()
def taint(
    path: str = typer.Argument(".", help="Target repository directory"),
    format: str = typer.Option("rich", "--format", "-f", help="Output format: rich or json"),
) -> None:
    """Perform static taint analysis (source-to-sink dataflow tracking) on Python and JS."""
    target = Path(path).resolve()
    analyzer = TaintAnalyzer(str(target))
    data = analyzer.analyze()

    if format.lower() == "json":
        typer.echo(json.dumps(data, indent=2))
        return

    typer.secho(f"\n🌊 SecureShip Static Taint Analysis: {target.name}", fg=typer.colors.CYAN, bold=True)
    typer.echo(f"   Target: {target}")
    typer.echo(f"   Status: {data['status']}  |  Taint Findings: {data['total_taint_findings']}\n")

    if not data["findings"]:
        typer.secho("✅ No unsanitized source-to-sink injection flows detected!", fg=typer.colors.GREEN, bold=True)
        return

    table = Table(title="Untrusted Dataflow (Source -> Sink) Traces", border_style="red")
    table.add_column("Sink Vulnerability", style="bold red", width=20)
    table.add_column("Taint Call Path", style="yellow")
    table.add_column("File:Line", style="cyan", width=25)

    for f in data["findings"]:
        table.add_row(f["sink_type"], f["call_path"], f"{f['file']}:{f['sink_line']}")

    console.print(table)
    typer.secho(f"\n🚨 Detected {len(data['findings'])} dangerous unsanitized taint flow(s)!\n", fg=typer.colors.RED)


@app.command("ci-audit")
def ci_audit(
    path: str = typer.Argument(".", help="Target repository directory"),
    format: str = typer.Option("rich", "--format", "-f", help="Output format: rich or json"),
) -> None:
    """Audit CI/CD pipeline definitions (GitHub Actions, GitLab CI) for supply-chain risks."""
    target = Path(path).resolve()
    auditor = CICDAuditor(str(target))
    data = auditor.audit()

    if format.lower() == "json":
        typer.echo(json.dumps(data, indent=2))
        return

    typer.secho(f"\n⚙️ SecureShip CI/CD Supply Chain Pipeline Auditor", fg=typer.colors.CYAN, bold=True)
    typer.echo(f"   Target: {target}")
    typer.echo(f"   Findings: {data['total_findings']}\n")

    if not data["findings"]:
        typer.secho("✅ CI/CD workflows adhere to pipeline hardening standards (pinned SHAs, least privilege)!", fg=typer.colors.GREEN, bold=True)
        return

    table = Table(title="CI/CD Pipeline Security Findings", border_style="cyan")
    table.add_column("Rule ID", style="bold white", width=14)
    table.add_column("Title", style="white")
    table.add_column("Severity", width=10)
    table.add_column("File:Line", style="cyan")

    for f in data["findings"]:
        sev_color = "[red]CRITICAL[/red]" if f["severity"] == "CRITICAL" else "[yellow]HIGH[/yellow]" if f["severity"] == "HIGH" else "[dim]MEDIUM[/dim]"
        table.add_row(f["rule_id"], f["title"], sev_color, f"{f['file']}:{f['line']}")

    console.print(table)
    typer.secho(f"\n💡 Found {len(data['findings'])} CI/CD supply-chain security recommendations.\n", fg=typer.colors.YELLOW)


@app.command()
def version() -> None:
    """Print SecureShip version."""
    typer.echo("SecureShip v1.0.0 — Shift-Left DevSecOps Gate")


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    update: bool = typer.Option(False, "--update", help="Fetch & apply latest updates from GitHub"),
    version: bool = typer.Option(False, "--version", "-v", help="Show SecureShip version and exit"),
    modify_score: Optional[str] = typer.Option(
        None,
        "--modify-score",
        "--modify_score",
        "--min-score",
        "--modify-score-to",
        help="Quick scan with custom score threshold (e.g. 50, 65, 75, 80, 90 or 65%)",
    ),
    strict_sca: bool = typer.Option(
        False, "--strict-sca", "--strict-SCA", help="Quick scan with strict zero-tolerance SCA policy"
    ),
    strict_iac: bool = typer.Option(
        False,
        "--strict-iac",
        "--strict-IAC",
        "--strict-iat",
        "--strict-IAT",
        help="Quick scan with strict zero-tolerance IaC policy",
    ),
    strict_sec: bool = typer.Option(
        False, "--strict-sec", "--strict-SEC", help="Quick scan with strict zero-tolerance Secret policy"
    ),
    strict_sast: bool = typer.Option(
        False, "--strict-sast", "--strict-SAST", help="Quick scan with strict zero-tolerance SAST policy"
    ),
    confidence: Optional[str] = typer.Option(
        None, "--confidence", "--min-confidence", "--accuracy", help="Quick scan with accuracy filter: high, medium, low"
    ),
) -> None:
    """SecureShip root options handler."""
    if version:
        typer.echo("SecureShip v1.0.0 — Shift-Left DevSecOps Gate")
        raise typer.Exit(code=0)
    if update:
        code = run_self_update()
        raise typer.Exit(code=code)
    if ctx.invoked_subcommand is None:
        if (
            modify_score is not None
            or strict_sca
            or strict_iac
            or strict_sec
            or strict_sast
            or confidence is not None
        ):
            # Run scan directly with specified flags on current directory
            scan(
                path=".",
                min_score=modify_score,
                strict_sca=strict_sca,
                strict_iac=strict_iac,
                strict_sec=strict_sec,
                strict_sast=strict_sast,
                confidence=confidence,
            )
            raise typer.Exit(code=0)
        typer.echo(ctx.get_help())
        raise typer.Exit(code=0)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
