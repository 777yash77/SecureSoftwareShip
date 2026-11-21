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
from secureship.config import load_config, save_config
from secureship.db import HistoryDB
from secureship.models import Finding, FindingCategory, Severity, ShipStatus
from secureship.reporters.certificate_reporter import render_certificate_report
from secureship.reporters.console_reporter import render_console_report
from secureship.reporters.html_reporter import render_html_report
from secureship.reporters.json_reporter import render_json_report
from secureship.reporters.sarif_reporter import render_sarif_report
from secureship.scanner import SecureShipEngine
from secureship.updater import run_self_update

console = Console()

CLI_DESCRIPTION = """[bold cyan]🛡️ SecureShip[/bold cyan] — [bold white]Shift-Left DevSecOps Security Gate & Scanner Platform[/bold white]

Audit and evaluate codebases for hardcoded secrets, AST-based SAST code flaws, vulnerable dependencies (SCA), and Docker / K8s misconfigurations (IaC) directly in your terminal before shipping to production.

[bold yellow]QUICK EXAMPLES:[/bold yellow]
  [cyan]secureship scan[/cyan]                               Scan current folder (all categories)
  [cyan]secureship scan ./my-project[/cyan]                  Scan a specific project folder
  [cyan]secureship scan --modify-score <N>[/cyan]             Set custom passing score threshold to N% (e.g. 50, 65, 75, 85, 90; default: 80)
  [cyan]secureship scan --modify-score 70%[/cyan]             Supports percentages with or without '%' symbol
  [cyan]secureship scan --strict-sca[/cyan]                   Block push if ANY dependency vulnerability (even with 99 score)
  [cyan]secureship scan --strict-iac[/cyan]                   Block push if ANY Docker/K8s misconfiguration is detected
  [cyan]secureship scan --strict-sec[/cyan]                   Block push if ANY hardcoded secret/token is detected
  [cyan]secureship scan --strict-sast[/cyan]                  Block push if ANY SAST code vulnerability is detected
  [cyan]secureship scan --sec[/cyan]                         Scan [bold red]ONLY Secrets[/bold red] (AWS keys, GitHub tokens, .env)
  [cyan]secureship scan --iac[/cyan]                         Scan [bold red]ONLY Container & IaC[/bold red] (Docker, Compose, K8s)
  [cyan]secureship scan --sast[/cyan]                        Scan [bold red]ONLY SAST code flaws[/bold red] (SQLi, XSS, RCE, MD5)
  [cyan]secureship scan --sca[/cyan]                         Scan [bold red]ONLY Dependencies[/bold red] (CVEs in package.json, requirements)
  [cyan]secureship scan --fail-on high[/cyan]                Enforce Shift-Left Gate (exit 1 if High/Critical)
  [cyan]secureship scan --ignore[/cyan]                      [bold yellow]Emergency Override:[/bold yellow] ignore quality gate for git push
  [cyan]secureship scan --format html -o report.html[/cyan]  Generate printable standalone HTML report
  [cyan]secureship scan --staged[/cyan]                      Pre-commit mode: scan only Git staged lines
  [cyan]secureship config --min-score 70[/cyan]              Persist custom 70% threshold into .secureshiprc for Git hooks
  [cyan]secureship rules[/cyan]                              List all built-in security detection rules
  [cyan]secureship explain SAST-PY-001[/cyan]                Get AI / Expert exploit analysis & fix
  [cyan]secureship history[/cyan]                            View previous scans & security score trends
  [cyan]secureship certificate ./my-project[/cyan]           Generate executive Ship Readiness Certificate
  [cyan]secureship install-hook[/cyan]                       Install automated Git [bold green]pre-commit[/bold green] & [bold green]pre-push[/bold green] gates
  [cyan]secureship bypass --push[/cyan]                       Authorize emergency bypass token & execute git push
  [cyan]secureship update[/cyan]                             Fetch & install latest software updates from GitHub
  [cyan]secureship update --token ghp_...[/cyan]            Fetch update from private GitHub repository with PAT
  [cyan]secureship update --check[/cyan]                     Check for remote updates without applying
  [cyan]secureship serve --port 8787[/cyan]                  Launch Web Security Dashboard on port 8787
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

    strict_to_pass = list(set(strict_cat_enums)) if strict_cat_enums else None
    parsed_min_score = parse_score_threshold(min_score)
    engine = SecureShipEngine(target_path=str(target_path), categories=categories_to_pass)

    if staged:
        result = engine.scan_staged(
            min_severity=min_sev_enum,
            min_score=parsed_min_score,
            strict_categories=strict_to_pass,
        )
    else:
        result = engine.scan(
            min_severity=min_sev_enum,
            min_score=parsed_min_score,
            strict_categories=strict_to_pass,
        )

    # Render according to requested format
    fmt = format.lower()
    report_text = ""

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
    show: bool = typer.Option(False, "--show", "-s", help="Display current quality gate configuration"),
) -> None:
    """Configure or view repository quality gate rules (.secureshiprc)."""
    target = Path(path).resolve()
    current_cfg = load_config(target)

    no_args = min_score is None and not strict_sca and not strict_iac and not strict_sec and not strict_sast and github_token is None
    if show or no_args:
        cfg_file = target / ".secureshiprc"
        typer.secho(f"\n⚙️  SecureShip Quality Gate Configuration ({cfg_file.name if cfg_file.exists() else 'defaults'}):", fg=typer.colors.CYAN, bold=True)
        typer.echo(f"   • Passing Score (min_score): {current_cfg.get('min_score', 80)} / 100")
        stricts = current_cfg.get("strict_categories", [])
        typer.echo(f"   • Strict Blocker Categories:  {', '.join(stricts) if stricts else 'None (default: Critical severity blocks)'}")
        has_token = bool(current_cfg.get("github_token"))
        typer.echo(f"   • GitHub Private Token:       {'Configured (masked)' if has_token else 'Not set'}\n")
        return

    updates: dict = {}
    parsed_score = parse_score_threshold(min_score)
    if parsed_score is not None:
        updates["min_score"] = parsed_score

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
    saved_path = save_config(target, updates)

    typer.secho(f"\n✅ Updated SecureShip quality gate configuration in {saved_path}:", fg=typer.colors.GREEN, bold=True)
    if "min_score" in updates:
        typer.echo(f"   • Passing Score Threshold set to: {updates['min_score']}%")
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
        ("SAST-PY-001", "SAST", "Python SQL", "SQL Injection via dynamic f-string or string formatting in execute()", "CWE-89 / A03:2021"),
        ("SAST-PY-002", "SAST", "Python OS", "Command Injection via os.system() with dynamic input", "CWE-78 / A03:2021"),
        ("SAST-PY-003", "SAST", "Python Subprocess", "Command Injection via subprocess with shell=True", "CWE-78 / A03:2021"),
        ("SAST-PY-004", "SAST", "Python Pickle", "Arbitrary Code Execution via untrusted pickle.loads deserialization", "CWE-502 / A08:2021"),
        ("SAST-PY-005", "SAST", "Python YAML", "Unsafe YAML loading via yaml.load() without SafeLoader", "CWE-502 / A08:2021"),
        ("SAST-PY-006", "SAST", "Python Code", "Arbitrary Code Execution via eval() or exec()", "CWE-95 / A03:2021"),
        ("SAST-PY-007", "SAST", "Python Crypto", "Weak cryptographic hash algorithm (MD5 / SHA1)", "CWE-328 / A02:2021"),
        ("SAST-PY-008", "SAST", "Python Flask/Django", "Production DEBUG mode enabled (DEBUG = True)", "CWE-489 / A05:2021"),
        ("SAST-PY-009", "SAST", "Python Network", "Service bound to all network interfaces (0.0.0.0)", "CWE-1327 / A05:2021"),
        ("SAST-JS-001", "SAST", "JavaScript", "Code injection via eval()", "CWE-95 / A03:2021"),
        ("SAST-JS-002", "SAST", "JavaScript DOM", "Cross-Site Scripting (XSS) via unescaped innerHTML", "CWE-79 / A03:2021"),
        ("SAST-JS-003", "SAST", "JavaScript SQL", "SQL Injection via string concatenation in query()", "CWE-89 / A03:2021"),
        ("SAST-JS-004", "SAST", "Node.js ChildProc", "Command Injection via child_process.exec()", "CWE-78 / A03:2021"),
        ("SAST-JS-005", "SAST", "Node.js TLS", "Disabled TLS verification (rejectUnauthorized: false)", "CWE-295 / A02:2021"),
        ("SAST-JS-006", "SAST", "Node.js JWT", "Hardcoded JWT secret or weak signature key", "CWE-798 / A07:2021"),
        ("IAC-DOCKER-001", "IAC", "Dockerfile", "Container running as root (missing USER nonroot directive)", "CWE-250 / A05:2021"),
        ("IAC-DOCKER-002", "IAC", "Dockerfile", "Unpinned base image tag (:latest or untagged)", "CWE-1188 / A05:2021"),
        ("IAC-DOCKER-003", "IAC", "Dockerfile", "Secrets embedded in ENV or ARG build parameters", "CWE-798 / A07:2021"),
        ("IAC-COMPOSE-001", "IAC", "Docker Compose", "Service running with privileged: true (host takeover risk)", "CWE-250 / A05:2021"),
        ("IAC-COMPOSE-002", "IAC", "Docker Compose", "Sensitive DB port (5432, 3306, 6379) bound to 0.0.0.0", "CWE-668 / A05:2021"),
        ("IAC-K8S-001", "IAC", "Kubernetes", "Container missing CPU / Memory resource limits (DoS risk)", "CWE-770 / A05:2021"),
        ("IAC-K8S-002", "IAC", "Kubernetes", "Pod running with privileged securityContext (node escape)", "CWE-250 / A05:2021"),
        ("SCA-CVE20208203", "SCA", "npm:lodash", "Prototype Pollution in lodash < 4.17.21 (CVE-2020-8203)", "CWE-1321 / A06:2021"),
        ("SCA-CVE202223529", "SCA", "npm:jsonwebtoken", "Remote Code Execution in jsonwebtoken < 9.0.0 (CVE-2022-23529)", "CWE-502 / A06:2021"),
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
    db = HistoryDB()
    recent = db.get_recent_scans(limit=limit)

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

    engine = SecureShipEngine(target_path=str(target_path))
    result = engine.scan()
    cert_html = render_certificate_report(result)

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

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    # 1. Pre-Commit Hook (Scans staged changes fast)
    commit_hook = hooks_dir / "pre-commit"
    commit_content = """#!/usr/bin/env bash
# SecureShip Git Pre-Commit Hook (Automated Shift-Left Security Gate)
echo "🛡️  SecureShip: Scanning staged changes before commit..."

if ! command -v secureship &> /dev/null; then
    echo "⚠️  SecureShip CLI not found in PATH. Skipping hook."
    exit 0
fi

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
        "echo 🛡️  SecureShip: Scanning staged changes before commit...\n"
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
echo "🛡️  SecureShip: Running Pre-Push Security Audit & Ship-Readiness Check..."

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
        "echo 🛡️  SecureShip: Running Pre-Push Security Audit...\n"
        "if exist \".git\\secureship-bypass.token\" (\n"
        "    echo ⚠️  [WARNING] SecureShip: Emergency bypass active. Gate overridden.\n"
        "    del \".git\\secureship-bypass.token\" >nul 2>&1\n"
        "    exit /b 0\n"
        ")\n"
        "if \"%SECURESHIP_BYPASS%\"==\"1\" exit /b 0\n"
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
    try:
        for h in [commit_hook, push_hook]:
            current_stat = os.stat(h)
            os.chmod(h, current_stat.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass

    typer.secho(f"✅ SecureShip Git security gates successfully installed into: {hooks_dir}", fg=typer.colors.GREEN, bold=True)
    typer.secho("🛡️  Gate 1: pre-commit  (blocks committing secrets/vulnerabilities)", fg=typer.colors.CYAN)
    typer.secho("🛡️  Gate 2: pre-push    (blocks pushing unapproved code to GitHub)", fg=typer.colors.CYAN)
    typer.secho("💡 Emergency Override: 'secureship bypass --push' or 'git push --no-verify'", fg=typer.colors.WHITE)


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

    token_file = git_dir / "secureship-bypass.token"
    token_data = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "reason": reason,
        "author": os.environ.get("USERNAME") or os.environ.get("USER") or "developer",
    }
    token_file.write_text(json.dumps(token_data, indent=2), encoding="utf-8")

    typer.secho("\n⚠️  [SECURESHIP EMERGENCY BYPASS ARMED]", fg=typer.colors.YELLOW, bold=True)
    typer.secho(f"Reason:  {reason}", fg=typer.colors.WHITE)
    typer.secho(f"Author:  {token_data['author']}", fg=typer.colors.WHITE)
    typer.secho("Status:  Authorized for the next 'git push'.", fg=typer.colors.CYAN)
    typer.secho("Audit:   Security event logged for compliance verification.\n", fg=typer.colors.DIM)

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


@app.command()
def version() -> None:
    """Print SecureShip version."""
    typer.echo("SecureShip v1.0.0 — Shift-Left DevSecOps Gate")


@app.callback()
def main_callback(
    update: bool = typer.Option(False, "--update", help="Fetch & apply latest updates from GitHub"),
    version: bool = typer.Option(False, "--version", "-v", help="Show SecureShip version and exit"),
) -> None:
    """SecureShip root options handler."""
    if version:
        typer.echo("SecureShip v1.0.0 — Shift-Left DevSecOps Gate")
        raise typer.Exit(code=0)
    if update:
        code = run_self_update()
        raise typer.Exit(code=code)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
