from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from secureship.models import ScanResult, Severity, ShipStatus


console = Console()


def render_console_report(result: ScanResult) -> None:
    """Renders a polished, cybersecurity-themed console report using Rich."""
    summary = result.summary

    # Status color & styling
    status_color = "green" if summary.ship_status == ShipStatus.READY_TO_SHIP else (
        "red" if summary.ship_status == ShipStatus.BLOCKED else "yellow"
    )

    banner_text = Text()
    banner_text.append("🛡️  SECURESHIP ", style="bold cyan")
    banner_text.append("— Shift-Left DevSecOps Gate\n", style="bold white")
    banner_text.append(f"Target: {result.target_path}\n", style="dim")
    banner_text.append(f"Ship Status: ", style="bold white")
    banner_text.append(f"[{summary.ship_status.value}]", style=f"bold {status_color}")
    banner_text.append(f"  |  Security Score: ", style="bold white")
    banner_text.append(f"{summary.security_score}/100", style=f"bold {status_color}")
    banner_text.append(f" (Min Required: {summary.min_score})", style="dim")
    if summary.strict_violations:
        banner_text.append(f"\nStrict Policy Violation: {', '.join(summary.strict_violations)}", style="bold red")

    console.print(Panel(banner_text, border_style=status_color, title="Scan Summary", title_align="left"))

    # Summary Metrics Table
    sum_table = Table(title="Security Metrics & Severity Breakdown", show_header=True, header_style="bold magenta")
    sum_table.add_column("Metric", style="white")
    sum_table.add_column("Value", style="bold")

    sum_table.add_row("Security Score", f"[{status_color}]{summary.security_score} / 100[/]")
    sum_table.add_row("Passing Gate Threshold", f"{summary.min_score} / 100")
    if summary.strict_violations:
        sum_table.add_row("Strict Category Gate", f"[bold red]BLOCKED: {', '.join(summary.strict_violations)}[/]")
    sum_table.add_row("Ship-Readiness Verdict", f"[{status_color}]{summary.ship_status.value}[/]")
    sum_table.add_row("Total Findings", str(summary.total_findings))
    sum_table.add_row("CRITICAL Severity", f"[bold red]{summary.critical_count}[/]" if summary.critical_count else "0")
    sum_table.add_row("HIGH Severity", f"[red]{summary.high_count}[/]" if summary.high_count else "0")
    sum_table.add_row("MEDIUM Severity", f"[yellow]{summary.medium_count}[/]" if summary.medium_count else "0")
    sum_table.add_row("LOW Severity", f"[cyan]{summary.low_count}[/]" if summary.low_count else "0")
    sum_table.add_row("Files Scanned", str(summary.files_scanned))
    sum_table.add_row("Lines Scanned", str(summary.lines_scanned))
    sum_table.add_row("Scan Duration", f"{summary.scan_duration_ms:.2f} ms")

    console.print(sum_table)

    if not result.findings:
        console.print("\n[bold green]✅ No security vulnerabilities detected. Project is ready to ship![/]\n")
        return

    # Findings Detail Table
    find_table = Table(title=f"Detailed Findings ({len(result.findings)})", show_header=True, header_style="bold blue")
    find_table.add_column("Severity", justify="center", style="bold", width=10)
    find_table.add_column("Rule ID", style="cyan", width=14)
    find_table.add_column("Title & Description", style="white")
    find_table.add_column("Location", style="yellow")
    find_table.add_column("CWE / OWASP", style="dim", width=22)

    sev_styles = {
        Severity.CRITICAL: "bold white on red",
        Severity.HIGH: "bold red",
        Severity.MEDIUM: "bold yellow",
        Severity.LOW: "bold cyan",
    }

    for f in result.findings:
        sev_style = sev_styles.get(f.severity, "white")
        location = f"{f.file_path}:{f.line_start}"
        details = f"[bold]{f.title}[/]\n{f.description}\n[dim italic]Remediation: {f.remediation}[/]"
        cwe_owasp = f"{f.cwe_id}\n{f.owasp_category}"

        find_table.add_row(
            Text(f.severity.value, style=sev_style),
            f.rule_id,
            details,
            location,
            cwe_owasp,
        )

    console.print(find_table)
    console.print("")
