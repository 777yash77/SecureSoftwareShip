from __future__ import annotations

import html
from secureship.models import ScanResult, Severity, ShipStatus


def render_html_report(result: ScanResult) -> str:
    """Generates an elegant, self-contained HTML report with dark cybersecurity theme."""
    summary = result.summary
    status_bg = "#10b981" if summary.ship_status == ShipStatus.READY_TO_SHIP else (
        "#ef4444" if summary.ship_status == ShipStatus.BLOCKED else "#f59e0b"
    )
    status_glow = "rgba(16, 185, 129, 0.2)" if summary.ship_status == ShipStatus.READY_TO_SHIP else (
        "rgba(239, 68, 68, 0.2)" if summary.ship_status == ShipStatus.BLOCKED else "rgba(245, 158, 11, 0.2)"
    )

    findings_rows = []
    for f in result.findings:
        sev_color = {
            Severity.CRITICAL: "#ef4444",
            Severity.HIGH: "#f97316",
            Severity.MEDIUM: "#eab308",
            Severity.LOW: "#06b6d4",
        }.get(f.severity, "#94a3b8")

        snippet_html = html.escape(f.code_snippet)
        remediation_html = html.escape(f.remediation)
        fix_hint_html = html.escape(f.auto_fix_hint or "")

        row = f"""
        <tr class="finding-row" data-severity="{f.severity.value}" data-category="{f.category.value}">
            <td style="white-space: nowrap;">
                <span class="badge" style="background: {sev_color}22; color: {sev_color}; border: 1px solid {sev_color}66;">
                    {f.severity.value}
                </span>
            </td>
            <td><code class="rule-id">{html.escape(f.rule_id)}</code></td>
            <td>
                <strong>{html.escape(f.title)}</strong>
                <p class="desc">{html.escape(f.description)}</p>
                <div class="code-box">
                    <div class="code-header">
                        <span>{html.escape(f.file_path)}:{f.line_start}</span>
                        <button class="copy-btn" onclick="navigator.clipboard.writeText('{snippet_html}')">Copy Snippet</button>
                    </div>
                    <pre><code>{snippet_html}</code></pre>
                </div>
                <div class="remediation-box">
                    <span class="rem-title">💡 Remediation:</span> {remediation_html}
                    {f'<div class="fix-hint"><strong>Auto-Fix Hint:</strong> <code>{fix_hint_html}</code></div>' if fix_hint_html else ''}
                </div>
            </td>
            <td>
                <span class="meta-tag">{html.escape(f.cwe_id)}</span><br>
                <span class="meta-tag" style="font-size: 11px;">{html.escape(f.owasp_category)}</span>
            </td>
        </tr>
        """
        findings_rows.append(row)

    findings_table_body = "\n".join(findings_rows) if findings_rows else """
    <tr><td colspan="4" style="text-align: center; padding: 40px; color: #10b981;">
        ✨ No vulnerabilities found! Everything is secure.
    </td></tr>
    """

    # OWASP distribution items
    owasp_items = "".join(
        f'<div class="owasp-item"><span>{html.escape(k)}</span><strong>{v}</strong></div>'
        for k, v in summary.owasp_breakdown.items()
    ) or "<p style='color: #64748b;'>No OWASP violations detected.</p>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureShip Security Report — {html.escape(summary.ship_status.value)}</title>
    <style>
        :root {{
            --bg-dark: #090d16;
            --card-bg: #111827;
            --border: #1f293d;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-dark);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            padding: 32px;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 24px;
            margin-bottom: 32px;
        }}
        .brand {{ display: flex; align-items: center; gap: 14px; }}
        .brand-icon {{ font-size: 32px; }}
        .brand-title h1 {{ font-size: 24px; font-weight: 700; letter-spacing: -0.5px; }}
        .brand-title p {{ color: var(--text-muted); font-size: 13px; }}
        .verdict-banner {{
            display: inline-flex;
            align-items: center;
            gap: 12px;
            padding: 10px 24px;
            border-radius: 9999px;
            background: {status_glow};
            border: 2px solid {status_bg};
            box-shadow: 0 0 20px {status_glow};
        }}
        .verdict-text {{ font-size: 18px; font-weight: 800; color: {status_bg}; letter-spacing: 0.5px; }}
        
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .kpi-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
        }}
        .kpi-label {{ color: var(--text-muted); font-size: 12px; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; }}
        .kpi-value {{ font-size: 28px; font-weight: 800; margin-top: 6px; }}
        
        .grid-two {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 24px;
            margin-bottom: 32px;
        }}
        @media(max-width: 868px) {{ .grid-two {{ grid-template-columns: 1fr; }} }}
        
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
        }}
        .card h3 {{ font-size: 16px; margin-bottom: 16px; font-weight: 600; color: #e2e8f0; }}
        
        .owasp-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid #1e293b;
            font-size: 13px;
        }}
        .owasp-item:last-child {{ border-bottom: none; }}
        .owasp-item strong {{ background: #1e293b; padding: 2px 10px; border-radius: 6px; }}
        
        .filter-bar {{
            display: flex;
            gap: 12px;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            background: #1e293b;
            border: 1px solid #334155;
            color: #cbd5e1;
            padding: 6px 14px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
        }}
        .filter-btn.active {{ background: #0284c7; border-color: #38bdf8; color: #fff; }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}
        th {{
            text-align: left;
            padding: 12px 16px;
            border-bottom: 2px solid var(--border);
            color: var(--text-muted);
            font-size: 12px;
            text-transform: uppercase;
        }}
        td {{
            padding: 16px;
            border-bottom: 1px solid #1e293b;
            vertical-align: top;
        }}
        tr:hover td {{ background: rgba(255, 255, 255, 0.015); }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.5px;
        }}
        .rule-id {{ background: #0f172a; padding: 3px 6px; border-radius: 4px; font-size: 12px; color: #38bdf8; }}
        .desc {{ color: var(--text-muted); font-size: 13px; margin: 6px 0 10px; }}
        .code-box {{
            background: #090d16;
            border: 1px solid #1e293b;
            border-radius: 6px;
            overflow: hidden;
            margin: 8px 0;
            font-family: monospace;
            font-size: 12px;
        }}
        .code-header {{
            background: #0f172a;
            padding: 6px 12px;
            display: flex;
            justify-content: space-between;
            color: #64748b;
            border-bottom: 1px solid #1e293b;
            font-size: 11px;
        }}
        .code-box pre {{ padding: 10px 12px; overflow-x: auto; color: #f1f5f9; }}
        .copy-btn {{
            background: transparent;
            border: none;
            color: #38bdf8;
            cursor: pointer;
            font-size: 11px;
        }}
        .copy-btn:hover {{ text-decoration: underline; }}
        .remediation-box {{
            background: rgba(56, 189, 248, 0.05);
            border-left: 3px solid #38bdf8;
            padding: 8px 12px;
            border-radius: 0 6px 6px 0;
            font-size: 12px;
            color: #cbd5e1;
            margin-top: 6px;
        }}
        .rem-title {{ color: #38bdf8; font-weight: 600; }}
        .fix-hint {{ margin-top: 4px; color: #10b981; }}
        .fix-hint code {{ background: #022c22; padding: 2px 6px; border-radius: 4px; color: #34d399; }}
        .meta-tag {{ background: #1e293b; padding: 3px 8px; border-radius: 4px; font-size: 11px; color: #94a3b8; display: inline-block; margin-bottom: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="brand">
                <div class="brand-icon">🛡️</div>
                <div class="brand-title">
                    <h1>SecureShip Security Gate</h1>
                    <p>Shift-Left DevSecOps Engine Report — Generated {html.escape(result.timestamp)}</p>
                </div>
            </div>
            <div class="verdict-banner">
                <span class="verdict-text">{html.escape(summary.ship_status.value)}</span>
            </div>
        </header>

        <section class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-label">Security Score</div>
                <div class="kpi-value" style="color: {status_bg};">{summary.security_score} <span style="font-size: 16px; color: #64748b;">/ 100</span></div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Total Findings</div>
                <div class="kpi-value">{summary.total_findings}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Critical Severity</div>
                <div class="kpi-value" style="color: #ef4444;">{summary.critical_count}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">High Severity</div>
                <div class="kpi-value" style="color: #f97316;">{summary.high_count}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Files & Lines Scanned</div>
                <div class="kpi-value" style="font-size: 20px; line-height: 1.4;">{summary.files_scanned} files <br><span style="font-size: 14px; color: #64748b;">{summary.lines_scanned} LOC</span></div>
            </div>
        </section>

        <div class="grid-two">
            <div class="card">
                <h3>Vulnerability Severity Breakdown</h3>
                <div style="display: flex; gap: 16px; margin-top: 16px;">
                    <div style="flex: 1; text-align: center; background: #0f172a; padding: 16px; border-radius: 8px; border-top: 3px solid #ef4444;">
                        <div style="font-size: 24px; font-weight: 700; color: #ef4444;">{summary.critical_count}</div>
                        <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Critical</div>
                    </div>
                    <div style="flex: 1; text-align: center; background: #0f172a; padding: 16px; border-radius: 8px; border-top: 3px solid #f97316;">
                        <div style="font-size: 24px; font-weight: 700; color: #f97316;">{summary.high_count}</div>
                        <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">High</div>
                    </div>
                    <div style="flex: 1; text-align: center; background: #0f172a; padding: 16px; border-radius: 8px; border-top: 3px solid #eab308;">
                        <div style="font-size: 24px; font-weight: 700; color: #eab308;">{summary.medium_count}</div>
                        <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Medium</div>
                    </div>
                    <div style="flex: 1; text-align: center; background: #0f172a; padding: 16px; border-radius: 8px; border-top: 3px solid #06b6d4;">
                        <div style="font-size: 24px; font-weight: 700; color: #06b6d4;">{summary.low_count}</div>
                        <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Low</div>
                    </div>
                </div>
            </div>
            <div class="card">
                <h3>OWASP Top 10 Mapping</h3>
                <div>{owasp_items}</div>
            </div>
        </div>

        <section class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h3>Detailed Security Findings</h3>
                <div class="filter-bar">
                    <button class="filter-btn active" onclick="filterFindings('ALL')">All ({summary.total_findings})</button>
                    <button class="filter-btn" onclick="filterFindings('CRITICAL')">Critical ({summary.critical_count})</button>
                    <button class="filter-btn" onclick="filterFindings('HIGH')">High ({summary.high_count})</button>
                    <button class="filter-btn" onclick="filterFindings('MEDIUM')">Medium ({summary.medium_count})</button>
                    <button class="filter-btn" onclick="filterFindings('LOW')">Low ({summary.low_count})</button>
                </div>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Rule ID</th>
                        <th>Vulnerability & Remediation</th>
                        <th>Classification</th>
                    </tr>
                </thead>
                <tbody id="findings-table-body">
                    {findings_table_body}
                </tbody>
            </table>
        </section>
    </div>

    <script>
        function filterFindings(sev) {{
            document.querySelectorAll('.filter-btn').forEach(btn => {{
                btn.classList.toggle('active', btn.innerText.startsWith(sev) || (sev === 'ALL' && btn.innerText.startsWith('All')));
            }});
            const rows = document.querySelectorAll('.finding-row');
            rows.forEach(row => {{
                if (sev === 'ALL' || row.getAttribute('data-severity') === sev) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
    """
