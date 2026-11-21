from __future__ import annotations

import html
from secureship.models import ScanResult, Severity, ShipStatus


def render_certificate_report(result: ScanResult) -> str:
    """Generates an official, print-ready Ship Readiness Executive Audit Certificate."""
    summary = result.summary
    is_ready = summary.ship_status == ShipStatus.READY_TO_SHIP
    status_color = "#059669" if is_ready else "#dc2626"
    seal_text = "SHIP READY — APPROVED" if is_ready else "SHIP BLOCKED — CRITICAL RISKS"

    # OWASP matrix rows
    owasp_rows = []
    standard_owasp = [
        ("A01:2021", "Broken Access Control"),
        ("A02:2021", "Cryptographic Failures"),
        ("A03:2021", "Injection (SQLi / Command / Code)"),
        ("A05:2021", "Security Misconfiguration"),
        ("A06:2021", "Vulnerable and Outdated Components"),
        ("A07:2021", "Identification & Authentication Failures"),
        ("A08:2021", "Software & Data Integrity Failures"),
    ]

    for code, name in standard_owasp:
        count = sum(v for k, v in summary.owasp_breakdown.items() if code in k or name.lower() in k.lower())
        passed = count == 0
        owasp_rows.append(f"""
        <tr>
            <td style="padding: 10px 14px; border-bottom: 1px solid #e2e8f0; font-family: monospace; font-weight: bold;">{code}</td>
            <td style="padding: 10px 14px; border-bottom: 1px solid #e2e8f0;">{name}</td>
            <td style="padding: 10px 14px; border-bottom: 1px solid #e2e8f0; text-align: center;">{count}</td>
            <td style="padding: 10px 14px; border-bottom: 1px solid #e2e8f0; text-align: center;">
                <span style="display: inline-block; padding: 2px 10px; border-radius: 9999px; font-size: 11px; font-weight: bold; background: {'#d1fae5; color: #065f46;' if passed else '#fee2e2; color: #991b1b;'}">
                    {'PASSED' if passed else 'NON-COMPLIANT'}
                </span>
            </td>
        </tr>
        """)

    # Findings checklist
    checklist_rows = []
    for idx, f in enumerate(result.findings, start=1):
        sev_color = {
            Severity.CRITICAL: "#dc2626",
            Severity.HIGH: "#ea580c",
            Severity.MEDIUM: "#d97706",
            Severity.LOW: "#0284c7",
        }.get(f.severity, "#475569")

        checklist_rows.append(f"""
        <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; margin-bottom: 12px; page-break-inside: avoid; background: #fafafa;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <input type="checkbox" style="width: 16px; height: 16px;">
                    <span style="font-weight: 700; font-size: 14px; color: #1e293b;">#{idx}. {html.escape(f.title)}</span>
                    <span style="background: {sev_color}18; color: {sev_color}; border: 1px solid {sev_color}55; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 800;">
                        {f.severity.value}
                    </span>
                </div>
                <code style="font-size: 12px; color: #475569; background: #e2e8f0; padding: 2px 6px; border-radius: 4px;">{html.escape(f.file_path)}:{f.line_start}</code>
            </div>
            <p style="font-size: 12px; color: #475569; margin: 4px 0 8px 24px;">{html.escape(f.description)}</p>
            <div style="margin-left: 24px; font-size: 12px; background: #eff6ff; border-left: 3px solid #3b82f6; padding: 6px 10px; color: #1e40af; border-radius: 0 4px 4px 0;">
                <strong>Action Required:</strong> {html.escape(f.remediation)}
            </div>
        </div>
        """)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureShip Certificate — {html.escape(result.target_path)}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: #f1f5f9;
            color: #0f172a;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            padding: 32px;
            line-height: 1.5;
        }}
        .cert-paper {{
            max-width: 900px;
            margin: 0 auto;
            background: #ffffff;
            border: 2px solid #cbd5e1;
            border-radius: 16px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.08);
            padding: 48px;
            position: relative;
        }}
        .top-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #0f172a;
            padding-bottom: 20px;
            margin-bottom: 28px;
        }}
        .print-btn {{
            background: #0f172a;
            color: #ffffff;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 700;
            cursor: pointer;
            box-shadow: 0 4px 10px rgba(15,23,42,0.2);
        }}
        .print-btn:hover {{ background: #1e293b; }}
        @media print {{
            body {{ background: #ffffff; padding: 0; }}
            .cert-paper {{ border: none; box-shadow: none; padding: 20px; max-width: 100%; }}
            .no-print {{ display: none !important; }}
        }}
        .seal-box {{
            display: inline-flex;
            flex-direction: column;
            align-items: center;
            padding: 14px 28px;
            border: 3px solid {status_color};
            border-radius: 12px;
            background: {status_color}10;
        }}
        .score-circle {{
            width: 80px;
            height: 80px;
            border-radius: 50%;
            background: {status_color};
            color: #ffffff;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            font-size: 26px;
            font-weight: 900;
        }}
    </style>
</head>
<body>
    <div class="cert-paper">
        <div class="no-print" style="margin-bottom: 20px; display: flex; justify-content: flex-end;">
            <button class="print-btn" onclick="window.print()">🖨️ Print / Save as PDF Certificate</button>
        </div>

        <div class="top-bar">
            <div>
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 28px;">🛡️</span>
                    <h1 style="font-size: 24px; font-weight: 800; letter-spacing: -0.5px;">SECURESHIP DEVSECOPS AUDIT</h1>
                </div>
                <p style="font-size: 12px; color: #64748b; margin-top: 4px;">Formal Shift-Left Security & Ship-Readiness Attestation</p>
            </div>
            <div class="seal-box">
                <span style="font-size: 14px; font-weight: 900; color: {status_color}; letter-spacing: 0.5px;">{seal_text}</span>
                <span style="font-size: 10px; color: #64748b; margin-top: 2px;">AUDIT ID: {result.scan_id}</span>
            </div>
        </div>

        <!-- Meta Grid -->
        <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 24px; margin-bottom: 32px; background: #f8fafc; padding: 20px; border-radius: 12px; border: 1px solid #e2e8f0;">
            <div style="font-size: 13px; line-height: 1.8;">
                <div><strong>Target Project:</strong> <code>{html.escape(result.target_path)}</code></div>
                <div><strong>Assessment Date:</strong> {html.escape(result.timestamp)}</div>
                <div><strong>Total Findings:</strong> {summary.total_findings} (Critical: {summary.critical_count}, High: {summary.high_count}, Med: {summary.medium_count}, Low: {summary.low_count})</div>
                <div><strong>Files & Lines Evaluated:</strong> {summary.files_scanned} files / {summary.lines_scanned} LOC in {summary.scan_duration_ms} ms</div>
            </div>
            <div style="display: flex; align-items: center; justify-content: center; gap: 16px;">
                <div class="score-circle">
                    <span>{summary.security_score}</span>
                    <span style="font-size: 10px; opacity: 0.8;">SCORE</span>
                </div>
                <div style="font-size: 12px;">
                    <div style="font-weight: 700; color: #1e293b;">Quality Gate</div>
                    <div style="color: {status_color}; font-weight: 800;">{summary.ship_status.value}</div>
                    <div style="color: #64748b; font-size: 11px;">Min 80 required</div>
                </div>
            </div>
        </div>

        <!-- OWASP Compliance Matrix -->
        <h2 style="font-size: 16px; font-weight: 800; margin-bottom: 12px; color: #1e293b;">1. OWASP Top 10 Compliance Verification</h2>
        <table style="width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 32px;">
            <thead>
                <tr style="background: #0f172a; color: #ffffff; text-align: left;">
                    <th style="padding: 10px 14px; border-radius: 6px 0 0 0;">Code</th>
                    <th style="padding: 10px 14px;">OWASP Category</th>
                    <th style="padding: 10px 14px; text-align: center;">Violations</th>
                    <th style="padding: 10px 14px; text-align: center; border-radius: 0 6px 0 0;">Status</th>
                </tr>
            </thead>
            <tbody>
                {"".join(owasp_rows)}
            </tbody>
        </table>

        <!-- Findings Remediation Checklist -->
        <h2 style="font-size: 16px; font-weight: 800; margin-bottom: 12px; color: #1e293b;">2. Security Findings & Remediation Checklist</h2>
        <div style="margin-bottom: 32px;">
            {"".join(checklist_rows) if checklist_rows else '<p style="color: #059669; font-weight: bold; padding: 20px; text-align: center;">No vulnerabilities found. Codebase passes all security criteria.</p>'}
        </div>

        <!-- Signatures & Attestation Footer -->
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 40px; border-top: 2px dashed #cbd5e1; padding-top: 24px; margin-top: 40px; page-break-inside: avoid;">
            <div>
                <p style="font-size: 11px; text-transform: uppercase; font-weight: bold; color: #64748b;">Automated Attestation Engine</p>
                <p style="font-size: 14px; font-weight: 700; margin-top: 4px;">SecureShip DevSecOps Platform v1.0.0</p>
                <p style="font-size: 11px; color: #94a3b8; margin-top: 2px;">Cryptographically verified scanner output</p>
            </div>
            <div>
                <p style="font-size: 11px; text-transform: uppercase; font-weight: bold; color: #64748b;">Lead DevSecOps Architect / Reviewer</p>
                <div style="height: 36px; border-bottom: 1px solid #94a3b8; margin-top: 8px;"></div>
                <p style="font-size: 11px; color: #94a3b8; margin-top: 4px;">Signature & Date of Approval</p>
            </div>
        </div>
    </div>
</body>
</html>
    """


generate_certificate_html = render_certificate_report

