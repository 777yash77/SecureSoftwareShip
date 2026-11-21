import json
import os
import subprocess
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from secureship.cli import app as cli_app
from secureship.server import app as fastapi_app
from secureship.scanner import SecureShipScanner
from secureship.models import Finding, Severity, FindingCategory
from secureship.reporters.sarif_reporter import generate_sarif
from secureship.reporters.certificate_reporter import generate_certificate_html
from secureship.advisor import explain_finding
from secureship.db import save_scan, get_recent_scans, get_scan, get_score_trend

client = TestClient(fastapi_app)
runner = CliRunner()


def test_sarif_generation():
    """Verify SARIF 2.1.0 schema compliance and structure."""
    scanner = SecureShipScanner()
    result = scanner.scan_path("./demo-vulnerable-app")
    sarif = generate_sarif(result)

    assert sarif["version"] == "2.1.0"
    assert "2.1.0" in sarif["$schema"]
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "SecureShip"
    assert len(run["results"]) == len(result.findings)

    # Check a sample result
    sample = run["results"][0]
    assert "ruleId" in sample
    assert "level" in sample
    assert "message" in sample
    assert "locations" in sample
    assert len(sample["locations"]) > 0


def test_cli_sarif_format(tmp_path):
    """Test CLI --format sarif outputs valid SARIF JSON."""
    sarif_file = tmp_path / "test.sarif"
    res = runner.invoke(
        cli_app,
        ["scan", "./demo-vulnerable-app", "--format", "sarif", "--output", str(sarif_file)],
    )
    assert res.exit_code == 0
    assert sarif_file.exists()
    data = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "SecureShip"


def test_certificate_generation():
    """Verify Ship Readiness Certificate HTML contains expected sections."""
    scanner = SecureShipScanner()
    result = scanner.scan_path("./demo-vulnerable-app")
    html = generate_certificate_html(result)

    assert "SECURESHIP DEVSECOPS AUDIT" in html or "SecureShip Certificate" in html
    assert "BLOCKED" in html or "READY TO SHIP" in html
    assert "OWASP Top 10 Compliance" in html
    assert "Attestation" in html
    assert result.scan_id in html


def test_api_certificate_and_report_endpoints():
    """Test certificate and scan report endpoints in FastAPI."""
    # Run a scan to establish a recent scan
    scan_resp = client.post("/api/scan", json={"path": "./demo-vulnerable-app"})
    assert scan_resp.status_code == 200
    scan_id = scan_resp.json()["scan_id"]

    # Test /api/report/certificate
    cert_resp = client.get("/api/report/certificate")
    assert cert_resp.status_code == 200
    assert "SECURESHIP DEVSECOPS AUDIT" in cert_resp.text or "SecureShip Certificate" in cert_resp.text

    # Test /api/scans/{scan_id}/report
    report_resp = client.get(f"/api/scans/{scan_id}/report")
    assert report_resp.status_code == 200
    assert "SECURESHIP DEVSECOPS AUDIT" in report_resp.text or "SecureShip Certificate" in report_resp.text


def test_sqlite_scan_history_and_trend():
    """Verify SQLite persistence, scan history retrieval, and score trends."""
    scanner = SecureShipScanner()
    result = scanner.scan_path("./demo-vulnerable-app")

    save_scan(result)
    recent = get_recent_scans(limit=5)
    assert len(recent) >= 1
    assert any(s.scan_id == result.scan_id for s in recent)

    fetched = get_scan(result.scan_id)
    assert fetched is not None
    assert fetched.scan_id == result.scan_id
    assert fetched.summary.security_score == result.summary.security_score

    trend = get_score_trend(limit=10)
    assert len(trend) >= 1
    assert "timestamp" in trend[0]
    assert "security_score" in trend[0]

    # Test API endpoint
    api_history = client.get("/api/history")
    assert api_history.status_code == 200
    h_data = api_history.json()
    assert isinstance(h_data, list)
    assert len(h_data) >= 1
    assert "security_score" in h_data[0]


def test_ai_advisor_offline_fallback():
    """Verify deterministic expert advisor fallback when no external API is configured."""
    finding = Finding(
        id="finding-test-1",
        rule_id="SAST-PY-007",
        title="Weak Cryptographic Hash (MD5/SHA1)",
        category=FindingCategory.SAST,
        severity=Severity.HIGH,
        file_path="app.py",
        line_start=15,
        line_end=15,
        code_snippet="hashlib.md5(password.encode()).hexdigest()",
        owasp_category="A02:2021-Cryptographic Failures",
        cwe_id="CWE-328",
        description="MD5 is cryptographically broken and vulnerable to collision attacks.",
        remediation="Use SHA-256 or bcrypt.",
    )

    advice = explain_finding(finding)
    assert advice.rule_id == "SAST-PY-007"
    assert "collision" in advice.analysis.lower() or "broken" in advice.analysis.lower()
    assert len(advice.remediation_strategy) >= 1
    assert "sha256" in advice.patched_code.lower() or "bcrypt" in advice.patched_code.lower()
    assert "deterministic" in advice.provider.lower() or "expert" in advice.provider.lower()


def test_api_explain_endpoint():
    """Test POST /api/explain API endpoint."""
    resp = client.post(
        "/api/explain",
        json={
            "finding": {
                "id": "finding-test-2",
                "rule_id": "SEC-001",
                "title": "AWS Access Key ID Detected",
                "category": "SECRETS",
                "severity": "CRITICAL",
                "file_path": "app.py",
                "line_start": 5,
                "line_end": 5,
                "code_snippet": "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
                "owasp_category": "A07:2021-Identification and Authentication Failures",
                "cwe_id": "CWE-798",
                "description": "Hardcoded AWS Access Key detected.",
                "remediation": "Move to environment variable.",
            }
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["rule_id"] == "SEC-001"
    assert "os.environ" in data["patched_code"]
    assert len(data["remediation_strategy"]) >= 1


def test_cli_install_hook(tmp_path):
    """Test `secureship install-hook` creates executable pre-commit hook."""
    git_dir = tmp_path / ".git" / "hooks"
    git_dir.mkdir(parents=True)

    result = runner.invoke(cli_app, ["install-hook", "--path", str(tmp_path)])
    assert result.exit_code == 0
    hook_file = git_dir / "pre-commit"
    assert hook_file.exists()
    content = hook_file.read_text(encoding="utf-8")
    assert "secureship scan --staged" in content


def test_scan_uploaded_zip():
    """Verify POST /api/scan/upload safely unzips and scans project files."""
    import io
    import zipfile

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "app.py",
            "import hashlib\nhashlib.md5(b'insecure')\nAWS_KEY = 'AKIA1111222233334444'\n",
        )
    zip_buffer.seek(0)

    resp = client.post(
        "/api/scan/upload",
        files={"file": ("project.zip", zip_buffer.getvalue(), "application/zip")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "summary" in data
    assert data["summary"]["total_findings"] >= 2
    assert data["summary"]["ship_status"] == "BLOCKED"


def test_cli_category_flags():
    """Verify category filtering flags (--sec, --iac, --sast, --sca)."""
    # Test --sec on demo app
    res_sec = runner.invoke(cli_app, ["scan", "./demo-vulnerable-app", "--sec", "--format", "json"])
    assert res_sec.exit_code == 0
    data_sec = json.loads(res_sec.output)
    assert all(f["category"] == "SECRETS" for f in data_sec["findings"])

    # Test --iac on demo app
    res_iac = runner.invoke(cli_app, ["scan", "./demo-vulnerable-app", "--iac", "--format", "json"])
    assert res_iac.exit_code == 0
    data_iac = json.loads(res_iac.output)
    assert all(f["category"] == "IAC" for f in data_iac["findings"])


def test_cli_rules_and_explain():
    """Verify 'secureship rules' and 'secureship explain' commands."""
    res_rules = runner.invoke(cli_app, ["rules"])
    assert res_rules.exit_code == 0
    assert "SAST-PY-001" in res_rules.output
    assert "SEC-001" in res_rules.output

    res_explain = runner.invoke(cli_app, ["explain", "SAST-PY-001"])
    assert res_explain.exit_code == 0
    assert "Vulnerability Analysis" in res_explain.output
    assert "cursor.execute" in res_explain.output


def test_modify_score_threshold():
    """Verify customizable quality gate score threshold."""
    from secureship.scorer import Scorer
    from secureship.models import ShipStatus

    # Score of 65 with default threshold (80) -> NEEDS REVIEW
    status_default = Scorer.determine_ship_status(score=65, critical_count=0, min_score=80)
    assert status_default == ShipStatus.NEEDS_REVIEW

    # Score of 65 with modified threshold (65) -> READY TO SHIP
    status_modified = Scorer.determine_ship_status(score=65, critical_count=0, min_score=65)
    assert status_modified == ShipStatus.READY_TO_SHIP

    # Score below modified threshold (60 < 65) -> NEEDS REVIEW
    status_below = Scorer.determine_ship_status(score=60, critical_count=0, min_score=65)
    assert status_below == ShipStatus.NEEDS_REVIEW


def test_strict_sca_blocker():
    """Verify --strict-sca fails the quality gate even if score is high (e.g. 98)."""
    from secureship.scorer import Scorer
    from secureship.models import Finding, FindingCategory, Severity, ShipStatus

    sca_finding = Finding(
        id="f-1",
        rule_id="SCA-CVE-2023-1111",
        title="Vulnerable dependency",
        category=FindingCategory.SCA,
        severity=Severity.LOW,
        file_path="package.json",
        line_start=1,
        line_end=1,
        code_snippet="lodash: 4.17.15",
        owasp_category="A06:2021",
        cwe_id="CWE-1395",
        description="Known vulnerability",
        remediation="Upgrade package",
    )

    # Without strict: score is 98 (100 - 2 for LOW), ship status is READY TO SHIP
    summary_normal = Scorer.generate_summary([sca_finding], 1, 10, 5.0, min_score=80)
    assert summary_normal.security_score == 98
    assert summary_normal.ship_status == ShipStatus.READY_TO_SHIP
    assert len(summary_normal.strict_violations) == 0

    # With --strict-sca: even with score 98, status is forced to BLOCKED
    summary_strict = Scorer.generate_summary(
        [sca_finding], 1, 10, 5.0, min_score=80, strict_categories=[FindingCategory.SCA]
    )
    assert summary_strict.security_score == 98
    assert summary_strict.ship_status == ShipStatus.BLOCKED
    assert len(summary_strict.strict_violations) == 1
    assert "SCA" in summary_strict.strict_violations[0]


def test_cli_modify_score_and_strict_flags():
    """Test CLI commands for --modify-score and --strict-sca on demo app."""
    # 1. Test CLI with --modify-score 65 and JSON output
    res_mod = runner.invoke(cli_app, ["scan", "./demo-vulnerable-app", "--modify-score", "65", "--format", "json"])
    assert res_mod.exit_code == 0
    data_mod = json.loads(res_mod.output)
    assert data_mod["summary"]["min_score"] == 65

    # 2. Test CLI with --strict-sca -> demo-vulnerable-app has vulnerable dependencies, so it must exit with code 1
    res_strict = runner.invoke(cli_app, ["scan", "./demo-vulnerable-app", "--strict-sca"])
    assert res_strict.exit_code == 1
    assert "STRICT POLICY ENFORCEMENT VIOLATION" in res_strict.output
    assert "SCA" in res_strict.output


def test_config_command_and_rc(tmp_path):
    """Test 'secureship config' command creating and reading .secureshiprc."""
    # Set configuration in tmp_path
    res = runner.invoke(cli_app, ["config", "--path", str(tmp_path), "--modify-score", "65", "--strict-sca"])
    assert res.exit_code == 0
    rc_file = tmp_path / ".secureshiprc"
    assert rc_file.exists()
    cfg = json.loads(rc_file.read_text(encoding="utf-8"))
    assert cfg["min_score"] == 65
    assert "SCA" in cfg["strict_categories"]

    # Show configuration
    res_show = runner.invoke(cli_app, ["config", "--path", str(tmp_path), "--show"])
    assert res_show.exit_code == 0
    assert "65 / 100" in res_show.output
    assert "SCA" in res_show.output



