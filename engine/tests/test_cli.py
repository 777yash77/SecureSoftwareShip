from typer.testing import CliRunner
from secureship.cli import app

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "SecureShip v1.0.0" in result.output


def test_cli_scan_demo_app():
    # Scanning demo-vulnerable-app with --format json
    result = runner.invoke(app, ["scan", "./demo-vulnerable-app", "--format", "json"])
    assert result.exit_code == 0
    assert "BLOCKED" in result.output
    assert "findings" in result.output


def test_cli_scan_fail_on():
    # Scan with --fail-on high should exit with code 1 due to high/critical findings
    result = runner.invoke(app, ["scan", "./demo-vulnerable-app", "--fail-on", "high"])
    assert result.exit_code == 1
    assert "Build FAILED" in result.output
