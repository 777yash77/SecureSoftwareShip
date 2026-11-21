import json
from pathlib import Path
from typer.testing import CliRunner
import pytest

from secureship.cli import app as cli_app
from secureship.updater import (
    resolve_token,
    fetch_latest_commit_info,
    DEFAULT_GITHUB_REPO,
    DEFAULT_REPO_SLUG,
)

runner = CliRunner()


def test_resolve_token(tmp_path, monkeypatch):
    """Verify GitHub token resolution precedence: CLI > Env > .secureshiprc."""
    # 1. Direct CLI argument
    assert resolve_token("ghp_direct_arg") == "ghp_direct_arg"

    # 2. Environment variable
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_env_token")
    assert resolve_token(None) == "ghp_env_token"
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    # 3. .secureshiprc configuration
    rc_file = tmp_path / ".secureshiprc"
    rc_file.write_text(json.dumps({"github_token": "ghp_rc_token"}), encoding="utf-8")
    assert resolve_token(None, target_dir=tmp_path) == "ghp_rc_token"


def test_cli_update_help():
    """Verify secureship update and root --update flags appear in help."""
    res = runner.invoke(cli_app, ["update", "--help"])
    assert res.exit_code == 0
    assert "--repo" in res.output
    assert "--token" in res.output
    assert "--check" in res.output
    assert "777yash77/SecureSoftwareShip" in res.output


def test_cli_update_check_unauthenticated():
    """Verify update --check safely handles unauthenticated / private repos."""
    res = runner.invoke(cli_app, ["update", "--check"])
    assert res.exit_code == 1
    assert "SecureShip Self-Updater" in res.output
    assert "777yash77/SecureSoftwareShip" in res.output
    assert "Personal Access Token" in res.output


def test_config_github_token(tmp_path):
    """Verify setting github token via secureship config."""
    res = runner.invoke(
        cli_app,
        ["config", "--path", str(tmp_path), "--github-token", "ghp_test_secret_pat"],
    )
    assert res.exit_code == 0
    rc = json.loads((tmp_path / ".secureshiprc").read_text(encoding="utf-8"))
    assert rc["github_token"] == "ghp_test_secret_pat"

    res_show = runner.invoke(cli_app, ["config", "--path", str(tmp_path), "--show"])
    assert res_show.exit_code == 0
    assert "GitHub Private Token" in res_show.output
    assert "Configured (masked)" in res_show.output
