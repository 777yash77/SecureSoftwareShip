from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import typer
from rich.console import Console
from rich.panel import Panel

from secureship.config import load_config, save_config

console = Console()

DEFAULT_GITHUB_REPO = "https://github.com/777yash77/SecureSoftwareShip.git"
DEFAULT_REPO_SLUG = "777yash77/SecureSoftwareShip"
DEFAULT_BRANCH = "main"


def resolve_token(token: Optional[str] = None, target_dir: Optional[Path] = None) -> Optional[str]:
    """Resolves GitHub Personal Access Token from CLI flag, env vars, or .secureshiprc."""
    if token and token.strip():
        return token.strip()

    # Environment variables
    for env_var in ("GITHUB_TOKEN", "GH_TOKEN", "SECURESHIP_GITHUB_TOKEN", "SECURESHIP_GH_TOKEN"):
        val = os.environ.get(env_var)
        if val and val.strip():
            return val.strip()

    # Configuration file (.secureshiprc)
    check_dir = target_dir or Path(".").resolve()
    cfg = load_config(check_dir)
    cfg_token = cfg.get("github_token")
    if cfg_token and str(cfg_token).strip():
        return str(cfg_token).strip()

    return None


def fetch_latest_commit_info(
    repo_slug: str = DEFAULT_REPO_SLUG,
    branch: str = DEFAULT_BRANCH,
    token: Optional[str] = None,
) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
    """Fetches the latest commit SHA, author, and message from GitHub REST API.

    Returns:
        (success, commit_sha, commit_message, error_message)
    """
    api_url = f"https://api.github.com/repos/{repo_slug}/commits/{branch}"
    headers = {
        "User-Agent": "SecureShip-Updater",
        "Accept": "application/vnd.github.v3+json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(api_url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            data = json.loads(response.read().decode("utf-8"))
            sha = data.get("sha", "")[:8]
            commit_info = data.get("commit", {})
            msg = commit_info.get("message", "").split("\n")[0].strip()
            author = commit_info.get("author", {}).get("name", "Unknown")
            return True, sha, f"{msg} (by {author})", None
    except urllib.error.HTTPError as e:
        if e.code in (401, 404):
            return (
                False,
                None,
                None,
                "Repository is private or not found. A valid GitHub Personal Access Token is required.",
            )
        return False, None, None, f"GitHub API error {e.code}: {e.reason}"
    except Exception as e:
        return False, None, None, f"Network error communicating with GitHub: {e}"


def run_self_update(
    repo_url: str = DEFAULT_GITHUB_REPO,
    branch: str = DEFAULT_BRANCH,
    token: Optional[str] = None,
    check_only: bool = False,
    force: bool = False,
) -> int:
    """Orchestrates self-update from GitHub repository (supports both public and private repos)."""
    resolved_token = resolve_token(token)

    # Extract slug from repo_url
    slug = DEFAULT_REPO_SLUG
    clean_url = repo_url.replace(".git", "").rstrip("/")
    if "github.com/" in clean_url:
        slug = clean_url.split("github.com/")[-1]

    console.print(Panel(
        f"[bold cyan]🛡️  SecureShip Self-Updater[/bold cyan]\n"
        f"[dim]Source Repository:[/dim] [white]https://github.com/{slug}[/white]\n"
        f"[dim]Target Branch:    [/dim] [yellow]{branch}[/yellow]\n"
        f"[dim]Auth Status:      [/dim] [{'bold green]Authenticated (Token present)' if resolved_token else '[yellow]Public / Unauthenticated'}]",
        title="Software Update",
        border_style="cyan"
    ))

    # 1. Check GitHub API
    console.print(f"[*] Querying GitHub for latest updates on [bold cyan]{slug} ({branch})[/bold cyan]...")
    success, sha, msg, err = fetch_latest_commit_info(slug, branch, resolved_token)

    if not success:
        if "private" in (err or "").lower() and not resolved_token:
            typer.secho(f"\n🔒 {err}", fg=typer.colors.YELLOW, bold=True)
            typer.echo("If this is a private repository, provide a GitHub Personal Access Token (PAT):")
            typer.echo("  1. CLI Flag:   secureship update --token ghp_yourTokenHere")
            typer.echo("  2. Env Var:    $env:GITHUB_TOKEN = 'ghp_yourTokenHere'")
            typer.echo("  3. Config:     secureship config --github-token ghp_yourTokenHere\n")

            # If running in interactive terminal, prompt user
            if sys.stdin.isatty():
                prompt_token = typer.prompt("Enter GitHub Token (or press Enter to cancel)", hide_input=True, default="")
                if prompt_token.strip():
                    return run_self_update(repo_url, branch, prompt_token.strip(), check_only, force)

            return 1
        else:
            typer.secho(f"\n❌ Update check failed: {err}\n", fg=typer.colors.RED, bold=True)
            return 1

    typer.secho(f"✅ Latest Remote Version: Commit [{sha}] — \"{msg}\"", fg=typer.colors.GREEN, bold=True)

    if check_only:
        typer.secho("ℹ️  Update check complete (--check specified). No changes applied.\n", fg=typer.colors.CYAN)
        return 0

    # 2. Perform the update
    typer.echo("\n[*] Fetching and applying updates...")

    # Method A: If running inside a git checkout with matching remote
    install_root = Path(__file__).resolve().parent.parent.parent
    git_dir = install_root / ".git"

    if git_dir.exists():
        console.print("[*] Local git repository detected. Synchronizing working tree...")
        try:
            # Configure authenticated remote temporarily if token provided
            auth_url = repo_url
            if resolved_token:
                auth_url = repo_url.replace("https://", f"https://{resolved_token}@")

            pull_cmd = ["git", "pull", auth_url, branch]
            res_pull = subprocess.run(pull_cmd, cwd=str(install_root), capture_output=True, text=True)
            if res_pull.returncode == 0:
                console.print("[+] Git pull successful. Re-installing updated engine dependencies...")
                pip_cmd = [sys.executable, "-m", "pip", "install", "-e", str(install_root / "engine"), "--quiet"]
                res_pip = subprocess.run(pip_cmd, capture_output=True, text=True)
                if res_pip.returncode == 0:
                    typer.secho(f"\n🎉 SecureShip successfully updated to commit [{sha}]!\n", fg=typer.colors.GREEN, bold=True)
                    return 0
        except Exception as e:
            console.print(f"[dim]Git pull fallback: {e}[/dim]")

    # Method B: Update via pip git+https directly (universal mode)
    console.print("[*] Updating SecureShip package via pip from GitHub...")
    auth_git_url = f"git+https://github.com/{slug}.git@{branch}#subdirectory=engine"
    if resolved_token:
        auth_git_url = f"git+https://{resolved_token}@github.com/{slug}.git@{branch}#subdirectory=engine"

    pip_git_cmd = [sys.executable, "-m", "pip", "install", "--upgrade", auth_git_url]
    res_pip_git = subprocess.run(pip_git_cmd, capture_output=True, text=True)

    if res_pip_git.returncode == 0:
        typer.secho(f"\n🎉 SecureShip successfully updated to commit [{sha}] from GitHub!\n", fg=typer.colors.GREEN, bold=True)
        return 0

    # Method C: Download zip archive from GitHub API and install
    console.print("[*] Pip git clone failed or git is missing. Downloading release archive directly...")
    archive_url = f"https://api.github.com/repos/{slug}/zipball/{branch}"
    headers = {
        "User-Agent": "SecureShip-Updater",
        "Accept": "application/vnd.github.v3+json",
    }
    if resolved_token:
        headers["Authorization"] = f"Bearer {resolved_token}"

    req = urllib.request.Request(archive_url, headers=headers)
    temp_dir = tempfile.mkdtemp(prefix="secureship_update_")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read()

        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            zf.extractall(temp_dir)

        # Locate engine folder inside extracted root
        extracted_dirs = [d for d in Path(temp_dir).iterdir() if d.is_dir()]
        extracted_root = extracted_dirs[0] if extracted_dirs else Path(temp_dir)
        engine_target = extracted_root / "engine"
        if not engine_target.exists():
            engine_target = extracted_root

        pip_install_cmd = [sys.executable, "-m", "pip", "install", "--upgrade", str(engine_target)]
        res_inst = subprocess.run(pip_install_cmd, capture_output=True, text=True)

        if res_inst.returncode == 0:
            typer.secho(f"\n🎉 SecureShip successfully updated to latest version [{sha}]!\n", fg=typer.colors.GREEN, bold=True)
            return 0
        else:
            typer.secho(f"\n❌ Installation failed: {res_inst.stderr}\n", fg=typer.colors.RED, bold=True)
            return 1
    except urllib.error.HTTPError as e:
        typer.secho(f"\n❌ Failed to download update archive (HTTP {e.code}: {e.reason}).\n", fg=typer.colors.RED, bold=True)
        return 1
    except Exception as e:
        typer.secho(f"\n❌ Update failed: {e}\n", fg=typer.colors.RED, bold=True)
        return 1
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
