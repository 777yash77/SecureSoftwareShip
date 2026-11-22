from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

CONFIG_FILENAMES = [".secureshiprc", "secureship.json", ".secureship.json"]


def find_config_file(start_path: Path) -> Optional[Path]:
    """Search for configuration file in start_path and its parents, then fallback to user home directory."""
    cur = start_path.resolve()
    if cur.is_file():
        cur = cur.parent

    # 1. Traverse upward until filesystem root
    while True:
        for name in CONFIG_FILENAMES:
            candidate = cur / name
            if candidate.exists() and candidate.is_file():
                return candidate
        if cur.parent == cur:
            break
        cur = cur.parent

    # 2. Check user home directory (~/.secureshiprc or ~/.secureship/config.json)
    try:
        home = Path.home()
        for name in CONFIG_FILENAMES:
            candidate = home / name
            if candidate.exists() and candidate.is_file():
                return candidate
        global_cfg = home / ".secureship" / "config.json"
        if global_cfg.exists() and global_cfg.is_file():
            return global_cfg
    except Exception:
        pass

    return None


def load_config(target_path: Path) -> Dict[str, Any]:
    """Load configuration dictionary from .secureshiprc or return defaults."""
    config_file = find_config_file(target_path)
    if not config_file:
        return {}

    try:
        content = config_file.read_text(encoding="utf-8").strip()
        if not content:
            return {}
        return json.loads(content)
    except Exception:
        return {}


def save_config(target_dir: Path, data: Dict[str, Any], is_global: bool = False) -> Path:
    """Save configuration to .secureshiprc in target directory or globally in user home."""
    if is_global:
        home = Path.home()
        secureship_dir = home / ".secureship"
        secureship_dir.mkdir(parents=True, exist_ok=True)
        config_path = secureship_dir / "config.json"
        existing = {}
        if config_path.exists():
            try:
                existing = json.loads(config_path.read_text(encoding="utf-8"))
            except Exception:
                existing = {}
        existing.update(data)
        config_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        return config_path

    target_dir = target_dir.resolve()
    if target_dir.is_file():
        target_dir = target_dir.parent

    config_path = target_dir / ".secureshiprc"
    existing = load_config(target_dir)
    existing.update(data)
    config_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return config_path
