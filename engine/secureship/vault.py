from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from secureship.models import Finding, FindingCategory


class VaultMigrator:
    """Automated Secret Vault exporter: migrates hardcoded credentials to .env.example, HashiCorp Vault, and Kubernetes Secrets."""

    def __init__(self, target_path: Optional[str] = None):
        self.target_path = Path(target_path).resolve() if target_path else Path.cwd()

    def extract_secret_keys(self, findings: List[Finding]) -> Dict[str, str]:
        """Extracts variable names and values from secret findings."""
        secrets: Dict[str, str] = {}
        idx = 1
        for f in findings:
            if f.category != FindingCategory.SECRETS and not f.rule_id.startswith("SEC-"):
                continue

            # Try to extract key name from snippet
            snippet = f.code_snippet
            match = re.search(r"""([a-zA-Z0-9_\-\.]+)\s*[:=]\s*["']?([^"'\s]+)["']?""", snippet)
            if match:
                key = re.sub(r"[^a-zA-Z0-9_]", "_", match.group(1).upper())
                val = match.group(2)
            else:
                key = f"SECRET_KEY_{idx}_{f.rule_id.replace('-', '_')}"
                val = snippet.strip()
                idx += 1

            secrets[key] = val
        return secrets

    def generate_env_example(self, secrets: Dict[str, str]) -> str:
        """Generates a sanitized .env.example template for the project."""
        lines = [
            "# ==============================================================================",
            "# [SecureShip Sanitized Environment Variable Template]",
            "# Auto-generated from detected hardcoded secrets. Populate these in your .env file.",
            "# DO NOT COMMIT REAL CREDENTIALS TO VERSION CONTROL.",
            "# ==============================================================================",
            "",
        ]
        for k in sorted(secrets.keys()):
            lines.append(f"{k}=your_{k.lower()}_here")
        return "\n".join(lines) + "\n"

    def generate_hashicorp_vault_payload(self, secrets: Dict[str, str]) -> Dict[str, Any]:
        """Generates HashiCorp Vault KV version 2 secret payload."""
        return {
            "data": {k: "REDACTED_MIGRATE_TO_VAULT" for k in sorted(secrets.keys())},
            "custom_metadata": {
                "generated_by": "SecureShip Shift-Left DevSecOps",
                "secret_count": str(len(secrets)),
            },
        }

    def generate_k8s_secret_manifest(self, secrets: Dict[str, str], secret_name: str = "app-secrets") -> str:
        """Generates a declarative Kubernetes Secret YAML manifest with base64 encoded templates."""
        b64_entries = []
        for k in sorted(secrets.keys()):
            encoded = base64.b64encode(f"dummy_{k.lower()}_value".encode()).decode()
            b64_entries.append(f"  {k}: {encoded}")

        lines = [
            "apiVersion: v1",
            "kind: Secret",
            "metadata:",
            f"  name: {secret_name}",
            "  labels:",
            "    app.kubernetes.io/managed-by: secureship",
            "type: Opaque",
            "data:",
        ]
        lines.extend(b64_entries)
        return "\n".join(lines) + "\n"

    def export(
        self,
        findings: List[Finding],
        out_dir: Optional[Path] = None,
        secret_name: str = "app-secrets",
    ) -> Dict[str, Any]:
        root = (out_dir or self.target_path).resolve()
        secrets = self.extract_secret_keys(findings)

        env_example = self.generate_env_example(secrets)
        vault_payload = self.generate_hashicorp_vault_payload(secrets)
        k8s_manifest = self.generate_k8s_secret_manifest(secrets, secret_name=secret_name)

        return {
            "secret_count": len(secrets),
            "keys": list(secrets.keys()),
            "env_example": env_example,
            "vault_json": vault_payload,
            "k8s_yaml": k8s_manifest,
        }
