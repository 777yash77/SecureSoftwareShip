from __future__ import annotations

from secureship.models import ScanResult


def render_json_report(result: ScanResult) -> str:
    """Serializes scan result into JSON string."""
    return result.model_dump_json(indent=2)
