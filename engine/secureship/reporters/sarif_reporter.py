from __future__ import annotations

import json
from typing import Any, Dict, List

from secureship.models import Finding, ScanResult, Severity


def render_sarif_report(result: ScanResult) -> str:
    """Generates an OASIS SARIF 2.1.0 compliant report for GitHub Code Scanning / CI."""
    rules_dict: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []

    level_map = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
    }

    for f in result.findings:
        # Collect unique rule metadata
        if f.rule_id not in rules_dict:
            rules_dict[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {
                    "text": f"{f.description}\n\nRemediation: {f.remediation}",
                    "markdown": f"**{f.title}**\n\n{f.description}\n\n### Remediation\n{f.remediation}",
                },
                "properties": {
                    "category": f.category.value,
                    "owasp": f.owasp_category,
                    "cwe": f.cwe_id,
                    "problem.severity": level_map.get(f.severity, "warning"),
                },
            }

        # Build SARIF result entry
        sarif_entry: Dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": level_map.get(f.severity, "warning"),
            "properties": {
                "confidence": f.confidence.value if hasattr(f, "confidence") and hasattr(f.confidence, "value") else str(getattr(f, "confidence", "HIGH")),
            },
            "message": {
                "text": f"{f.title}: {f.description} (Remediation: {f.remediation})"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file_path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": f.line_start,
                            "endLine": max(f.line_start, f.line_end),
                            "snippet": {"text": f.code_snippet},
                        },
                    }
                }
            ],
            "properties": {
                "cwe": f.cwe_id,
                "owasp": f.owasp_category,
                "severity": f.severity.value,
            },
        }

        if f.auto_fix_hint:
            sarif_entry["fixes"] = [
                {
                    "description": {"text": f"Suggested fix: {f.auto_fix_hint}"},
                    "fileChanges": [
                        {
                            "artifactLocation": {
                                "uri": f.file_path.replace("\\", "/"),
                            },
                            "replacements": [
                                {
                                    "deletedRegion": {
                                        "startLine": f.line_start,
                                        "endLine": max(f.line_start, f.line_end),
                                    },
                                    "insertedContent": {"text": f.auto_fix_hint},
                                }
                            ],
                        }
                    ],
                }
            ]

        sarif_results.append(sarif_entry)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecureShip",
                        "organization": "SecureShip DevSecOps",
                        "semanticVersion": "1.0.0",
                        "informationUri": "https://github.com/secureship/secureship",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2)


def generate_sarif(result: ScanResult) -> Dict[str, Any]:
    """Returns the parsed SARIF 2.1.0 dictionary structure."""
    return json.loads(render_sarif_report(result))

