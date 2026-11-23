from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from secureship.models import Finding, ScanResult


@dataclass
class ComplianceControl:
    control_id: str
    name: str
    description: str
    status: str = "PASSED"  # PASSED or VIOLATED
    violations: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ComplianceReport:
    standard: str
    standard_name: str
    total_controls: int
    passed_controls: int
    violated_controls: int
    compliance_score: int  # 0 to 100
    controls: List[ComplianceControl] = field(default_factory=list)


class ComplianceEngine:
    """Evaluates scan findings against international security standards (OWASP Top 10, CWE Top 25, PCI-DSS, SOC 2, NIST SSDF)."""

    OWASP_MAPPING = {
        "A01:2021-Broken Access Control": ("A01", "Broken Access Control", ["IAC-COMPOSE-001", "IAC-K8S-002", "IAC-TF-001", "IAC-TF-002"]),
        "A02:2021-Cryptographic Failures": ("A02", "Cryptographic Failures", ["SAST-PY-004", "SAST-JAVA-004", "SAST-GO-003", "SAST-GO-004", "IAC-TF-003", "IAC-TF-004"]),
        "A03:2021-Injection": ("A03", "Injection Flaws", ["SAST-PY-001", "SAST-PY-002", "SAST-PY-005", "SAST-JS-001", "SAST-JAVA-001", "SAST-JAVA-002", "SAST-JAVA-003", "SAST-GO-001", "SAST-GO-002"]),
        "A04:2021-Insecure Design": ("A04", "Insecure Design", ["SAST-PY-006", "SAST-PY-010", "SAST-JS-004"]),
        "A05:2021-Security Misconfiguration": ("A05", "Security Misconfiguration", ["IAC-DOCKER-001", "IAC-DOCKER-002", "IAC-DOCKER-003", "IAC-COMPOSE-002", "IAC-COMPOSE-003", "IAC-K8S-001", "IAC-K8S-003", "SAST-JS-007", "SAST-JS-008"]),
        "A06:2021-Vulnerable and Outdated Components": ("A06", "Vulnerable & Outdated Components", ["SCA-"]),
        "A07:2021-Identification and Authentication Failures": ("A07", "Authentication & Credential Failures", ["SEC-000", "SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005", "SEC-006", "SEC-007", "SEC-008", "SEC-009", "SEC-010", "SEC-011", "SAST-JAVA-006", "SAST-GO-006"]),
        "A08:2021-Software and Data Integrity Failures": ("A08", "Software & Data Integrity Failures", ["SAST-PY-003", "IAC-DOCKER-004", "IAC-DOCKER-005", "SAST-JAVA-001"]),
        "A09:2021-Security Logging and Monitoring Failures": ("A09", "Security Logging Failures", ["SAST-PY-012"]),
        "A10:2021-Server-Side Request Forgery": ("A10", "Server-Side Request Forgery (SSRF)", ["SAST-PY-009", "SAST-JS-005"]),
    }

    PCI_DSS_MAPPING = {
        "PCI-6.2": ("PCI-6.2", "Protect Software from Known Vulnerabilities (SCA/CVE)", ["SCA-"]),
        "PCI-6.3": ("PCI-6.3", "Develop Secure Applications & Code Reviews (SAST)", ["SAST-PY-001", "SAST-PY-002", "SAST-JS-001", "SAST-JAVA-002", "SAST-GO-001"]),
        "PCI-6.4": ("PCI-6.4", "Address Common Software Weaknesses & Injection Flaws", ["SAST-PY-001", "SAST-PY-005", "SAST-JS-002", "SAST-JAVA-003"]),
        "PCI-6.5": ("PCI-6.5", "Prevent Injection, Path Traversal, and Cross-Site Scripting", ["SAST-PY-008", "SAST-JS-002", "SAST-JS-006", "SAST-JAVA-005", "SAST-GO-005"]),
        "PCI-8.2": ("PCI-8.2", "Secure Management of Authentication Credentials", ["SEC-000", "SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005", "SEC-006", "SEC-007", "SEC-008", "SEC-009", "SEC-010", "SEC-011"]),
        "PCI-8.3": ("PCI-8.3", "Prohibit Hardcoded Passwords in Source Code", ["SEC-003", "SAST-JAVA-006", "SAST-GO-006"]),
    }

    SOC2_MAPPING = {
        "CC6.1": ("CC6.1", "Logical Access Controls & Least Privilege Enforcement", ["IAC-COMPOSE-001", "IAC-K8S-002", "IAC-DOCKER-002", "IAC-TF-001"]),
        "CC6.6": ("CC6.6", "Boundary Protection & Network Boundary Controls", ["SAST-PY-007", "IAC-COMPOSE-002", "IAC-K8S-004", "IAC-TF-002"]),
        "CC6.8": ("CC6.8", "Prevention and Detection of Malicious / Unauthorized Code", ["SAST-PY-003", "SAST-JAVA-001", "SAST-JS-001"]),
        "CC7.1": ("CC7.1", "Vulnerability Management & Patch Governance", ["SCA-", "IAC-DOCKER-001"]),
    }

    NIST_SSDF_MAPPING = {
        "PW.1": ("PW.1", "Secure Software Architecture and Platform Configuration", ["IAC-DOCKER-002", "IAC-K8S-001", "IAC-TF-001", "IAC-TF-003"]),
        "PW.4": ("PW.4", "Review Software Source Code for Known Vulnerabilities", ["SAST-PY-001", "SAST-PY-002", "SAST-JS-001", "SAST-JAVA-002", "SAST-GO-001"]),
        "PW.7": ("PW.7", "Configure Software Securely Prior to Deployment", ["IAC-DOCKER-001", "IAC-COMPOSE-001", "IAC-K8S-002", "SAST-PY-010"]),
        "RV.1": ("RV.1", "Identify, Analyze, and Mitigate Software Vulnerabilities", ["SCA-", "SEC-001", "SEC-002"]),
    }

    def evaluate(self, findings: List[Finding], standard: str = "owasp") -> ComplianceReport:
        norm = standard.lower().replace("-", "").replace("_", "")

        if "pci" in norm:
            mapping = self.PCI_DSS_MAPPING
            std_name = "PCI-DSS v4.0 (Payment Card Industry Data Security Standard)"
            std_key = "PCI-DSS"
        elif "soc" in norm:
            mapping = self.SOC2_MAPPING
            std_name = "SOC 2 Type II (Trust Services Criteria CC6 / CC7)"
            std_key = "SOC2"
        elif "nist" in norm or "ssdf" in norm:
            mapping = self.NIST_SSDF_MAPPING
            std_name = "NIST SP 800-218 (Secure Software Development Framework)"
            std_key = "NIST-SSDF"
        else:
            mapping = self.OWASP_MAPPING
            std_name = "OWASP Top 10 (2021) Enterprise Security Benchmark"
            std_key = "OWASP"

        controls: List[ComplianceControl] = []
        for ctrl_id, info in mapping.items():
            cid, name, rule_prefixes = info
            matched_findings = []
            for f in findings:
                cwe_val = getattr(f, "cwe_id", getattr(f, "cwe", "")) or ""
                for prefix in rule_prefixes:
                    if f.rule_id.startswith(prefix) or prefix in cwe_val:
                        matched_findings.append({
                            "finding_id": getattr(f, "finding_id", getattr(f, "id", "")),
                            "rule_id": f.rule_id,
                            "title": f.title,
                            "severity": f.severity.value,
                            "file_path": f.file_path,
                            "line_start": f.line_start,
                        })
                        break

            status = "VIOLATED" if matched_findings else "PASSED"
            controls.append(ComplianceControl(
                control_id=cid,
                name=name,
                description=f"Requires zero vulnerabilities matching: {', '.join(rule_prefixes)}",
                status=status,
                violations=matched_findings,
            ))

        total = len(controls)
        passed = sum(1 for c in controls if c.status == "PASSED")
        violated = total - passed
        score = int(round((passed / total) * 100)) if total > 0 else 100

        return ComplianceReport(
            standard=std_key,
            standard_name=std_name,
            total_controls=total,
            passed_controls=passed,
            violated_controls=violated,
            compliance_score=score,
            controls=controls,
        )

    def evaluate_all(self, findings: List[Finding]) -> Dict[str, Any]:
        """Evaluates findings across all supported compliance frameworks."""
        return {
            "owasp": self.report_to_dict(self.evaluate(findings, "owasp")),
            "pci_dss": self.report_to_dict(self.evaluate(findings, "pci-dss")),
            "soc2": self.report_to_dict(self.evaluate(findings, "soc2")),
            "nist_ssdf": self.report_to_dict(self.evaluate(findings, "nist")),
        }

    @staticmethod
    def report_to_dict(rep: ComplianceReport) -> Dict[str, Any]:
        return {
            "standard": rep.standard,
            "standard_name": rep.standard_name,
            "total_controls": rep.total_controls,
            "passed_controls": rep.passed_controls,
            "violated_controls": rep.violated_controls,
            "compliance_score": rep.compliance_score,
            "controls": [
                {
                    "control_id": c.control_id,
                    "name": c.name,
                    "description": c.description,
                    "status": c.status,
                    "violations": c.violations,
                }
                for c in rep.controls
            ],
        }
