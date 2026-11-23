"""SecureShip: Shift-Left DevSecOps Security Gate and Platform."""

from secureship.badge import BadgeGenerator
from secureship.ci_generator import CIGenerator
from secureship.ci_cd_auditor import CICDAuditor
from secureship.compliance import ComplianceEngine
from secureship.container_auditor import ContainerAuditor
from secureship.git_scanner import GitHistoryScanner
from secureship.license_checker import LicenseAuditor
from secureship.models import Finding, FindingCategory, ScanResult, Severity, ShipStatus
from secureship.protector import SecretProtector
from secureship.remediator import RemediationEngine
from secureship.sbom import SBOMGenerator
from secureship.scanner import SecureShipEngine
from secureship.scorer import Scorer
from secureship.taint_analyzer import TaintAnalyzer
from secureship.threat_model import ThreatModelingEngine
from secureship.vault import VaultMigrator

__version__ = "1.0.0"

__all__ = [
    "Finding",
    "FindingCategory",
    "ScanResult",
    "Severity",
    "ShipStatus",
    "SecureShipEngine",
    "Scorer",
    "RemediationEngine",
    "SBOMGenerator",
    "ComplianceEngine",
    "CIGenerator",
    "SecretProtector",
    "ThreatModelingEngine",
    "GitHistoryScanner",
    "VaultMigrator",
    "BadgeGenerator",
    "ContainerAuditor",
    "LicenseAuditor",
    "TaintAnalyzer",
    "CICDAuditor",
]
