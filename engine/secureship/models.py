from __future__ import annotations

import enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def weight(self) -> int:
        weights = {
            "CRITICAL": 25,
            "HIGH": 15,
            "MEDIUM": 5,
            "LOW": 2,
        }
        return weights.get(self.value, 0)


class ShipStatus(str, enum.Enum):
    READY_TO_SHIP = "READY TO SHIP"
    NEEDS_REVIEW = "NEEDS REVIEW"
    BLOCKED = "BLOCKED"


class FindingCategory(str, enum.Enum):
    SECRETS = "SECRETS"
    SAST = "SAST"
    SCA = "SCA"
    IAC = "IAC"


class Finding(BaseModel):
    id: str
    rule_id: str
    title: str
    category: FindingCategory
    severity: Severity
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    owasp_category: str
    cwe_id: str
    description: str
    remediation: str
    auto_fix_hint: Optional[str] = None


class ScanSummary(BaseModel):
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    files_scanned: int = 0
    lines_scanned: int = 0
    scan_duration_ms: float = 0.0
    security_score: int = 100
    min_score: int = 80
    strict_violations: List[str] = Field(default_factory=list)
    ship_status: ShipStatus = ShipStatus.READY_TO_SHIP
    owasp_breakdown: Dict[str, int] = Field(default_factory=dict)
    category_breakdown: Dict[str, int] = Field(default_factory=dict)


class ScanResult(BaseModel):
    scan_id: str
    timestamp: str
    target_path: str
    summary: ScanSummary
    findings: List[Finding] = Field(default_factory=list)


class ScanRequest(BaseModel):
    path: str = "."
    fail_on: Optional[str] = None
    min_severity: Optional[Severity] = None
    min_score: Optional[int] = None
    strict_categories: Optional[List[FindingCategory]] = None
