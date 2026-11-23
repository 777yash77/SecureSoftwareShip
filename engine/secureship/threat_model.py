from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ThreatVector:
    category: str  # Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
    title: str
    description: str
    affected_asset: str
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    mitigation: str


@dataclass
class ThreatModelReport:
    project_name: str
    entrypoints: List[str] = field(default_factory=list)
    datastores: List[str] = field(default_factory=list)
    exposed_ports: List[str] = field(default_factory=list)
    threats: List[ThreatVector] = field(default_factory=list)
    total_threats: int = 0
    high_risk_count: int = 0


class ThreatModelingEngine:
    """Automated STRIDE threat modeling and attack surface analyzer."""

    def __init__(self, target_path: Optional[str] = None):
        self.target_path = Path(target_path).resolve() if target_path else Path.cwd()

    def analyze(self, target_dir: Optional[Path] = None) -> ThreatModelReport:
        root = (target_dir or self.target_path).resolve()
        entrypoints = []
        datastores = []
        exposed_ports = []
        threats: List[ThreatVector] = []

        # Recursively inspect code for attack surface indicators
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if any(part in ("node_modules", ".git", ".venv", "dist", "build") for part in p.parts):
                continue

            try:
                content = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            rel = str(p.relative_to(root)).replace("\\", "/")
            name_lower = p.name.lower()

            # 1. Inspect Docker / Container ports
            if "dockerfile" in name_lower or p.suffix.lower() == ".dockerfile":
                for m in re.finditer(r"^\s*EXPOSE\s+([0-9\s/tcpudp]+)", content, re.MULTILINE | re.IGNORECASE):
                    ports = m.group(1).strip().split()
                    for pt in ports:
                        exposed_ports.append(f"{pt} ({rel})")
                        if pt in ("22", "3306", "5432", "6379", "27017"):
                            threats.append(ThreatVector(
                                category="Information Disclosure",
                                title=f"Management/Database Port {pt} Exposed in Container",
                                description=f"Port {pt} is exposed in container build, allowing network attackers to target database/SSH service.",
                                affected_asset=rel,
                                risk_level="HIGH",
                                mitigation=f"Remove EXPOSE {pt} from container. Bind only to private overlay networks."
                            ))

            # 2. Inspect API routes (FastAPI, Flask, Express, Spring, Go)
            for m in re.finditer(r"""@(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']""", content, re.IGNORECASE):
                method = m.group(1).upper()
                route = m.group(2)
                entrypoints.append(f"{method} {route} ({rel})")

            for m in re.finditer(r"""(?:app|router)\.(get|post|put|delete|patch|use)\s*\(\s*["']([^"']+)["']""", content, re.IGNORECASE):
                method = m.group(1).upper()
                route = m.group(2)
                entrypoints.append(f"{method} {route} ({rel})")

            # 3. Detect Datastores & Connection URIs
            if re.search(r"mongodb(?:\+srv)?://", content, re.IGNORECASE):
                datastores.append(f"MongoDB ({rel})")
            if re.search(r"postgres(?:ql)?://", content, re.IGNORECASE):
                datastores.append(f"PostgreSQL ({rel})")
            if re.search(r"mysql://", content, re.IGNORECASE):
                datastores.append(f"MySQL ({rel})")
            if re.search(r"redis://", content, re.IGNORECASE):
                datastores.append(f"Redis Cache ({rel})")
            if re.search(r"sqlite:///", content, re.IGNORECASE) or name_lower.endswith(".db") or name_lower.endswith(".sqlite"):
                datastores.append(f"SQLite DB ({rel})")

            # 4. STRIDE: Elevation of Privilege (Root containers or sudo)
            if "dockerfile" in name_lower and not re.search(r"^\s*USER\s+", content, re.MULTILINE):
                threats.append(ThreatVector(
                    category="Elevation of Privilege",
                    title="Container Executes as Root User",
                    description="Container image defaults to root user execution without dropping privileges.",
                    affected_asset=rel,
                    risk_level="HIGH",
                    mitigation="Specify 'USER nonroot' or UID 10001 in Dockerfile."
                ))

            # 5. STRIDE: Spoofing (Missing Auth on Sensitive Endpoints)
            if any(sub in content for sub in ("/admin", "/api/v1/admin", "/internal/")):
                if not any(auth in content for auth in ("jwt", "authenticate", "auth_required", "Bearer", "Depends(")):
                    threats.append(ThreatVector(
                        category="Spoofing",
                        title="Unauthenticated Administrative Routes",
                        description="Internal/Admin endpoint detected without obvious authentication verification.",
                        affected_asset=rel,
                        risk_level="HIGH",
                        mitigation="Enforce mandatory role-based authentication middleware on all administrative entrypoints."
                    ))

            # 6. STRIDE: Denial of Service (Missing Resource Limits or Timeouts)
            if re.search(r"requests\.(get|post|put)\([^)]+\)", content) and "timeout=" not in content:
                threats.append(ThreatVector(
                    category="Denial of Service",
                    title="Missing HTTP Outbound Request Timeout",
                    description="Outbound HTTP calls without explicit timeout can hang worker threads indefinitely.",
                    affected_asset=rel,
                    risk_level="MEDIUM",
                    mitigation="Add explicit timeout argument (e.g. requests.get(url, timeout=10))."
                ))

            # 7. STRIDE: Tampering (Unvalidated dynamic serialization)
            if "pickle.loads" in content or "yaml.load(" in content:
                threats.append(ThreatVector(
                    category="Tampering",
                    title="Unsafe Object Deserialization in Data Pipeline",
                    description="Dynamic object deserialization allows attackers to tamper with serialized objects and execute arbitrary code.",
                    affected_asset=rel,
                    risk_level="CRITICAL",
                    mitigation="Replace pickle/unsafe YAML with JSON or yaml.safe_load()."
                ))

            # 8. STRIDE: Information Disclosure (Cleartext Secrets)
            if re.search(r"""(password|secret|api_key)\s*=\s*["'][^"']{8,}["']""", content, re.IGNORECASE):
                threats.append(ThreatVector(
                    category="Information Disclosure",
                    title="Hardcoded Credentials Exposed in Source",
                    description="Plaintext secret variables discovered in repository code.",
                    affected_asset=rel,
                    risk_level="CRITICAL",
                    mitigation="Migrate credential variables to environment variables or secret vaults."
                ))

        # Deduplicate
        unique_threats = []
        seen = set()
        for t in threats:
            key = (t.category, t.title, t.affected_asset)
            if key not in seen:
                seen.add(key)
                unique_threats.append(t)

        high_count = sum(1 for t in unique_threats if t.risk_level in ("CRITICAL", "HIGH"))

        return ThreatModelReport(
            project_name=root.name,
            entrypoints=sorted(list(set(entrypoints)))[:50],
            datastores=sorted(list(set(datastores))),
            exposed_ports=sorted(list(set(exposed_ports))),
            threats=unique_threats,
            total_threats=len(unique_threats),
            high_risk_count=high_count,
        )

    @staticmethod
    def report_to_dict(rep: ThreatModelReport) -> Dict[str, Any]:
        return {
            "project_name": rep.project_name,
            "total_threats": rep.total_threats,
            "high_risk_count": rep.high_risk_count,
            "exposed_ports": rep.exposed_ports,
            "datastores": rep.datastores,
            "entrypoints": rep.entrypoints,
            "threats": [
                {
                    "category": t.category,
                    "title": t.title,
                    "description": t.description,
                    "affected_asset": t.affected_asset,
                    "risk_level": t.risk_level,
                    "mitigation": t.mitigation,
                }
                for t in rep.threats
            ],
        }
