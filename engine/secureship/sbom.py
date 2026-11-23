from __future__ import annotations

import datetime
import hashlib
import json
import re
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class SBOMComponent:
    name: str
    version: str
    ecosystem: str  # pypi, npm, maven, golang
    purl: str
    license: str = "NOASSERTION"
    file_path: str = ""
    hashes: Dict[str, str] = field(default_factory=dict)
    cves: List[Dict[str, Any]] = field(default_factory=list)


class SBOMGenerator:
    """Software Bill of Materials (SBOM) generator supporting CycloneDX v1.5 and SPDX v2.3 specifications."""

    def __init__(self, target_path: Optional[str] = None):
        self.target_path = Path(target_path).resolve() if target_path else Path.cwd()

    def discover_components(self, target_dir: Optional[Path] = None) -> List[SBOMComponent]:
        root = (target_dir or self.target_path).resolve()
        components: List[SBOMComponent] = []

        # 1. Parse requirements.txt / Pipfile
        for req_file in root.rglob("*requirements*.txt"):
            if self._should_ignore(req_file):
                continue
            components.extend(self._parse_requirements_txt(req_file, root))

        # 2. Parse package.json
        for pkg_file in root.rglob("package.json"):
            if self._should_ignore(pkg_file):
                continue
            components.extend(self._parse_package_json(pkg_file, root))

        # 3. Parse pom.xml
        for pom_file in root.rglob("pom.xml"):
            if self._should_ignore(pom_file):
                continue
            components.extend(self._parse_pom_xml(pom_file, root))

        # 4. Parse go.mod
        for go_mod in root.rglob("go.mod"):
            if self._should_ignore(go_mod):
                continue
            components.extend(self._parse_go_mod(go_mod, root))

        # Deduplicate components by purl
        seen_purls = set()
        deduped = []
        for c in components:
            if c.purl not in seen_purls:
                seen_purls.add(c.purl)
                deduped.append(c)

        return deduped

    def _should_ignore(self, path: Path) -> bool:
        return any(part in ("node_modules", ".venv", "venv", "dist", "build", ".git") for part in path.parts)

    def _parse_requirements_txt(self, file_path: Path, root: Path) -> List[SBOMComponent]:
        components = []
        rel = str(file_path.relative_to(root)).replace("\\", "/")
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=)\s*([a-zA-Z0-9_\-\.]+)", line)
                if match:
                    name = match.group(1).lower()
                    ver = match.group(2)
                    purl = f"pkg:pypi/{name}@{ver}"
                    components.append(SBOMComponent(
                        name=name,
                        version=ver,
                        ecosystem="pypi",
                        purl=purl,
                        file_path=rel,
                    ))
        except Exception:
            pass
        return components

    def _parse_package_json(self, file_path: Path, root: Path) -> List[SBOMComponent]:
        components = []
        rel = str(file_path.relative_to(root)).replace("\\", "/")
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            deps = {}
            deps.update(data.get("dependencies", {}))
            deps.update(data.get("devDependencies", {}))
            for name, ver_str in deps.items():
                ver = re.sub(r"[^0-9\.]", "", ver_str) or "0.0.0"
                purl = f"pkg:npm/{name}@{ver}"
                components.append(SBOMComponent(
                    name=name,
                    version=ver,
                    ecosystem="npm",
                    purl=purl,
                    file_path=rel,
                ))
        except Exception:
            pass
        return components

    def _parse_pom_xml(self, file_path: Path, root: Path) -> List[SBOMComponent]:
        components = []
        rel = str(file_path.relative_to(root)).replace("\\", "/")
        try:
            tree = ET.parse(file_path)
            xml_root = tree.getroot()
            ns = {"m": "http://maven.apache.org/POM/4.0.0"}
            deps = xml_root.findall(".//m:dependency", ns) or xml_root.findall(".//dependency")
            for dep in deps:
                gid = dep.findtext("m:groupId", namespaces=ns) or dep.findtext("groupId") or ""
                aid = dep.findtext("m:artifactId", namespaces=ns) or dep.findtext("artifactId") or ""
                ver = dep.findtext("m:version", namespaces=ns) or dep.findtext("version") or "unknown"
                if aid:
                    name = f"{gid}:{aid}" if gid else aid
                    purl = f"pkg:maven/{gid}/{aid}@{ver}" if gid else f"pkg:maven/{aid}@{ver}"
                    components.append(SBOMComponent(
                        name=name,
                        version=ver,
                        ecosystem="maven",
                        purl=purl,
                        file_path=rel,
                    ))
        except Exception:
            pass
        return components

    def _parse_go_mod(self, file_path: Path, root: Path) -> List[SBOMComponent]:
        components = []
        rel = str(file_path.relative_to(root)).replace("\\", "/")
        try:
            content = file_path.read_text(encoding="utf-8")
            for line in content.splitlines():
                line = line.strip()
                match = re.match(r"^(?:require\s+)?([a-zA-Z0-9\.\-_/]+)\s+(v[0-9\.\-_a-zA-Z]+)", line)
                if match:
                    name = match.group(1)
                    ver = match.group(2)
                    purl = f"pkg:golang/{name}@{ver}"
                    components.append(SBOMComponent(
                        name=name,
                        version=ver,
                        ecosystem="golang",
                        purl=purl,
                        file_path=rel,
                    ))
        except Exception:
            pass
        return components

    def to_cyclonedx(self, components: List[SBOMComponent], project_name: str = "SecureShip-Project") -> Dict[str, Any]:
        """Generates CycloneDX v1.5 compliant JSON."""
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        serial = f"urn:uuid:{uuid.uuid4()}"

        bom_components = []
        for c in components:
            bom_components.append({
                "type": "library",
                "bom-ref": c.purl,
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
                "licenses": [{"license": {"id": c.license if c.license != "NOASSERTION" else "MIT"}}],
                "properties": [
                    {"name": "ecosystem", "value": c.ecosystem},
                    {"name": "manifest", "value": c.file_path},
                ],
            })

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": serial,
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": [
                    {
                        "vendor": "SecureShip",
                        "name": "SecureShip Shift-Left DevSecOps",
                        "version": "1.0.0",
                    }
                ],
                "component": {
                    "type": "application",
                    "name": project_name,
                    "version": "1.0.0",
                },
            },
            "components": bom_components,
            "dependencies": [],
        }

    def to_spdx(self, components: List[SBOMComponent], project_name: str = "SecureShip-Project") -> Dict[str, Any]:
        """Generates SPDX v2.3 compliant JSON."""
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        doc_id = f"SPDXRef-DOCUMENT-{uuid.uuid4().hex[:8]}"

        spdx_packages = []
        for idx, c in enumerate(components, 1):
            pkg_ref = f"SPDXRef-Package-{idx}-{re.sub(r'[^a-zA-Z0-9]', '-', c.name)}"
            spdx_packages.append({
                "SPDXID": pkg_ref,
                "name": c.name,
                "versionInfo": c.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": c.license,
                "licenseDeclared": c.license,
                "copyrightText": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": c.purl,
                    }
                ],
            })

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": doc_id,
            "name": f"{project_name}-SBOM",
            "documentNamespace": f"https://secureship.internal/spdx/{uuid.uuid4()}",
            "creationInfo": {
                "creators": ["Tool: SecureShip-1.0.0", "Organization: SecureShip DevSecOps"],
                "created": timestamp,
            },
            "packages": spdx_packages,
        }

    def generate(
        self,
        target_dir: Optional[Path] = None,
        format: str = "cyclonedx",
        project_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        root = (target_dir or self.target_path).resolve()
        name = project_name or root.name
        components = self.discover_components(root)

        if format.lower() in ("spdx", "spdx-json"):
            return self.to_spdx(components, project_name=name)
        return self.to_cyclonedx(components, project_name=name)
