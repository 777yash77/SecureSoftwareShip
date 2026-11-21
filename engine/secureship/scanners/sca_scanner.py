from __future__ import annotations

import json
import re
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from secureship.models import Finding, FindingCategory, Severity
from secureship.scanners.base import BaseScanner
from secureship.scorer import IgnoreMatcher


# Built-in fallback database for offline scanning or API timeouts
BUILTIN_CVE_DATABASE: Dict[str, Dict[str, Any]] = {
    "npm:lodash": {
        "max_vulnerable": "4.17.20",
        "cve": "CVE-2020-8203",
        "title": "Prototype Pollution in lodash",
        "severity": Severity.HIGH,
        "safe_version": "4.17.21",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "cwe": "CWE-1321",
        "desc": "lodash before 4.17.21 is vulnerable to prototype pollution in zipObjectDeep.",
    },
    "npm:axios": {
        "max_vulnerable": "0.21.1",
        "cve": "CVE-2020-28168",
        "title": "Server-Side Request Forgery (SSRF) in axios",
        "severity": Severity.HIGH,
        "safe_version": "0.21.2",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "cwe": "CWE-918",
        "desc": "Axios up to 0.21.1 is vulnerable to SSRF via follow-redirects proxy header bypass.",
    },
    "npm:jsonwebtoken": {
        "max_vulnerable": "8.5.1",
        "cve": "CVE-2022-23529",
        "title": "Remote Code Execution in jsonwebtoken",
        "severity": Severity.CRITICAL,
        "safe_version": "9.0.0",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "cwe": "CWE-502",
        "desc": "Insecure key object validation allows arbitrary file write / code execution.",
    },
    "npm:express": {
        "max_vulnerable": "4.19.1",
        "cve": "CVE-2024-29041",
        "title": "Open Redirect via malformed URLs in Express",
        "severity": Severity.MEDIUM,
        "safe_version": "4.19.2",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "cwe": "CWE-601",
        "desc": "Express before 4.19.2 allows open redirection via mishandling user-supplied URL strings.",
    },
    "pypi:requests": {
        "max_vulnerable": "2.30.0",
        "cve": "CVE-2023-32681",
        "title": "Unintended Leak of Proxy-Authorization in Requests",
        "severity": Severity.MEDIUM,
        "safe_version": "2.31.0",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "cwe": "CWE-200",
        "desc": "Requests leaks Proxy-Authorization headers to destination servers when following redirects.",
    },
    "pypi:urllib3": {
        "max_vulnerable": "1.26.17",
        "cve": "CVE-2023-43804",
        "title": "Cookie Header Leak in urllib3 across Cross-Origin Redirects",
        "severity": Severity.HIGH,
        "safe_version": "1.26.18",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "cwe": "CWE-200",
        "desc": "urllib3 does not remove HTTP Cookie headers during cross-origin redirect chains.",
    },
    "pypi:flask": {
        "max_vulnerable": "2.2.4",
        "cve": "CVE-2023-30861",
        "title": "Session Cookie Disclosure in Flask",
        "severity": Severity.HIGH,
        "safe_version": "2.2.5",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "cwe": "CWE-384",
        "desc": "Flask session cookies lack Vary: Cookie header caching protections in some reverse-proxy setups.",
    },
    "pypi:django": {
        "max_vulnerable": "4.2.3",
        "cve": "CVE-2023-36053",
        "title": "Catastrophic ReDoS in Django EmailValidator",
        "severity": Severity.HIGH,
        "safe_version": "4.2.4",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "cwe": "CWE-1333",
        "desc": "EmailValidator and URLValidator are susceptible to catastrophic backtracking regex attacks.",
    },
    "maven:org.apache.logging.log4j:log4j-core": {
        "max_vulnerable": "2.14.1",
        "cve": "CVE-2021-44228",
        "title": "Log4Shell JNDI Remote Code Execution in Log4j",
        "severity": Severity.CRITICAL,
        "safe_version": "2.17.1",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "cwe": "CWE-502",
        "desc": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP.",
    },
    "maven:org.springframework:spring-core": {
        "max_vulnerable": "5.3.17",
        "cve": "CVE-2022-22965",
        "title": "Spring4Shell Remote Code Execution via Data Binding",
        "severity": Severity.CRITICAL,
        "safe_version": "5.3.18",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "cwe": "CWE-94",
        "desc": "Spring Framework RCE via data binding on JDK 9+ when deployed as a WAR on Tomcat.",
    },
}


def parse_semver(v_str: str) -> Tuple[int, int, int]:
    """Basic semver extractor for fallback comparison."""
    clean = re.sub(r"[^0-9.]", "", v_str)
    parts = clean.split(".")
    try:
        major = int(parts[0]) if len(parts) > 0 and parts[0] else 0
        minor = int(parts[1]) if len(parts) > 1 and parts[1] else 0
        patch = int(parts[2]) if len(parts) > 2 and parts[2] else 0
        return (major, minor, patch)
    except Exception:
        return (0, 0, 0)


def is_version_vulnerable(candidate: str, max_vulnerable: str) -> bool:
    """Returns True if candidate <= max_vulnerable."""
    c_ver = parse_semver(candidate)
    m_ver = parse_semver(max_vulnerable)
    return c_ver <= m_ver


class SCAScanner(BaseScanner):
    """Software Composition Analysis (SCA) for package.json, requirements.txt, and pom.xml."""

    category = FindingCategory.SCA
    name = "Dependency / SCA Scanner"

    OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

    @property
    def supported_extensions(self) -> Set[str]:
        return {".json", ".txt", ".xml"}

    def can_scan(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        return name in ("package.json", "requirements.txt", "pom.xml")

    def scan_file(self, file_path: Path, relative_path: str, content: str) -> List[Finding]:
        name = file_path.name.lower()
        if name == "package.json":
            return self._scan_package_json(file_path, relative_path, content)
        elif name == "requirements.txt":
            return self._scan_requirements_txt(file_path, relative_path, content)
        elif name == "pom.xml":
            return self._scan_pom_xml(file_path, relative_path, content)
        return []

    # =========================================================================
    # PARSERS
    # =========================================================================

    def _scan_package_json(self, file_path: Path, relative_path: str, content: str) -> List[Finding]:
        dependencies: List[Dict[str, Any]] = []
        lines = content.splitlines()

        try:
            data = json.loads(content)
        except Exception:
            return []

        all_deps: Dict[str, str] = {}
        if isinstance(data.get("dependencies"), dict):
            all_deps.update(data["dependencies"])
        if isinstance(data.get("devDependencies"), dict):
            all_deps.update(data["devDependencies"])

        for pkg, raw_version in all_deps.items():
            clean_ver = re.sub(r"[\^~>=<v ]", "", raw_version)
            # Find line number
            line_no = 1
            for idx, line in enumerate(lines, start=1):
                if f'"{pkg}"' in line:
                    line_no = idx
                    break

            dependencies.append({
                "ecosystem": "npm",
                "name": pkg,
                "version": clean_ver,
                "raw_version": raw_version,
                "line": line_no,
            })

        return self._check_dependencies(dependencies, relative_path, lines)

    def _scan_requirements_txt(self, file_path: Path, relative_path: str, content: str) -> List[Finding]:
        dependencies: List[Dict[str, Any]] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            line_clean = line.strip()
            if not line_clean or line_clean.startswith("#"):
                continue

            # e.g. requests==2.25.0 or flask>=1.0.2
            match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(?:==|>=|<=|~=)\s*([0-9A-Za-z\.\-_]+)", line_clean)
            if match:
                pkg_name = match.group(1).lower()
                version = match.group(2)
                dependencies.append({
                    "ecosystem": "PyPI",
                    "name": pkg_name,
                    "version": version,
                    "raw_version": version,
                    "line": idx,
                })

        return self._check_dependencies(dependencies, relative_path, lines)

    def _scan_pom_xml(self, file_path: Path, relative_path: str, content: str) -> List[Finding]:
        dependencies: List[Dict[str, Any]] = []
        lines = content.splitlines()

        try:
            # Strip XML namespace for simple tag matching
            xml_text = re.sub(r'\sxmlns="[^"]+"', "", content, count=1)
            root = ET.fromstring(xml_text)
            for dep in root.findall(".//dependency"):
                group_id_el = dep.find("groupId")
                artifact_id_el = dep.find("artifactId")
                version_el = dep.find("version")

                if group_id_el is not None and artifact_id_el is not None and version_el is not None:
                    group_id = (group_id_el.text or "").strip()
                    artifact_id = (artifact_id_el.text or "").strip()
                    version = (version_el.text or "").strip()
                    pkg_name = f"{group_id}:{artifact_id}"

                    # Approximate line number
                    line_no = 1
                    for idx, line in enumerate(lines, start=1):
                        if artifact_id in line:
                            line_no = idx
                            break

                    dependencies.append({
                        "ecosystem": "Maven",
                        "name": pkg_name,
                        "version": version,
                        "raw_version": version,
                        "line": line_no,
                    })
        except Exception:
            pass

        return self._check_dependencies(dependencies, relative_path, lines)

    # =========================================================================
    # VULNERABILITY QUERY & OFFLINE RESOLUTION
    # =========================================================================

    def _check_dependencies(
        self, deps: List[Dict[str, Any]], relative_path: str, lines: List[str]
    ) -> List[Finding]:
        if not deps:
            return []

        # Attempt OSV.dev batch API query with short timeout (1.5s) to avoid hanging
        online_results = self._query_osv_batch(deps)

        findings: List[Finding] = []

        for idx, dep in enumerate(deps):
            line_no = dep["line"]
            line_text = lines[line_no - 1] if line_no <= len(lines) else ""
            if IgnoreMatcher.is_line_suppressed(line_text):
                continue

            eco = dep["ecosystem"]
            name = dep["name"]
            ver = dep["version"]

            vuln_info: Optional[Dict[str, Any]] = None

            # 1. Check OSV online results if available
            if online_results and idx < len(online_results):
                osv_res = online_results[idx]
                vulns = osv_res.get("vulns", [])
                if vulns:
                    first_vuln = vulns[0]
                    vuln_id = first_vuln.get("id", "VULN-UNKNOWN")
                    # Check aliases for CVE
                    aliases = first_vuln.get("aliases", [])
                    cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
                    summary = first_vuln.get("summary") or first_vuln.get("details", "")[:120]

                    vuln_info = {
                        "cve": cve_id,
                        "title": f"Known Vulnerability in {name} ({cve_id})",
                        "severity": Severity.HIGH,
                        "safe_version": "Latest patched release",
                        "owasp": "A06:2021-Vulnerable and Outdated Components",
                        "cwe": "CWE-1395",
                        "desc": summary or f"Package {name}@{ver} contains security vulnerabilities reported in OSV.dev.",
                    }

            # 2. Check built-in fallback database
            db_key = f"{eco.lower()}:{name.lower()}"
            if db_key in BUILTIN_CVE_DATABASE:
                known = BUILTIN_CVE_DATABASE[db_key]
                if is_version_vulnerable(ver, known["max_vulnerable"]):
                    # Built-in detailed data takes precedence or enriches
                    vuln_info = known

            if vuln_info:
                rule_id = f"SCA-{vuln_info['cve'].replace('-', '')[:10]}"
                if IgnoreMatcher.is_line_suppressed(line_text, rule_id):
                    continue

                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        rule_id=rule_id,
                        title=vuln_info["title"],
                        category=FindingCategory.SCA,
                        severity=vuln_info["severity"],
                        file_path=relative_path,
                        line_start=line_no,
                        line_end=line_no,
                        code_snippet=line_text.strip() or f"{name}: {ver}",
                        owasp_category=vuln_info["owasp"],
                        cwe_id=vuln_info["cwe"],
                        description=vuln_info["desc"],
                        remediation=f"Upgrade {name} to version {vuln_info['safe_version']} or higher.",
                        auto_fix_hint=f"{name}@{vuln_info['safe_version']}",
                    )
                )

        return findings

    def _query_osv_batch(self, deps: List[Dict[str, Any]]) -> Optional[List[Dict[str, Any]]]:
        queries = []
        for d in deps:
            queries.append({
                "package": {
                    "name": d["name"],
                    "ecosystem": d["ecosystem"],
                },
                "version": d["version"],
            })

        try:
            with httpx.Client(timeout=2.0) as client:
                resp = client.post(self.OSV_BATCH_URL, json={"queries": queries})
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("results", [])
        except Exception:
            # Offline or timeout: safely fall back to built-in DB
            return None
        return None
