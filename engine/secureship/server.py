from __future__ import annotations

import io
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, File, Form, HTTPException, Query, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel


from secureship.advisor import AdvisorResponse, SecurityAdvisor
from secureship.badge import BadgeGenerator
from secureship.ci_generator import CIGenerator
from secureship.ci_cd_auditor import CICDAuditor
from secureship.compliance import ComplianceEngine
from secureship.container_auditor import ContainerAuditor
from secureship.db import HistoryDB
from secureship.git_scanner import GitHistoryScanner
from secureship.license_checker import LicenseAuditor
from secureship.models import Finding, ScanRequest, ScanResult, Severity
from secureship.protector import SecretProtector
from secureship.remediator import RemediationEngine
from secureship.reporters.certificate_reporter import render_certificate_report
from secureship.reporters.html_reporter import render_html_report
from secureship.reporters.json_reporter import render_json_report
from secureship.reporters.sarif_reporter import render_sarif_report
from secureship.sbom import SBOMGenerator
from secureship.scanner import SecureShipEngine
from secureship.taint_analyzer import TaintAnalyzer
from secureship.threat_model import ThreatModelingEngine
from secureship.vault import VaultMigrator


app = FastAPI(
    title="SecureShip Security Engine API",
    description="Shift-Left DevSecOps Core Engine API for CLI, VS Code Extension, and Web Dashboard",
    version="1.0.0",
)

# Enable CORS for local web dashboard and extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db = HistoryDB()

# In-memory scan history buffer (last 20 scans)
scan_history: List[ScanResult] = []


class ContentScanRequest(BaseModel):
    file_path: str
    content: str


class GitHubScanRequest(BaseModel):
    repo_url: str
    branch: Optional[str] = None
    min_severity: Optional[Severity] = None


class ExplainRequest(BaseModel):

    finding: Finding
    code_context: Optional[str] = None


@app.get("/api/health")
def health_check() -> Dict[str, str]:
    return {"status": "ok", "engine": "SecureShip", "version": "1.0.0"}


@app.post("/api/scan", response_model=ScanResult)
def run_scan(request: ScanRequest) -> ScanResult:
    """Runs a full directory or file scan against target path."""
    try:
        raw_path = request.path.strip()
        target = Path(raw_path)
        if not target.is_absolute():
            if not target.exists():
                repo_root = Path(__file__).resolve().parent.parent.parent
                cleaned_name = raw_path.lstrip("./\\").strip()
                if (repo_root / cleaned_name).exists():
                    target = (repo_root / cleaned_name).resolve()
                elif (repo_root / target.name).exists():
                    target = (repo_root / target.name).resolve()

        if not target.exists():
            raise HTTPException(
                status_code=400,
                detail=f"Target path '{raw_path}' does not exist on disk. Please enter a valid directory path (e.g. 'c:\\Users\\yaswanth\\Downloads\\SecureShip\\demo-vulnerable-app').",
            )

        engine = SecureShipEngine(target_path=str(target))
        result = engine.scan(
            min_severity=request.min_severity,
            min_score=request.min_score,
            strict_categories=request.strict_categories,
            min_confidence=request.min_confidence,
        )
        scan_history.insert(0, result)
        if len(scan_history) > 20:
            scan_history.pop()
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan execution failed: {str(e)}")


@app.post("/api/scan/content", response_model=List[Finding])
def scan_content(request: ContentScanRequest) -> List[Finding]:
    """Scans content directly for real-time IDE diagnostics."""
    engine = SecureShipEngine(".")
    return engine.scan_content(request.file_path, request.content)


@app.post("/api/scan/github", response_model=ScanResult)
async def scan_github_repo(req: GitHubScanRequest) -> ScanResult:
    """Clones/downloads a public GitHub repository archive and performs a full Shift-Left security scan."""
    clean_url = req.repo_url.strip().rstrip("/")
    m = re.search(r"github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?$", clean_url)
    if not m:
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub repository URL. Expected format: https://github.com/owner/repo",
        )
    owner, repo = m.group(1), m.group(2)

    temp_dir = tempfile.mkdtemp(prefix="secureship_gh_")
    try:
        branches_to_try = [req.branch] if req.branch else ["main", "master"]
        downloaded = False
        async with httpx.AsyncClient(follow_redirects=True, timeout=45.0) as client:
            for branch in branches_to_try:
                zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
                resp = await client.get(zip_url)
                if resp.status_code == 200:
                    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                        zf.extractall(temp_dir)
                    downloaded = True
                    break

        if not downloaded:
            raise HTTPException(
                status_code=404,
                detail=f"Could not download repository '{owner}/{repo}'. Please check if the repository is public and the branch exists.",
            )

        extracted_items = os.listdir(temp_dir)
        scan_target = (
            os.path.join(temp_dir, extracted_items[0])
            if len(extracted_items) == 1 and os.path.isdir(os.path.join(temp_dir, extracted_items[0]))
            else temp_dir
        )

        engine = SecureShipEngine(target_path=scan_target)
        result = engine.scan(min_severity=req.min_severity)
        result.target_path = f"github.com/{owner}/{repo}"

        scan_history.insert(0, result)
        if len(scan_history) > 20:
            scan_history.pop()
        db.save_scan(result)
        return result
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.post("/api/scan/upload", response_model=ScanResult)
async def scan_uploaded_zip(
    file: UploadFile = File(...),
    min_severity: Optional[str] = Form(None),
) -> ScanResult:
    """Accepts a .zip archive, safely unpacks it in a sandbox, and runs a complete security audit."""
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip archive files are supported.")

    min_sev_enum = None
    if min_severity:
        try:
            min_sev_enum = Severity(min_severity.upper())
        except ValueError:
            pass

    content = await file.read()
    temp_dir = tempfile.mkdtemp(prefix="secureship_upload_")
    try:
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                # Prevent Zip Slip directory traversal vulnerability
                base_dir = os.path.abspath(temp_dir)
                for member in zf.infolist():
                    target_path = os.path.abspath(os.path.join(temp_dir, member.filename))
                    if not target_path.startswith(base_dir):
                        raise HTTPException(status_code=400, detail="Malicious path traversal detected in zip archive.")
                zf.extractall(temp_dir)
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="Corrupted or invalid zip file.")

        extracted_items = os.listdir(temp_dir)
        scan_target = (
            os.path.join(temp_dir, extracted_items[0])
            if len(extracted_items) == 1 and os.path.isdir(os.path.join(temp_dir, extracted_items[0]))
            else temp_dir
        )

        engine = SecureShipEngine(target_path=scan_target)
        result = engine.scan(min_severity=min_sev_enum)
        result.target_path = f"Archive: {file.filename}"

        scan_history.insert(0, result)
        if len(scan_history) > 20:
            scan_history.pop()
        db.save_scan(result)
        return result
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)



@app.get("/api/scans", response_model=List[ScanResult])
def get_scans() -> List[ScanResult]:
    """Retrieves list of recent scan results from memory or database."""
    if not scan_history:
        db_scans = db.get_recent_scans(limit=20)
        if db_scans:
            scan_history.extend(db_scans)
    return scan_history


@app.get("/api/history")
def get_history_trend(limit: int = 20) -> List[Dict[str, Any]]:
    """Retrieves persistent scan summary history trend for graphing."""
    return db.get_score_trend(limit=limit)


@app.post("/api/explain", response_model=AdvisorResponse)
async def explain_finding(req: ExplainRequest) -> AdvisorResponse:
    """AI / Expert Advisor: Explains why finding is exploitable and provides context-aware fix."""
    return await SecurityAdvisor.explain_finding(req.finding, req.code_context)


@app.get("/api/report/html")
def get_html_report(scan_id: Optional[str] = Query(None)) -> Response:
    """Exports HTML report for the specified or most recent scan."""
    target_scan = _resolve_scan(scan_id)
    html_content = render_html_report(target_scan)
    return Response(content=html_content, media_type="text/html")


@app.get("/api/report/json")
def get_json_report(scan_id: Optional[str] = Query(None)) -> Response:
    """Exports JSON report for the specified or most recent scan."""
    target_scan = _resolve_scan(scan_id)
    json_str = render_json_report(target_scan)
    return Response(content=json_str, media_type="application/json")


@app.get("/api/report/sarif")
def get_sarif_report(scan_id: Optional[str] = Query(None)) -> Response:
    """Exports SARIF 2.1.0 report for the specified or most recent scan."""
    target_scan = _resolve_scan(scan_id)
    sarif_str = render_sarif_report(target_scan)
    return Response(content=sarif_str, media_type="application/json")


@app.get("/api/report/certificate")
@app.get("/api/scans/{scan_id}/report")
def get_certificate_report(scan_id: Optional[str] = None) -> Response:
    """Exports official Ship Readiness Certificate & Executive Audit Report."""
    target_scan = _resolve_scan(scan_id)
    cert_html = render_certificate_report(target_scan)
    return Response(content=cert_html, media_type="text/html")


class FixRequest(BaseModel):
    path: str = "."
    apply: bool = False
    rules: Optional[List[str]] = None


class CIRequest(BaseModel):
    platform: str
    path: str = "."
    overwrite: bool = False


class ProtectRequest(BaseModel):
    path: str = "."
    unstage: bool = True


@app.post("/api/protect-gitignore")
def protect_gitignore_endpoint(req: ProtectRequest) -> Dict[str, Any]:
    """Auto-protects repository by adding .env, DB credentials, private keys to .gitignore."""
    target = Path(req.path).resolve()
    protector = SecretProtector(str(target))
    return protector.protect(target_dir=target, auto_unstage=req.unstage)


@app.get("/api/threat-model")
def get_threat_model(path: str = Query(".", description="Target repository path")) -> Dict[str, Any]:
    """Generates STRIDE threat model and attack surface matrix."""
    target = Path(path).resolve()
    engine = ThreatModelingEngine(str(target))
    rep = engine.analyze(target)
    return ThreatModelingEngine.report_to_dict(rep)


@app.get("/api/git-history")
def get_git_history(
    path: str = Query(".", description="Target Git repository"),
    commits: int = Query(50, description="Max commits to scan"),
    branch: Optional[str] = Query(None, description="Branch to scan"),
) -> List[Dict[str, Any]]:
    """Scans Git commit history for leaked credentials and API tokens."""
    target = Path(path).resolve()
    scanner = GitHistoryScanner(str(target))
    findings = scanner.scan_history(repo_dir=target, max_commits=commits, branch=branch)
    return GitHistoryScanner.findings_to_dict(findings)


@app.post("/api/vault")
def export_vault(path: str = Query(".", description="Target repository path")) -> Dict[str, Any]:
    """Extracts secrets and exports .env.example, HashiCorp Vault, and K8s secret payloads."""
    target = Path(path).resolve()
    engine = SecureShipEngine(str(target), categories=[FindingCategory.SECRETS])
    result = engine.scan()
    migrator = VaultMigrator(str(target))
    return migrator.export(result.findings)


@app.get("/api/badge.svg")
def get_badge(
    scan_id: Optional[str] = Query(None),
) -> Response:
    """Returns dynamic Shields.io-compliant SVG security status badge."""
    target_scan = _resolve_scan(scan_id)
    svg = BadgeGenerator.generate_svg(target_scan.summary.security_score, target_scan.summary.ship_status.value)
    return Response(content=svg, media_type="image/svg+xml")


@app.get("/api/container")
def get_container_audit(path: str = Query(".", description="Target directory or Dockerfile")) -> List[Dict[str, Any]]:
    """Deep container security inspection: multi-stage builds, SUID permissions, ARG secrets."""
    target = Path(path).resolve()
    auditor = ContainerAuditor(str(target))
    if target.is_file():
        content = target.read_text(encoding="utf-8", errors="replace")
        findings = auditor.audit_file(target, target.name, content)
    else:
        findings = auditor.audit_directory(target)
    return ContainerAuditor.findings_to_dict(findings)


@app.get("/api/sbom")
def get_sbom(
    path: str = Query(".", description="Target repository path"),
    format: str = Query("cyclonedx", description="cyclonedx or spdx"),
) -> Dict[str, Any]:
    """Generates CycloneDX v1.5 or SPDX v2.3 compliant Software Bill of Materials (SBOM)."""
    target = Path(path).resolve()
    gen = SBOMGenerator(str(target))
    return gen.generate(target, format=format)


@app.get("/api/compliance")
def get_compliance(
    scan_id: Optional[str] = Query(None),
    standard: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Evaluates scan findings against international standards (OWASP Top 10, PCI-DSS, SOC 2, NIST SSDF)."""
    target_scan = _resolve_scan(scan_id)
    engine = ComplianceEngine()
    if standard:
        rep = engine.evaluate(target_scan.findings, standard=standard)
        return ComplianceEngine.report_to_dict(rep)
    return engine.evaluate_all(target_scan.findings)


@app.post("/api/fix")
def apply_fix(req: FixRequest) -> Dict[str, Any]:
    """Automated security auto-fix engine: preview diffs or apply safe code remediations."""
    target = Path(req.path).resolve()
    engine = RemediationEngine(str(target))
    return engine.scan_and_remediate(target_dir=target, apply=req.apply, rules=req.rules)


@app.get("/api/ci-templates")
def list_ci_templates() -> Dict[str, Any]:
    """Lists available CI/CD platforms for automated shift-left pipeline generation."""
    return {"platforms": list(CIGenerator.TEMPLATES.keys())}


@app.post("/api/ci-templates")
def generate_ci_template(req: CIRequest) -> Dict[str, Any]:
    """Generates production-ready CI/CD shift-left pipeline workflow file."""
    target = Path(req.path).resolve()
    gen = CIGenerator(str(target))
    try:
        return gen.generate(req.platform, target_dir=target, overwrite=req.overwrite)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/license")
def get_license_audit(
    path: str = Query(".", description="Target repository path"),
    policy: str = Query("commercial", description="License policy: permissive, commercial, or strict"),
) -> Dict[str, Any]:
    """Audits dependencies for Open-Source License compliance and legal viral copyleft risk."""
    target = Path(path).resolve()
    auditor = LicenseAuditor(str(target))
    return auditor.audit(policy=policy)


@app.get("/api/taint")
def get_taint_analysis(path: str = Query(".", description="Target repository path")) -> Dict[str, Any]:
    """Static taint analysis: traces untrusted HTTP/CLI inputs to dangerous injection sinks."""
    target = Path(path).resolve()
    analyzer = TaintAnalyzer(str(target))
    return analyzer.analyze()


@app.get("/api/ci-audit")
def get_ci_audit(path: str = Query(".", description="Target repository path")) -> Dict[str, Any]:
    """Audits CI/CD pipeline definitions (.github/workflows) for supply-chain vulnerabilities."""
    target = Path(path).resolve()
    auditor = CICDAuditor(str(target))
    return auditor.audit()


def _resolve_scan(scan_id: Optional[str] = None) -> ScanResult:
    if scan_id:
        found = next((s for s in scan_history if s.scan_id == scan_id), None)
        if not found:
            found = db.get_scan(scan_id)
        if found:
            return found

    if scan_history:
        return scan_history[0]

    db_scans = db.get_recent_scans(limit=1)
    if db_scans:
        scan_history.append(db_scans[0])
        return db_scans[0]

    # Generate initial scan of demo app if none exists
    demo_target = Path("./demo-vulnerable-app")
    if not demo_target.exists():
        repo_root = Path(__file__).resolve().parent.parent.parent / "demo-vulnerable-app"
        if repo_root.exists():
            demo_target = repo_root
        else:
            demo_target = Path(".")
    engine = SecureShipEngine(str(demo_target))
    result = engine.scan()
    scan_history.append(result)
    return result


# Mount built dashboard if available
dashboard_dist = Path(__file__).resolve().parent.parent.parent / "dashboard" / "dist"
if dashboard_dist.exists():
    app.mount("/", StaticFiles(directory=str(dashboard_dist), html=True), name="dashboard")


def create_app() -> FastAPI:
    return app
