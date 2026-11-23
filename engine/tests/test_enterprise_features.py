import json
from pathlib import Path
import pytest
from typer.testing import CliRunner
from fastapi.testclient import TestClient

from secureship import (
    BadgeGenerator,
    CIGenerator,
    ComplianceEngine,
    ContainerAuditor,
    Finding,
    FindingCategory,
    GitHistoryScanner,
    RemediationEngine,
    SBOMGenerator,
    SecretProtector,
    SecureShipEngine,
    Severity,
    ThreatModelingEngine,
    VaultMigrator,
)
from secureship.cli import app as cli_app
from secureship.server import app as fastapi_app

runner = CliRunner()
client = TestClient(fastapi_app)


# =============================================================================
# 1. REMEDIATION ENGINE TESTS
# =============================================================================

def test_remediate_dockerfile():
    engine = RemediationEngine()
    dockerfile = "FROM python:latest\nADD app.py /app/\nCMD [\"python\", \"app.py\"]\n"
    fixed, fixes = engine.remediate_content("Dockerfile", dockerfile)
    assert ":pinned-stable" in fixed
    assert "COPY app.py /app/" in fixed
    assert "USER nonroot" in fixed
    assert len(fixes) == 3


def test_remediate_python_vulnerabilities():
    engine = RemediationEngine()
    py_code = """
import hashlib
import tempfile

f = tempfile.mktemp()
h = hashlib.md5(b"test").hexdigest()
app.run(host="0.0.0.0", debug=True)
"""
    fixed, fixes = engine.remediate_content("server.py", py_code)
    assert "NamedTemporaryFile" in fixed
    assert "hashlib.sha256" in fixed
    assert "debug=False" in fixed
    assert "127.0.0.1" in fixed
    assert len(fixes) == 4


def test_remediate_docker_compose_and_k8s():
    engine = RemediationEngine()
    compose = "services:\n  web:\n    privileged: true\n"
    fixed_comp, fixes_comp = engine.remediate_content("docker-compose.yml", compose)
    assert "privileged: false" in fixed_comp
    assert len(fixes_comp) == 1

    k8s = "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  securityContext:\n    privileged: true\n"
    fixed_k8s, fixes_k8s = engine.remediate_content("pod.yaml", k8s)
    assert "privileged: false" in fixed_k8s
    assert "hostNetwork: false" in fixed_k8s
    assert len(fixes_k8s) == 2


def test_remediation_dry_run_and_apply(tmp_path):
    dfile = tmp_path / "Dockerfile"
    dfile.write_text("FROM alpine:latest\nCMD [\"sh\"]\n", encoding="utf-8")

    engine = RemediationEngine(str(tmp_path))
    # Dry run
    res_dry = engine.scan_and_remediate(target_dir=tmp_path, apply=False)
    assert res_dry["total_fixes"] > 0
    assert "Dockerfile" in res_dry["diffs"]
    assert "FROM alpine:latest" in dfile.read_text(encoding="utf-8")  # Unmodified

    # Apply
    res_apply = engine.scan_and_remediate(target_dir=tmp_path, apply=True)
    assert res_apply["applied"] is True
    assert ":pinned-stable" in dfile.read_text(encoding="utf-8")


# =============================================================================
# 2. SBOM GENERATOR TESTS
# =============================================================================

def test_sbom_generation_cyclonedx_and_spdx(tmp_path):
    # Requirements.txt
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\nfastapi>=0.100.0\n", encoding="utf-8")

    # Package.json
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"dependencies": {"express": "^4.18.2"}}), encoding="utf-8")

    # Go.mod
    go = tmp_path / "go.mod"
    go.write_text("module myapp\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1\n", encoding="utf-8")

    gen = SBOMGenerator(str(tmp_path))
    comps = gen.discover_components(tmp_path)
    assert len(comps) == 4

    purls = [c.purl for c in comps]
    assert any("pkg:pypi/requests@" in p for p in purls)
    assert any("pkg:pypi/fastapi@" in p for p in purls)
    assert any("pkg:npm/express@" in p for p in purls)
    assert any("pkg:golang/github.com/gin-gonic/gin@" in p for p in purls)

    # Test CycloneDX
    cdx = gen.to_cyclonedx(comps, "TestApp")
    assert cdx["bomFormat"] == "CycloneDX"
    assert cdx["specVersion"] == "1.5"
    assert len(cdx["components"]) == 4

    # Test SPDX
    spdx = gen.to_spdx(comps, "TestApp")
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert len(spdx["packages"]) == 4


# =============================================================================
# 3. COMPLIANCE ENGINE TESTS
# =============================================================================

def test_compliance_evaluation():
    engine = ComplianceEngine()
    findings = [
        Finding(
            id="f1",
            rule_id="SAST-PY-001",
            title="SQL Injection",
            category=FindingCategory.SAST,
            severity=Severity.CRITICAL,
            file_path="db.py",
            line_start=10,
            line_end=10,
            code_snippet="cursor.execute(f'...)",
            owasp_category="A03:2021-Injection",
            cwe_id="CWE-89",
            description="Dynamic SQL query",
            remediation="Use placeholders",
        ),
        Finding(
            id="f2",
            rule_id="SEC-001",
            title="AWS Access Key",
            category=FindingCategory.SECRETS,
            severity=Severity.CRITICAL,
            file_path="config.py",
            line_start=5,
            line_end=5,
            code_snippet="AKIA...",
            owasp_category="A07:2021-Identification and Authentication Failures",
            cwe_id="CWE-798",
            description="Exposed AWS key",
            remediation="Use env vars",
        ),
    ]

    # OWASP
    owasp_rep = engine.evaluate(findings, "owasp")
    assert owasp_rep.standard == "OWASP"
    assert owasp_rep.violated_controls == 2
    assert owasp_rep.compliance_score < 100

    # PCI-DSS
    pci_rep = engine.evaluate(findings, "pci-dss")
    assert pci_rep.standard == "PCI-DSS"
    assert pci_rep.violated_controls >= 1

    # SOC 2
    soc_rep = engine.evaluate(findings, "soc2")
    assert soc_rep.standard == "SOC2"

    # All
    all_reps = engine.evaluate_all(findings)
    assert "owasp" in all_reps
    assert "pci_dss" in all_reps
    assert "soc2" in all_reps
    assert "nist_ssdf" in all_reps


# =============================================================================
# 4. CI/CD WORKFLOW GENERATOR TESTS
# =============================================================================

def test_ci_workflow_generation(tmp_path):
    gen = CIGenerator(str(tmp_path))

    # GitHub Actions
    gh = gen.generate("github", target_dir=tmp_path)
    assert gh["created"] is True
    assert (tmp_path / ".github" / "workflows" / "secureship.yml").exists()

    # GitLab CI
    gl = gen.generate("gitlab", target_dir=tmp_path)
    assert gl["created"] is True
    assert (tmp_path / ".gitlab-ci.yml").exists()

    # Generate all
    res_all = gen.generate_all(target_dir=tmp_path, overwrite=True)
    assert len(res_all) == 5
    assert (tmp_path / "Jenkinsfile").exists()
    assert (tmp_path / "azure-pipelines.yml").exists()
    assert (tmp_path / "bitbucket-pipelines.yml").exists()


# =============================================================================
# 5. JAVA & GO SAST SCANNER TESTS
# =============================================================================

def test_java_sast_rules(tmp_path):
    java_file = tmp_path / "VulnerableService.java"
    java_file.write_text("""
public class VulnerableService {
    public void query(String id) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM accounts WHERE id = " + id);
        Runtime.getRuntime().exec("ping " + id);
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(new byte[0]));
        ois.readObject();
    }
}
""", encoding="utf-8")

    engine = SecureShipEngine(str(tmp_path))
    res = engine.scan()
    rule_ids = {f.rule_id for f in res.findings}

    assert "SAST-JAVA-001" in rule_ids  # Deserialization
    assert "SAST-JAVA-002" in rule_ids  # SQL Injection
    assert "SAST-JAVA-003" in rule_ids  # Command Injection
    assert "SAST-JAVA-004" in rule_ids  # Weak Cryptography (DES)


def test_go_sast_rules(tmp_path):
    go_file = tmp_path / "server.go"
    go_file.write_text("""
package main
import (
    "crypto/tls"
    "database/sql"
    "fmt"
    "os/exec"
)

func handle(db *sql.DB, user string) {
    db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", user))
    exec.Command("sh", "-c", fmt.Sprintf("echo %s", user))
    cfg := &tls.Config{InsecureSkipVerify: true}
}
""", encoding="utf-8")

    engine = SecureShipEngine(str(tmp_path))
    res = engine.scan()
    rule_ids = {f.rule_id for f in res.findings}

    assert "SAST-GO-001" in rule_ids  # SQL Injection
    assert "SAST-GO-002" in rule_ids  # Command Injection
    assert "SAST-GO-003" in rule_ids  # Insecure TLS Skip Verify


# =============================================================================
# 6. TERRAFORM IAC SCANNER TESTS
# =============================================================================

def test_terraform_iac_rules(tmp_path):
    tf_file = tmp_path / "main.tf"
    tf_file.write_text("""
resource "aws_s3_bucket" "public_bucket" {
    bucket = "my-company-backup-data"
    acl    = "public-read"
}

resource "aws_ebs_volume" "unencrypted" {
    availability_zone = "us-east-1a"
    size              = 40
    encrypted         = false
}
""", encoding="utf-8")

    engine = SecureShipEngine(str(tmp_path))
    res = engine.scan()
    rule_ids = {f.rule_id for f in res.findings}

    assert "IAC-TF-001" in rule_ids  # Public S3 Bucket ACL
    assert "IAC-TF-003" in rule_ids  # Unencrypted EBS volume


# =============================================================================
# 7. CLI COMMAND TESTS FOR NEW FEATURES
# =============================================================================

def test_cli_fix_command(tmp_path):
    dfile = tmp_path / "Dockerfile"
    dfile.write_text("FROM node:latest\nCMD [\"node\"]\n", encoding="utf-8")

    # Dry run
    res = runner.invoke(cli_app, ["fix", str(tmp_path), "--dry-run"])
    assert res.exit_code == 0
    assert "Diff for Dockerfile" in res.output

    # Apply
    res2 = runner.invoke(cli_app, ["fix", str(tmp_path), "--apply"])
    assert res2.exit_code == 0
    assert "Successfully applied" in res2.output
    assert ":pinned-stable" in dfile.read_text(encoding="utf-8")


def test_cli_sbom_command(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("flask==2.3.2\n", encoding="utf-8")

    out_json = tmp_path / "sbom.json"
    res = runner.invoke(cli_app, ["sbom", str(tmp_path), "-o", str(out_json)])
    assert res.exit_code == 0
    assert out_json.exists()
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["bomFormat"] == "CycloneDX"


def test_cli_compliance_command(tmp_path):
    py = tmp_path / "app.py"
    py.write_text("import os\nos.system('echo hi')", encoding="utf-8")

    res = runner.invoke(cli_app, ["compliance", str(tmp_path), "--standard", "owasp"])
    assert res.exit_code == 0
    assert "Compliance Audit: OWASP Top 10" in res.output
    assert "Compliance Readiness Score" in res.output


def test_cli_init_ci_command(tmp_path):
    res = runner.invoke(cli_app, ["init-ci", "--path", str(tmp_path), "--platform", "gitlab"])
    assert res.exit_code == 0
    assert (tmp_path / ".gitlab-ci.yml").exists()


# =============================================================================
# 8. FASTAPI ENDPOINT TESTS FOR NEW FEATURES
# =============================================================================

def test_api_sbom_and_compliance():
    # Health check
    res_h = client.get("/api/health")
    assert res_h.status_code == 200

    # SBOM
    res_sbom = client.get("/api/sbom?format=cyclonedx")
    assert res_sbom.status_code == 200
    assert "bomFormat" in res_sbom.json()

    # Compliance
    res_comp = client.get("/api/compliance?standard=owasp")
    assert res_comp.status_code == 200
    assert res_comp.json()["standard"] == "OWASP"

    # CI templates list
    res_ci = client.get("/api/ci-templates")
    assert res_ci.status_code == 200
    assert "github" in res_ci.json()["platforms"]


# =============================================================================
# 9. SECRET SHIELD & GITIGNORE IMMUNIZATION TESTS
# =============================================================================

def test_secret_protector_creates_gitignore_and_protects(tmp_path):
    # Create simulated secrets on disk
    (tmp_path / ".env").write_text("DB_PASSWORD=supersecret\n", encoding="utf-8")
    (tmp_path / "app.db").write_text("sqlite format 3\n", encoding="utf-8")

    protector = SecretProtector(str(tmp_path))
    res = protector.protect(tmp_path)

    assert res["status"] == "PROTECTED"
    assert (tmp_path / ".gitignore").exists()
    content = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in content
    assert "*.db" in content
    assert "*.sqlite" in content
    assert "credentials.json" in content
    assert ".env" in res["detected_sensitive_files"]
    assert "app.db" in res["detected_sensitive_files"]


def test_secret_protector_idempotent(tmp_path):
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("node_modules/\n.env\n", encoding="utf-8")

    protector = SecretProtector(str(tmp_path))
    res1 = protector.protect(tmp_path)
    assert ".env" not in res1["patterns_added"]  # Already existed
    assert "*.db" in res1["patterns_added"]

    # Running a second time should add 0 new patterns
    res2 = protector.protect(tmp_path)
    assert res2["patterns_added"] == []


def test_cli_protect_command(tmp_path):
    (tmp_path / ".env.production").write_text("SECRET_KEY=12345\n", encoding="utf-8")

    res = runner.invoke(cli_app, ["protect", str(tmp_path)])
    assert res.exit_code == 0
    assert "SecureShip Secret Shield & .gitignore Immunizer" in res.output
    assert (tmp_path / ".gitignore").exists()
    assert ".env.*" in (tmp_path / ".gitignore").read_text(encoding="utf-8")


def test_api_protect_gitignore(tmp_path):
    res = client.post("/api/protect-gitignore", json={"path": str(tmp_path), "unstage": False})
    assert res.status_code == 200
    assert res.json()["status"] == "PROTECTED"
    assert (tmp_path / ".gitignore").exists()


# =============================================================================
# 10. THREAT MODELING, GIT HISTORY, VAULT, BADGE & CONTAINER AUDITOR TESTS
# =============================================================================

def test_threat_modeling_engine(tmp_path):
    dfile = tmp_path / "Dockerfile"
    dfile.write_text("FROM python:3.11\nEXPOSE 22\nEXPOSE 8080\n", encoding="utf-8")

    pyfile = tmp_path / "routes.py"
    pyfile.write_text("""
import pickle
@app.get("/admin/users")
def get_users():
    return pickle.loads(raw_data)
""", encoding="utf-8")

    engine = ThreatModelingEngine(str(tmp_path))
    rep = engine.analyze(tmp_path)

    assert rep.total_threats > 0
    categories = {t.category for t in rep.threats}
    assert "Information Disclosure" in categories or "Tampering" in categories or "Elevation of Privilege" in categories
    assert any("22" in p for p in rep.exposed_ports)
    assert any("/admin/users" in ep for ep in rep.entrypoints)


def test_vault_migrator(tmp_path):
    findings = [
        Finding(
            id="f1",
            rule_id="SEC-001",
            title="AWS Access Key",
            category=FindingCategory.SECRETS,
            severity=Severity.CRITICAL,
            file_path="config.py",
            line_start=1,
            line_end=1,
            code_snippet='AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"',
            owasp_category="A07:2021",
            cwe_id="CWE-798",
            description="desc",
            remediation="rem",
        )
    ]
    migrator = VaultMigrator(str(tmp_path))
    data = migrator.export(findings, out_dir=tmp_path)

    assert data["secret_count"] == 1
    assert "AWS_SECRET_KEY" in data["env_example"]
    assert "AWS_SECRET_KEY" in data["vault_json"]["data"]
    assert "kind: Secret" in data["k8s_yaml"]


def test_badge_generator():
    svg_pass = BadgeGenerator.generate_svg(95, "READY TO SHIP")
    assert "<svg" in svg_pass
    assert "#10b981" in svg_pass
    assert "95% passing" in svg_pass

    svg_block = BadgeGenerator.generate_svg(30, "BLOCKED")
    assert "#ef4444" in svg_block
    assert "30% blocked" in svg_block


def test_container_auditor(tmp_path):
    dfile = tmp_path / "Dockerfile"
    dfile.write_text("""
FROM node:18
ARG GITHUB_TOKEN=secret
RUN apt-get update && apt-get install -y gcc
RUN chmod 4755 /bin/mytool
CMD ["npm", "start"]
""", encoding="utf-8")

    auditor = ContainerAuditor(str(tmp_path))
    findings = auditor.audit_file(dfile, "Dockerfile", dfile.read_text(encoding="utf-8"))
    rule_ids = {f.rule_id for f in findings}

    assert "CONTAINER-001" in rule_ids  # Single stage build
    assert "CONTAINER-002" in rule_ids  # Missing HEALTHCHECK
    assert "CONTAINER-003" in rule_ids  # ARG Secret
    assert "CONTAINER-005" in rule_ids  # SUID bit


def test_cli_threat_model_and_vault(tmp_path):
    # Threat model CLI
    res_tm = runner.invoke(cli_app, ["threat-model", str(tmp_path)])
    assert res_tm.exit_code == 0
    assert "STRIDE Threat Model" in res_tm.output

    # Vault CLI
    res_v = runner.invoke(cli_app, ["vault", str(tmp_path)])
    assert res_v.exit_code == 0
    assert "Secret Vault & Environment Migrator" in res_v.output

    # Badge CLI
    badge_file = tmp_path / "my-badge.svg"
    res_b = runner.invoke(cli_app, ["badge", str(tmp_path), "-o", str(badge_file)])
    assert res_b.exit_code == 0
    assert badge_file.exists()


def test_api_enterprise_endpoints(tmp_path):
    # Threat model endpoint
    res_tm = client.get(f"/api/threat-model?path={tmp_path}")
    assert res_tm.status_code == 200
    assert "threats" in res_tm.json()

    # Badge endpoint
    res_b = client.get("/api/badge.svg")
    assert res_b.status_code == 200
    assert "image/svg+xml" in res_b.headers["content-type"]
    assert "<svg" in res_b.text

    # Container audit endpoint
    res_c = client.get(f"/api/container?path={tmp_path}")
    assert res_c.status_code == 200
    assert isinstance(res_c.json(), list)
