from pathlib import Path
from secureship.scanners.iac_scanner import IaCScanner


def test_iac_dockerfile():
    scanner = IaCScanner()
    content = """
    FROM python:latest
    ENV API_KEY="sk_live_1234567890abcdef"
    WORKDIR /app
    COPY . .
    CMD ["python", "main.py"]
    """
    findings = scanner.scan_file(Path("Dockerfile"), "Dockerfile", content)
    rule_ids = {f.rule_id for f in findings}
    assert "IAC-DOCKER-001" in rule_ids  # Missing USER (root)
    assert "IAC-DOCKER-002" in rule_ids  # Unpinned :latest
    assert "IAC-DOCKER-003" in rule_ids  # Sensitive API key in ENV


def test_iac_docker_compose():
    scanner = IaCScanner()
    content = """
    version: '3'
    services:
      app:
        privileged: true
        ports:
          - "5432:5432"
    """
    findings = scanner.scan_file(Path("docker-compose.yml"), "docker-compose.yml", content)
    rule_ids = {f.rule_id for f in findings}
    assert "IAC-COMPOSE-001" in rule_ids  # Privileged
    assert "IAC-COMPOSE-002" in rule_ids  # Exposed DB port 5432


def test_iac_k8s():
    scanner = IaCScanner()
    content = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: insecure-pod
    spec:
      containers:
        - name: app
          image: app:latest
          securityContext:
            privileged: true
    """
    findings = scanner.scan_file(Path("pod.yaml"), "pod.yaml", content)
    rule_ids = {f.rule_id for f in findings}
    assert "IAC-K8S-001" in rule_ids  # Missing resources
    assert "IAC-K8S-002" in rule_ids  # Privileged context
