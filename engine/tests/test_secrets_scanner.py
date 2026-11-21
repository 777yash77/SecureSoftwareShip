from pathlib import Path
from secureship.scanners.secrets_scanner import SecretsScanner, calculate_shannon_entropy


def test_shannon_entropy():
    # Low entropy repeated string
    assert calculate_shannon_entropy("aaaaaaaa") == 0.0
    # High entropy random string
    assert calculate_shannon_entropy("dK9#mQ2$xP8*vL1@") > 3.5


def test_detect_aws_and_github_keys():
    scanner = SecretsScanner()
    content = """
    aws_key = "AKIA1111222233334444"
    gh_token = "ghp_111122223333444455556666777788889999"
    # Safe placeholder should be ignored
    safe_key = "AKIAEXAMPLETESTPLACEHOLDER"
    """
    findings = scanner.scan_file(Path("test.py"), "test.py", content)
    rule_ids = [f.rule_id for f in findings]
    assert "SEC-001" in rule_ids
    assert "SEC-002" in rule_ids


def test_detect_db_uri():
    scanner = SecretsScanner()
    content = 'DATABASE_URL="postgres://admin:SuperSecretPass99@db.prod.internal:5432/app"'
    findings = scanner.scan_file(Path("config.py"), "config.py", content)
    assert any(f.rule_id == "SEC-004" for f in findings)


def test_detect_private_key():
    scanner = SecretsScanner()
    content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    findings = scanner.scan_file(Path("id_rsa"), "id_rsa", content)
    assert any(f.rule_id == "SEC-003" for f in findings)


def test_inline_suppression():
    scanner = SecretsScanner()
    content = 'aws_key = "AKIA1111222233334444" # secureship-ignore'
    findings = scanner.scan_file(Path("test.py"), "test.py", content)
    assert len(findings) == 0
