"""Test suite for SecureShip Deep Enterprise Capabilities:
- License Compliance & Legal Risk Auditor
- Static Taint Analysis Engine (Source-to-Sink tracking)
- CI/CD Supply Chain Security Auditor
- Multi-Language SAST (C/C++, PHP, C#)
- Expanded Multi-Cloud Terraform Rules
- Expanded Secret Signatures (Slack, Twilio, SendGrid, Discord, MongoDB)
- New CLI Commands & FastAPI REST Endpoints
"""

import json
from pathlib import Path
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from secureship.cli import app as cli_app
from secureship.ci_cd_auditor import CICDAuditor
from secureship.license_checker import LicenseAuditor, LicenseRisk
from secureship.scanners.iac_scanner import IaCScanner
from secureship.scanners.sast_scanner import SASTScanner
from secureship.scanners.secrets_scanner import SecretsScanner
from secureship.server import app as api_app
from secureship.taint_analyzer import SinkType, TaintAnalyzer

runner = CliRunner()
client = TestClient(api_app)


def test_license_auditor_permissive_and_copyleft(tmp_path: Path):
    # Create package.json with permissive dependencies
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({
        "name": "my-app",
        "dependencies": {
            "express": "^4.19.2",
            "lodash": "^4.17.21"
        }
    }), encoding="utf-8")

    # Create requirements.txt with a GPL copyleft package
    req_txt = tmp_path / "requirements.txt"
    req_txt.write_text("flask==3.0.0\ngpl-sample==1.0.0\n", encoding="utf-8")

    auditor = LicenseAuditor(str(tmp_path))
    res = auditor.audit(policy="commercial")

    assert res["total_packages"] == 4
    # gpl-sample should be flagged as strong copyleft violation
    assert res["violations_count"] >= 1
    assert any(v["package"] == "gpl-sample" for v in res["violations"])
    assert res["status"] == "NON_COMPLIANT"


def test_static_taint_analyzer_python(tmp_path: Path):
    # Vulnerable Python file: request.args directly in cursor.execute
    vuln_py = tmp_path / "vuln.py"
    vuln_py.write_text(
        "from flask import request\n"
        "user_id = request.args.get('id')\n"
        "query = f'SELECT * FROM users WHERE id = {user_id}'\n"
        "cursor.execute(query)\n",
        encoding="utf-8"
    )

    # Clean Python file: input is sanitized with int() cast
    clean_py = tmp_path / "clean.py"
    clean_py.write_text(
        "from flask import request\n"
        "user_id = int(request.args.get('id'))\n"
        "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n",
        encoding="utf-8"
    )

    analyzer = TaintAnalyzer(str(tmp_path))
    res = analyzer.analyze()

    assert res["total_taint_findings"] >= 1
    assert any(f["file"] == "vuln.py" and f["sink_type"] == SinkType.SQL_INJECTION.value for f in res["findings"])
    # clean.py should NOT have taint findings
    assert not any(f["file"] == "clean.py" for f in res["findings"])


def test_static_taint_analyzer_js(tmp_path: Path):
    vuln_js = tmp_path / "server.js"
    vuln_js.write_text(
        "const cmd = req.query.cmd;\n"
        "child_process.exec(cmd);\n",
        encoding="utf-8"
    )

    analyzer = TaintAnalyzer(str(tmp_path))
    res = analyzer.analyze()

    assert res["total_taint_findings"] >= 1
    assert any(f["file"] == "server.js" for f in res["findings"])


def test_cicd_pipeline_auditor(tmp_path: Path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)

    wf_file = wf_dir / "ci.yml"
    wf_file.write_text(
        "name: CI\n"
        "on:\n"
        "  pull_request_target:\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v3\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - name: Print Title\n"
        "        run: echo \"${{ github.event.issue.title }}\"\n",
        encoding="utf-8"
    )

    auditor = CICDAuditor(str(tmp_path))
    res = auditor.audit()

    assert res["total_findings"] >= 3
    rule_ids = {f["rule_id"] for f in res["findings"]}
    assert "CICD-GH-001" in rule_ids  # Pwn-request
    assert "CICD-GH-002" in rule_ids  # Unpinned action
    assert "CICD-GH-003" in rule_ids  # Script injection
    assert "CICD-GH-004" in rule_ids  # write-all permissions


def test_c_cpp_sast_rules(tmp_path: Path):
    c_file = tmp_path / "main.c"
    c_file.write_text(
        "#include <stdio.h>\n"
        "#include <string.h>\n"
        "int main() {\n"
        "    char buf[100];\n"
        "    strcpy(buf, \"danger\");\n"
        "    gets(buf);\n"
        "    system(\"ls\");\n"
        "    return 0;\n"
        "}\n",
        encoding="utf-8"
    )

    scanner = SASTScanner()
    findings = scanner.scan_file(c_file, "main.c", c_file.read_text(encoding="utf-8"))

    rule_ids = {f.rule_id for f in findings}
    assert "SAST-C-001" in rule_ids  # strcpy
    assert "SAST-C-002" in rule_ids  # gets
    assert "SAST-C-004" in rule_ids  # system


def test_php_sast_rules(tmp_path: Path):
    php_file = tmp_path / "index.php"
    php_file.write_text(
        "<?php\n"
        "$code = $_GET['code'];\n"
        "eval($code);\n"
        "$page = $_GET['page'];\n"
        "include($page);\n"
        "$data = $_POST['data'];\n"
        "$obj = unserialize($data);\n",
        encoding="utf-8"
    )

    scanner = SASTScanner()
    findings = scanner.scan_file(php_file, "index.php", php_file.read_text(encoding="utf-8"))

    rule_ids = {f.rule_id for f in findings}
    assert "SAST-PHP-001" in rule_ids  # eval
    assert "SAST-PHP-002" in rule_ids  # include
    assert "SAST-PHP-003" in rule_ids  # unserialize


def test_csharp_sast_rules(tmp_path: Path):
    cs_file = tmp_path / "Program.cs"
    cs_file.write_text(
        "using System;\n"
        "using System.Runtime.Serialization.Formatters.Binary;\n"
        "class Program {\n"
        "    static void Main() {\n"
        "        var formatter = new BinaryFormatter();\n"
        "    }\n"
        "}\n",
        encoding="utf-8"
    )

    scanner = SASTScanner()
    findings = scanner.scan_file(cs_file, "Program.cs", cs_file.read_text(encoding="utf-8"))

    rule_ids = {f.rule_id for f in findings}
    assert "SAST-CS-001" in rule_ids  # BinaryFormatter


def test_terraform_rds_and_iam_rules(tmp_path: Path):
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        'resource "aws_db_instance" "default" {\n'
        '  allocated_storage   = 10\n'
        '  engine              = "mysql"\n'
        '  publicly_accessible = true\n'
        '}\n'
        'data "aws_iam_policy_document" "policy" {\n'
        '  statement {\n'
        '    effect = "Allow"\n'
        '    actions = ["*"]\n'
        '    resources = ["*"]\n'
        '  }\n'
        '}\n',
        encoding="utf-8"
    )

    scanner = IaCScanner()
    findings = scanner.scan_file(tf_file, "main.tf", tf_file.read_text(encoding="utf-8"))

    rule_ids = {f.rule_id for f in findings}
    assert "IAC-TF-004" in rule_ids  # publicly accessible RDS
    assert "IAC-TF-005" in rule_ids  # wildcard IAM actions


def test_new_secrets_detection(tmp_path: Path):
    sec_file = tmp_path / "tokens.py"
    dummy_slack = "xo" + "xb-123456789012-123456789012-abcdefghijklmnopqrstuvwx"
    dummy_twilio = "A" + "C1234567890abcdef1234567890abcdef"
    dummy_sg = "S" + "G.1234567890abcdefghijkl.1234567890abcdefghijklmnopqrstuvwxyz1234567"
    dummy_mongo = "mongodb+srv://admin:" + "Sup3rS3cret" + "@cluster0.abcde.mongodb.net/prod"

    sec_file.write_text(
        f'slack_bot = "{dummy_slack}"\n'
        f'twilio_sid = "{dummy_twilio}"\n'
        f'sendgrid = "{dummy_sg}"\n'
        f'mongo_uri = "{dummy_mongo}"\n',
        encoding="utf-8"
    )

    scanner = SecretsScanner()
    findings = scanner.scan_file(sec_file, "tokens.py", sec_file.read_text(encoding="utf-8"))

    rule_ids = {f.rule_id for f in findings}
    assert "SEC-012" in rule_ids  # Slack bot token
    assert "SEC-014" in rule_ids  # Twilio SID
    assert "SEC-015" in rule_ids  # SendGrid key
    assert "SEC-022" in rule_ids  # MongoDB URI


def test_cli_commands_license_taint_ciaudit(tmp_path: Path):
    # Test secureship license
    res_lic = runner.invoke(cli_app, ["license", str(tmp_path), "--format", "json"])
    assert res_lic.exit_code == 0
    data_lic = json.loads(res_lic.output)
    assert "compliance_score" in data_lic

    # Test secureship taint
    res_taint = runner.invoke(cli_app, ["taint", str(tmp_path), "--format", "json"])
    assert res_taint.exit_code == 0
    data_taint = json.loads(res_taint.output)
    assert "total_taint_findings" in data_taint

    # Test secureship ci-audit
    res_ci = runner.invoke(cli_app, ["ci-audit", str(tmp_path), "--format", "json"])
    assert res_ci.exit_code == 0
    data_ci = json.loads(res_ci.output)
    assert "total_findings" in data_ci


def test_api_license_taint_ciaudit(tmp_path: Path):
    r_lic = client.get(f"/api/license?path={tmp_path}")
    assert r_lic.status_code == 200
    assert "compliance_score" in r_lic.json()

    r_taint = client.get(f"/api/taint?path={tmp_path}")
    assert r_taint.status_code == 200
    assert "total_taint_findings" in r_taint.json()

    r_ci = client.get(f"/api/ci-audit?path={tmp_path}")
    assert r_ci.status_code == 200
    assert "total_findings" in r_ci.json()
