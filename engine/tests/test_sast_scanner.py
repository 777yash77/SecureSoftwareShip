from pathlib import Path
from secureship.scanners.sast_scanner import SASTScanner


def test_python_sast_sqli_and_rce():
    scanner = SASTScanner()
    code = """
import os
import subprocess
import pickle
import hashlib

def bad_func(user_id, cmd, blob):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    os.system("echo " + cmd)
    subprocess.Popen("rm -rf " + cmd, shell=True)
    pickle.loads(blob)
    eval("2 + 2")
    hashlib.md5(b"secret")
    DEBUG = True
    """
    findings = scanner.scan_file(Path("test.py"), "test.py", code)
    rule_ids = {f.rule_id for f in findings}

    assert "SAST-PY-001" in rule_ids  # SQL Injection
    assert "SAST-PY-002" in rule_ids  # os.system Command Injection
    assert "SAST-PY-003" in rule_ids  # subprocess shell=True
    assert "SAST-PY-004" in rule_ids  # pickle.loads
    assert "SAST-PY-006" in rule_ids  # eval
    assert "SAST-PY-007" in rule_ids  # md5
    assert "SAST-PY-009" in rule_ids  # DEBUG = True


def test_javascript_sast_vulns():
    scanner = SASTScanner()
    code = """
const express = require('express');
const child_process = require('child_process');
const jwt = require('jsonwebtoken');

eval(userInput);
document.body.innerHTML = userContent;
db.query("SELECT * FROM users WHERE name = '" + name + "'");
child_process.exec("ping " + host);
const config = { rejectUnauthorized: false };
jwt.sign({ id: 1 }, "static-secret-hardcoded");
    """
    findings = scanner.scan_file(Path("app.js"), "app.js", code)
    rule_ids = {f.rule_id for f in findings}

    assert "SAST-JS-001" in rule_ids  # eval
    assert "SAST-JS-002" in rule_ids  # innerHTML
    assert "SAST-JS-003" in rule_ids  # SQL string concat
    assert "SAST-JS-004" in rule_ids  # child_process.exec
    assert "SAST-JS-005" in rule_ids  # rejectUnauthorized: false
    assert "SAST-JS-006" in rule_ids  # jwt.sign hardcoded secret
