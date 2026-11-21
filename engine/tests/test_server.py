import pytest
from fastapi.testclient import TestClient
from secureship.server import app

client = TestClient(app)


def test_api_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_api_scan_content():
    response = client.post(
        "/api/scan/content",
        json={
            "file_path": "sample.py",
            "content": "import hashlib\nhashlib.md5(b'test')\n",
        },
    )
    assert response.status_code == 200
    findings = response.json()
    assert len(findings) >= 1
    assert any(f["rule_id"] == "SAST-PY-007" for f in findings)


def test_api_scan_directory():
    response = client.post(
        "/api/scan",
        json={"path": "./demo-vulnerable-app"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "summary" in data
    assert "findings" in data
    assert data["summary"]["total_findings"] > 5
    assert data["summary"]["ship_status"] == "BLOCKED"


def test_api_reports():
    # Trigger scan first to populate history
    client.post("/api/scan", json={"path": "./demo-vulnerable-app"})

    html_resp = client.get("/api/report/html")
    assert html_resp.status_code == 200
    assert "SecureShip Security Report" in html_resp.text

    json_resp = client.get("/api/report/json")
    assert json_resp.status_code == 200
    assert "scan_id" in json_resp.text
