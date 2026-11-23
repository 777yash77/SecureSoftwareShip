from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional


GITHUB_ACTIONS_TEMPLATE = """# SecureShip Shift-Left DevSecOps Gate
# Automated Static Application Security Testing (SAST), Secrets, IaC, and SCA Scanning
name: SecureShip Shift-Left Security Gate

on:
  push:
    branches: [ main, master, develop ]
  pull_request:
    branches: [ main, master ]

jobs:
  secureship-audit:
    name: Shift-Left Security Audit
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install SecureShip CLI
        run: |
          python -m pip install --upgrade pip
          pip install secureship

      - name: Run SecureShip Quality Gate Scan
        run: |
          secureship scan . --fail-on high --format sarif -o secureship-results.sarif

      - name: Upload SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secureship-results.sarif
          category: secureship-shift-left
"""

GITLAB_CI_TEMPLATE = """# SecureShip Shift-Left DevSecOps Pipeline
# Automated vulnerability gate for GitLab CI/CD

stages:
  - test
  - security-gate

secureship:shift-left:
  stage: security-gate
  image: python:3.11-slim
  before_script:
    - pip install --upgrade pip
    - pip install secureship
  script:
    - secureship scan . --fail-on high --format json -o gl-security-report.json
  artifacts:
    name: "secureship-audit-$CI_COMMIT_REF_SLUG"
    when: always
    paths:
      - gl-security-report.json
    expire_in: 30 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
"""

AZURE_PIPELINES_TEMPLATE = """# SecureShip DevSecOps Shift-Left Gate
# Azure DevOps Pipeline

trigger:
  branches:
    include:
      - main
      - master

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.11'
  displayName: 'Use Python 3.11'

- script: |
    python -m pip install --upgrade pip
    pip install secureship
  displayName: 'Install SecureShip DevSecOps'

- script: |
    secureship scan . --fail-on high --format json -o secureship-report.json
  displayName: 'Execute Shift-Left Gate Scan'
"""

BITBUCKET_PIPELINES_TEMPLATE = """# SecureShip Shift-Left DevSecOps Gate
# Bitbucket Pipelines Configuration

image: python:3.11-slim

pipelines:
  default:
    - step:
        name: SecureShip Security Audit
        caches:
          - pip
        script:
          - pip install secureship
          - secureship scan . --fail-on high
"""

JENKINSFILE_TEMPLATE = """// SecureShip Shift-Left DevSecOps Pipeline
pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('SecureShip Security Gate') {
            steps {
                sh '''
                    pip install --upgrade pip
                    pip install secureship
                    secureship scan . --fail-on high --format sarif -o secureship.sarif
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'secureship.sarif', fingerprint: true, allowEmptyArchive: true
        }
    }
}
"""


class CIGenerator:
    """Generates continuous integration pipeline configuration templates for automated shift-left security enforcement."""

    TEMPLATES = {
        "github": (".github/workflows/secureship.yml", GITHUB_ACTIONS_TEMPLATE),
        "gitlab": (".gitlab-ci.yml", GITLAB_CI_TEMPLATE),
        "azure": ("azure-pipelines.yml", AZURE_PIPELINES_TEMPLATE),
        "bitbucket": ("bitbucket-pipelines.yml", BITBUCKET_PIPELINES_TEMPLATE),
        "jenkins": ("Jenkinsfile", JENKINSFILE_TEMPLATE),
    }

    def __init__(self, target_path: Optional[str] = None):
        self.target_path = Path(target_path).resolve() if target_path else Path.cwd()

    def generate(
        self,
        platform: str,
        target_dir: Optional[Path] = None,
        overwrite: bool = False,
    ) -> Dict[str, Any]:
        root = (target_dir or self.target_path).resolve()
        platform_key = platform.lower()

        if platform_key not in self.TEMPLATES:
            raise ValueError(f"Unknown CI platform '{platform}'. Choose from: {', '.join(self.TEMPLATES.keys())}")

        rel_path, content = self.TEMPLATES[platform_key]
        dest_file = root / rel_path

        if dest_file.exists() and not overwrite:
            return {
                "platform": platform_key,
                "file_path": str(dest_file),
                "created": False,
                "reason": "File already exists. Pass overwrite=True to overwrite.",
            }

        dest_file.parent.mkdir(parents=True, exist_ok=True)
        dest_file.write_text(content.strip() + "\n", encoding="utf-8")

        return {
            "platform": platform_key,
            "file_path": str(dest_file),
            "relative_path": rel_path,
            "created": True,
        }

    def generate_all(self, target_dir: Optional[Path] = None, overwrite: bool = False) -> List[Dict[str, Any]]:
        results = []
        for p in self.TEMPLATES:
            results.append(self.generate(p, target_dir=target_dir, overwrite=overwrite))
        return results
