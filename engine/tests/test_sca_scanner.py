from pathlib import Path
from secureship.scanners.sca_scanner import SCAScanner


def test_sca_package_json():
    scanner = SCAScanner()
    content = """{
      "dependencies": {
        "lodash": "4.17.15",
        "axios": "0.21.1"
      }
    }"""
    findings = scanner.scan_file(Path("package.json"), "package.json", content)
    titles = [f.title for f in findings]
    assert any("lodash" in t for t in titles)
    assert any("axios" in t for t in titles)


def test_sca_requirements_txt():
    scanner = SCAScanner()
    content = "requests==2.25.0\nurllib3==1.26.4\n"
    findings = scanner.scan_file(Path("requirements.txt"), "requirements.txt", content)
    titles = [f.title for f in findings]
    assert any("Requests" in t or "requests" in t for t in titles)
    assert any("urllib3" in t for t in titles)


def test_sca_pom_xml():
    scanner = SCAScanner()
    content = """<project>
        <dependencies>
            <dependency>
                <groupId>org.apache.logging.log4j</groupId>
                <artifactId>log4j-core</artifactId>
                <version>2.14.1</version>
            </dependency>
        </dependencies>
    </project>"""
    findings = scanner.scan_file(Path("pom.xml"), "pom.xml", content)
    assert any("Log4j" in f.title or "Log4Shell" in f.title for f in findings)
