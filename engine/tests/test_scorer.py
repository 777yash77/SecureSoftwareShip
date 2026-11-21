import uuid
from secureship.models import Finding, FindingCategory, Severity, ShipStatus
from secureship.scorer import Scorer, IgnoreMatcher


def make_dummy_finding(sev: Severity) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        rule_id="TEST-001",
        title="Test Vulnerability",
        category=FindingCategory.SAST,
        severity=sev,
        file_path="test.py",
        line_start=1,
        line_end=1,
        code_snippet="bad_code()",
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-89",
        description="test",
        remediation="fix it",
    )


def test_scorer_deductions_and_status():
    # Clean project
    assert Scorer.calculate_score([]) == 100
    assert Scorer.determine_ship_status(100, 0) == ShipStatus.READY_TO_SHIP

    # Critical penalty: -25
    crit_finding = make_dummy_finding(Severity.CRITICAL)
    score_with_crit = Scorer.calculate_score([crit_finding])
    assert score_with_crit == 75
    # Any critical should BLOCK
    assert Scorer.determine_ship_status(score_with_crit, 1) == ShipStatus.BLOCKED

    # Low penalty: -2, Medium: -5, High: -15
    low_finding = make_dummy_finding(Severity.LOW)
    assert Scorer.calculate_score([low_finding]) == 98
    assert Scorer.determine_ship_status(98, 0) == ShipStatus.READY_TO_SHIP

    # High findings dropping score below 80 -> NEEDS REVIEW
    high1 = make_dummy_finding(Severity.HIGH)
    high2 = make_dummy_finding(Severity.HIGH)
    score_needs_review = Scorer.calculate_score([high1, high2])
    assert score_needs_review == 70
    assert Scorer.determine_ship_status(score_needs_review, 0) == ShipStatus.NEEDS_REVIEW


def test_inline_suppression_parsing():
    assert IgnoreMatcher.is_line_suppressed("x = 1 # secureship-ignore")
    assert IgnoreMatcher.is_line_suppressed("const y = 2; // secureship-ignore")
    assert IgnoreMatcher.is_line_suppressed("eval(x); // secureship-ignore: SAST-JS-001", "SAST-JS-001")
    assert not IgnoreMatcher.is_line_suppressed("x = 1 # normal comment")
