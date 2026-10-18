from cloudsentinel.collectors.demo_provider import load_demo_bundle
from cloudsentinel.engine.deduplication import compute_finding_fingerprint
from cloudsentinel.engine.risk_scoring import calculate_heuristic_risk
from cloudsentinel.engine.scanner import run_resource_scan


def test_heuristic_risk_score_calculation_and_bounds() -> None:
    res = calculate_heuristic_risk(impact=35, exposure=30, privilege=20)
    assert res.total_score == 85
    assert res.severity == "Critical"
    assert "Project heuristic" in res.explanation


def test_heuristic_risk_missing_input_returns_unknown() -> None:
    res = calculate_heuristic_risk(impact=None, exposure=20, privilege=10)
    assert res.total_score is None
    assert res.severity == "Unknown"


def test_fingerprint_is_deterministic_and_ignores_volatile_fields() -> None:
    fp1 = compute_finding_fingerprint(
        "NET-001", "sg-1", {"port": 22, "cidr": "0.0.0.0/0", "collected_at": "t1"}
    )
    fp2 = compute_finding_fingerprint(
        "NET-001", "sg-1", {"cidr": "0.0.0.0/0", "port": 22, "collected_at": "t2"}
    )
    assert fp1 == fp2


def test_scanner_runs_on_demo_bundle_and_finds_all_9_resource_and_event_issues() -> None:
    bundle = load_demo_bundle()
    scan_res = run_resource_scan(bundle)
    assert scan_res.status == "completed"
    assert scan_res.resources_scanned == 6
    assert scan_res.events_analyzed == 6
    rule_ids = {f["rule_id"] for f in scan_res.findings}
    assert rule_ids == {
        "NET-001",
        "NET-002",
        "NET-003",
        "S3-001",
        "IAM-001",
        "LOG-001",
        "IAM-002",
        "KEY-001",
        "AUTH-001",
    }
