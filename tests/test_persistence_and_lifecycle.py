from pathlib import Path

import pytest

from cloudsentinel.collectors.demo_provider import CollectionBundle, load_demo_bundle
from cloudsentinel.db.repository import CloudSentinelRepository
from cloudsentinel.engine.scanner import run_resource_scan


def test_tc11_repeat_scan_deduplicates_findings(tmp_path: Path) -> None:
    db_file = tmp_path / "test_cloudsentinel.db"
    repo = CloudSentinelRepository(db_path=db_file)

    bundle = load_demo_bundle()
    scan1 = run_resource_scan(bundle)
    scan1_id = repo.save_scan_and_sync_findings(scan1)

    findings_after_first = repo.list_findings()
    assert len(findings_after_first) == 9  # 5 resource rules + 4 event rules

    # Run a second scan on identical bundle -> must update scan_id, not duplicate rows
    scan2 = run_resource_scan(bundle)
    scan2_id = repo.save_scan_and_sync_findings(scan2)
    assert scan2_id > scan1_id

    findings_after_second = repo.list_findings()
    assert len(findings_after_second) == 9
    assert all(f["scan_id"] == scan2_id for f in findings_after_second)


def test_tc12_clean_rescan_marks_absent_finding_resolved(tmp_path: Path) -> None:
    db_file = tmp_path / "test_cloudsentinel.db"
    repo = CloudSentinelRepository(db_path=db_file)

    bundle = load_demo_bundle()
    repo.save_scan_and_sync_findings(run_resource_scan(bundle))
    assert len(repo.list_findings(status="Open")) == 9

    safe_resources = [r for r in bundle.resources if r["resource_id"] == "sg-demo-safe-003"]
    clean_bundle = CollectionBundle(
        source="synthetic_demo",
        provenance_label="Synthetic Demo",
        collected_at="2026-10-16T11:00:00Z",
        resources=safe_resources,
        events=[],
        diagnostics=[],
    )
    clean_scan = run_resource_scan(clean_bundle)
    assert clean_scan.status == "completed"
    repo.save_scan_and_sync_findings(clean_scan)

    assert len(repo.list_findings(status="Open")) == 0
    assert len(repo.list_findings(status="Resolved")) == 9


def test_tc13_failed_scan_does_not_resolve_existing_findings(tmp_path: Path) -> None:
    db_file = tmp_path / "test_cloudsentinel.db"
    repo = CloudSentinelRepository(db_path=db_file)

    bundle = load_demo_bundle()
    repo.save_scan_and_sync_findings(run_resource_scan(bundle))
    assert len(repo.list_findings(status="Open")) == 9

    failed_bundle = CollectionBundle(
        source="synthetic_demo",
        provenance_label="Synthetic Demo",
        collected_at="2026-10-16T12:00:00Z",
        resources=[],
        events=[],
        diagnostics=["Simulated collector failure"],
    )
    failed_scan = run_resource_scan(failed_bundle)
    assert failed_scan.status == "failed"
    repo.save_scan_and_sync_findings(failed_scan)

    assert len(repo.list_findings(status="Open")) == 9
    assert len(repo.list_findings(status="Resolved")) == 0


def test_suppression_requires_reason_and_writes_audit_log(tmp_path: Path) -> None:
    db_file = tmp_path / "test_cloudsentinel.db"
    repo = CloudSentinelRepository(db_path=db_file)

    bundle = load_demo_bundle()
    repo.save_scan_and_sync_findings(run_resource_scan(bundle))
    target_fp = repo.list_findings()[0]["fingerprint"]

    with pytest.raises(ValueError, match="requires a non-empty justification"):
        repo.update_finding_status(target_fp, new_status="Suppressed", note_or_reason="   ")

    repo.update_finding_status(
        target_fp,
        new_status="Suppressed",
        actor_label="ayush_analyst",
        note_or_reason="Approved lab bastion exception",
    )
    suppressed = repo.list_findings(status="Suppressed")
    assert len(suppressed) == 1
    assert suppressed[0]["suppressed_reason"] == "Approved lab bastion exception"

    logs = repo.list_audit_logs()
    assert len(logs) == 1
    assert logs[0]["actor_label"] == "ayush_analyst"
