import csv
import io
import json
from pathlib import Path

from cloudsentinel.collectors.demo_provider import load_demo_bundle
from cloudsentinel.db.repository import CloudSentinelRepository
from cloudsentinel.engine.scanner import run_resource_scan
from cloudsentinel.reports.report_generator import (
    generate_csv_report,
    generate_json_report,
)


def test_tc14_json_and_csv_exports_include_provenance_and_timestamps(tmp_path: Path) -> None:
    repo = CloudSentinelRepository(db_path=tmp_path / "export_test.db")
    bundle = load_demo_bundle()
    scan_res = run_resource_scan(bundle)
    scan_id = repo.save_scan_and_sync_findings(scan_res)

    scan_record = repo.get_scan_by_id(scan_id)
    findings = repo.list_findings(scan_id=scan_id)

    json_report = generate_json_report(scan_record, findings)
    parsed = json.loads(json_report)
    assert parsed["report_metadata"]["application"] == "CloudSentinel"
    assert "generated_at_utc" in parsed["report_metadata"]
    assert parsed["report_metadata"]["scan_summary"]["provenance_label"] == "Synthetic Demo"
    assert len(parsed["findings"]) == 9

    csv_report = generate_csv_report(scan_record, findings)
    reader = list(csv.DictReader(io.StringIO(csv_report)))
    assert len(reader) == 9
    assert reader[0]["provenance_label"] == "Synthetic Demo"
    assert reader[0]["scan_status"] == "completed"
    assert "report_generated_at_utc" in reader[0]


def test_fr05_repository_filtering_by_family_severity_and_search(tmp_path: Path) -> None:
    repo = CloudSentinelRepository(db_path=tmp_path / "filter_test.db")
    bundle = load_demo_bundle()
    repo.save_scan_and_sync_findings(run_resource_scan(bundle))

    net_findings = repo.list_findings(rule_family="NET")
    assert {f["rule_id"] for f in net_findings} == {"NET-001", "NET-002", "NET-003"}

    crit_findings = repo.list_findings(severity="Critical")
    assert {f["rule_id"] for f in crit_findings} == {"S3-001", "IAM-001", "LOG-001"}

    s3_search = repo.list_findings(search_query="demo-public-backups")
    assert len(s3_search) == 1
    assert s3_search[0]["rule_id"] == "S3-001"
