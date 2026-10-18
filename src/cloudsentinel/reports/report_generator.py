import csv
import io
import json
from datetime import UTC, datetime
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_json_report(
    scan: dict[str, Any] | None,
    findings: list[dict[str, Any]],
) -> str:
    """
    Generate a structured JSON report for a specific scan and its findings.
    Explicitly labels source provenance, scan status, and generation timestamp (Rule #11 & TC-14).
    """
    scan_meta = (
        {
            "scan_id": scan["id"],
            "provider": scan["provider"],
            "provenance_label": scan["provenance_label"],
            "region": scan["region"],
            "status": scan["status"],
            "resources_scanned": scan["resources_scanned"],
            "errors_count": scan["errors_count"],
            "started_at": scan["started_at"],
            "finished_at": scan["finished_at"],
            "diagnostics": scan.get("diagnostics", []),
        }
        if scan
        else {
            "scan_id": None,
            "provenance_label": "Synthetic Demo",
            "status": "no_scan_selected",
        }
    )

    payload = {
        "report_metadata": {
            "application": "CloudSentinel",
            "generated_at_utc": _utc_now_iso(),
            "heuristic_notice": (
                "Risk scores (0-100) are illustrative project heuristics (Impact + Exposure + Privilege), "
                "not breach probability."
            ),
            "scan_summary": scan_meta,
            "total_findings_exported": len(findings),
        },
        "findings": [
            {
                "rule_id": f["rule_id"],
                "title": f["title"],
                "severity": f["severity"],
                "risk_score": f["risk_score"],
                "status": f["status"],
                "resource_type": f["resource_type"],
                "resource_id": f["resource_id"],
                "region": f["region"],
                "fingerprint": f["fingerprint"],
                "first_seen": f["first_seen"],
                "last_seen": f["last_seen"],
                "evidence": f["evidence"],
                "score_breakdown": f["score_breakdown"],
                "recommendation": f["recommendation"],
                "analyst_note": f.get("analyst_note", ""),
                "suppressed_by": f.get("suppressed_by", ""),
                "suppressed_reason": f.get("suppressed_reason", ""),
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2)


def generate_csv_report(
    scan: dict[str, Any] | None,
    findings: list[dict[str, Any]],
) -> str:
    """
    Generate a flat CSV report for analyst spreadsheets with provenance and scan timestamps (TC-14).
    """
    output = io.StringIO()
    fieldnames = [
        "report_generated_at_utc",
        "scan_id",
        "provenance_label",
        "scan_status",
        "rule_id",
        "severity",
        "risk_score",
        "status",
        "resource_type",
        "resource_id",
        "region",
        "title",
        "recommendation",
        "fingerprint",
        "first_seen",
        "last_seen",
        "analyst_note",
        "suppressed_reason",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    gen_time = _utc_now_iso()
    provenance = scan["provenance_label"] if scan else "Synthetic Demo"
    scan_status = scan["status"] if scan else "unknown"
    scan_id = scan["id"] if scan else ""

    for f in findings:
        writer.writerow(
            {
                "report_generated_at_utc": gen_time,
                "scan_id": f.get("scan_id", scan_id),
                "provenance_label": provenance,
                "scan_status": scan_status,
                "rule_id": f["rule_id"],
                "severity": f["severity"],
                "risk_score": f["risk_score"],
                "status": f["status"],
                "resource_type": f["resource_type"],
                "resource_id": f["resource_id"],
                "region": f["region"],
                "title": f["title"],
                "recommendation": f["recommendation"],
                "fingerprint": f["fingerprint"],
                "first_seen": f["first_seen"],
                "last_seen": f["last_seen"],
                "analyst_note": f.get("analyst_note", ""),
                "suppressed_reason": f.get("suppressed_reason", ""),
            }
        )

    return output.getvalue()
