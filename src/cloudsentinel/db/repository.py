import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cloudsentinel.collectors.cloudtrail_importer import redact_sensitive_fields
from cloudsentinel.db.models import (
    ALLOWED_FINDING_STATUSES,
    ALLOWED_SCAN_STATUSES,
    ALLOWED_SEVERITIES,
    init_db,
)
from cloudsentinel.engine.scanner import ScanExecutionResult


def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class CloudSentinelRepository:
    """SQLite persistence layer for scans, findings, events, lifecycle transitions, and audit logs."""

    def __init__(self, db_path: str | Path = "data/cloudsentinel.db") -> None:
        self.db_path = Path(db_path)
        init_db(self.db_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def save_events(self, events: list[dict[str, Any]]) -> int:
        """Persist normalized and redacted CloudTrail events into SQLite `events` table."""
        inserted = 0
        with self._connect() as conn:
            for e in events:
                redacted = redact_sensitive_fields(e)
                conn.execute(
                    """
                    INSERT OR REPLACE INTO events (
                        source_event_id, event_time, event_name, actor,
                        source_ip, region, status, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(e["event_id"]),
                        str(e["event_time"]),
                        str(e["event_name"]),
                        str(e["actor"]).strip(),
                        str(e["source_ip"]),
                        str(e["region"]),
                        str(e["status"]),
                        json.dumps(redacted, sort_keys=True),
                    ),
                )
                inserted += 1
        return inserted

    def list_events(
        self,
        actor: str | None = None,
        event_name: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query persisted CloudTrail audit events with optional filters."""
        query = "SELECT * FROM events WHERE 1=1"
        params: list[Any] = []
        if actor and actor != "All":
            query += " AND actor = ?"
            params.append(actor)
        if event_name and event_name != "All":
            query += " AND event_name = ?"
            params.append(event_name)
        if status and status != "All":
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY event_time DESC, id DESC"

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        results: list[dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            item["details"] = json.loads(item["raw_json"]).get("details", {})
            results.append(item)
        return results

    def save_scan_and_sync_findings(
        self,
        scan_result: ScanExecutionResult,
        provider: str = "synthetic_demo",
        region: str = "us-east-1",
    ) -> int:
        if scan_result.status not in ALLOWED_SCAN_STATUSES:
            raise ValueError(f"Invalid scan status: {scan_result.status}")

        now = _utc_now_iso()
        seen_fingerprints: set[str] = set()

        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scans (
                    provider, provenance_label, region, started_at, finished_at,
                    status, resources_scanned, errors_count, diagnostics_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    provider,
                    scan_result.provenance_label,
                    region,
                    now,
                    now,
                    scan_result.status,
                    scan_result.resources_scanned,
                    len(scan_result.diagnostics),
                    json.dumps(scan_result.diagnostics),
                ),
            )
            scan_id = int(cursor.lastrowid)

            for f in scan_result.findings:
                severity = f.get("severity", "Unknown")
                if severity not in ALLOWED_SEVERITIES:
                    raise ValueError(f"Invalid finding severity: {severity}")

                fp = f["fingerprint"]
                seen_fingerprints.add(fp)

                existing = conn.execute(
                    "SELECT id, status FROM findings WHERE fingerprint = ?",
                    (fp,),
                ).fetchone()

                if existing is None:
                    conn.execute(
                        """
                        INSERT INTO findings (
                            scan_id, rule_id, resource_id, resource_type, region,
                            severity, risk_score, title, evidence_json,
                            score_breakdown_json, recommendation, status,
                            fingerprint, first_seen, last_seen
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?, ?)
                        """,
                        (
                            scan_id,
                            f["rule_id"],
                            f["resource_id"],
                            f["resource_type"],
                            f.get("region", region),
                            severity,
                            f["risk_score"],
                            f["title"],
                            json.dumps(f["evidence"], sort_keys=True),
                            json.dumps(f["score_breakdown"], sort_keys=True),
                            f["recommendation"],
                            fp,
                            now,
                            now,
                        ),
                    )
                else:
                    new_status = "Open" if existing["status"] == "Resolved" else existing["status"]
                    conn.execute(
                        """
                        UPDATE findings
                        SET scan_id = ?,
                            severity = ?,
                            risk_score = ?,
                            evidence_json = ?,
                            score_breakdown_json = ?,
                            status = ?,
                            last_seen = ?
                        WHERE fingerprint = ?
                        """,
                        (
                            scan_id,
                            severity,
                            f["risk_score"],
                            json.dumps(f["evidence"], sort_keys=True),
                            json.dumps(f["score_breakdown"], sort_keys=True),
                            new_status,
                            now,
                            fp,
                        ),
                    )

            if scan_result.status == "completed":
                active_rows = conn.execute(
                    "SELECT fingerprint FROM findings WHERE status IN ('Open', 'Acknowledged')"
                ).fetchall()
                for row in active_rows:
                    fp = row["fingerprint"]
                    if fp not in seen_fingerprints:
                        conn.execute(
                            "UPDATE findings SET status = 'Resolved', scan_id = ? WHERE fingerprint = ?",
                            (scan_id, fp),
                        )

        return scan_id

    def update_finding_status(
        self,
        fingerprint: str,
        new_status: str,
        actor_label: str = "local_analyst",
        note_or_reason: str = "",
    ) -> None:
        if new_status not in ALLOWED_FINDING_STATUSES:
            raise ValueError(f"Unsupported status '{new_status}'. Allowed: {sorted(ALLOWED_FINDING_STATUSES)}")

        cleaned_reason = note_or_reason.strip()
        if new_status == "Suppressed" and not cleaned_reason:
            raise ValueError("Suppressed status requires a non-empty justification/reason.")

        now = _utc_now_iso()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, status FROM findings WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if row is None:
                raise KeyError(f"No finding found with fingerprint: {fingerprint}")

            old_status = row["status"]
            if new_status == "Suppressed":
                conn.execute(
                    """
                    UPDATE findings
                    SET status = ?, suppressed_by = ?, suppressed_reason = ?, analyst_note = ?
                    WHERE fingerprint = ?
                    """,
                    (new_status, actor_label, cleaned_reason, cleaned_reason, fingerprint),
                )
            else:
                conn.execute(
                    "UPDATE findings SET status = ?, analyst_note = ? WHERE fingerprint = ?",
                    (new_status, cleaned_reason, fingerprint),
                )

            conn.execute(
                """
                INSERT INTO audit_log (action, actor_label, timestamp, details_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    "finding_status_change",
                    actor_label,
                    now,
                    json.dumps(
                        {
                            "fingerprint": fingerprint,
                            "old_status": old_status,
                            "new_status": new_status,
                            "reason": cleaned_reason,
                        }
                    ),
                ),
            )

    def list_findings(
        self,
        status: str | None = None,
        severity: str | None = None,
        rule_family: str | None = None,
        search_query: str | None = None,
        scan_id: int | None = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM findings WHERE 1=1"
        params: list[Any] = []
        if status and status != "All":
            query += " AND status = ?"
            params.append(status)
        if severity and severity != "All":
            query += " AND severity = ?"
            params.append(severity)
        if rule_family and rule_family != "All":
            query += " AND rule_id LIKE ?"
            params.append(f"{rule_family}-%")
        if scan_id is not None:
            query += " AND scan_id = ?"
            params.append(scan_id)
        if search_query and search_query.strip():
            q = f"%{search_query.strip()}%"
            query += " AND (resource_id LIKE ? OR title LIKE ? OR rule_id LIKE ?)"
            params.extend([q, q, q])

        query += " ORDER BY risk_score DESC, id ASC"

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        results: list[dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            item["evidence"] = json.loads(item["evidence_json"])
            item["score_breakdown"] = json.loads(item["score_breakdown_json"])
            results.append(item)
        return results

    def get_scan_by_id(self, scan_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["diagnostics"] = json.loads(item["diagnostics_json"])
        return item

    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        results: list[dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            item["diagnostics"] = json.loads(item["diagnostics_json"])
            results.append(item)
        return results

    def list_audit_logs(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

    def reset_database(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                DELETE FROM audit_log;
                DELETE FROM findings;
                DELETE FROM events;
                DELETE FROM scans;
                """
            )
