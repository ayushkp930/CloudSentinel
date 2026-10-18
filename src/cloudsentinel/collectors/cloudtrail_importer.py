import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cloudsentinel.utils.validation import validate_event_item

SENSITIVE_KEYS = {"password", "secretaccesskey", "sessiontoken", "accesstoken", "privatekey"}
MAX_IMPORT_BYTES = 5 * 1024 * 1024  # 5 MB safety limit (Blueprint Section 08 Input Handling)


@dataclass
class ImportedEventsBundle:
    source: str
    provenance_label: str
    events: list[dict[str, Any]] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)


def redact_sensitive_fields(data: Any) -> Any:
    """Recursively redact sensitive keys from event details before DB storage or export."""
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            if str(k).lower() in SENSITIVE_KEYS:
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = redact_sensitive_fields(v)
        return cleaned
    if isinstance(data, list):
        return [redact_sensitive_fields(item) for item in data]
    return data


def normalize_raw_cloudtrail_record(record: dict[str, Any]) -> dict[str, Any]:
    """
    Support both CloudSentinel normalized event dicts and standard AWS CloudTrail 'Records' format.
    """
    if "event_id" in record and "event_name" in record:
        normalized = dict(record)
        normalized["actor"] = str(normalized.get("actor", "unknown")).strip()
        normalized["details"] = redact_sensitive_fields(normalized.get("details", {}))
        return normalized

    # Convert native AWS CloudTrail JSON record shape if provided
    user_identity = record.get("userIdentity", {})
    actor = (
        user_identity.get("userName")
        or user_identity.get("arn")
        or user_identity.get("principalId")
        or "unknown"
    )
    error_code = record.get("errorCode")
    resp_elements = record.get("responseElements") or {}
    console_login_status = resp_elements.get("ConsoleLogin")

    if error_code or console_login_status == "Failure":
        status = "Failure"
    else:
        status = "Success"

    return {
        "event_id": str(record.get("eventID", "unknown")),
        "event_time": str(record.get("eventTime", "")),
        "event_name": str(record.get("eventName", "")),
        "event_source": str(record.get("eventSource", "unknown")),
        "actor": str(actor).strip(),
        "source_ip": str(record.get("sourceIPAddress", "unknown")),
        "region": str(record.get("awsRegion", "us-east-1")),
        "status": status,
        "details": redact_sensitive_fields(
            {
                "requestParameters": record.get("requestParameters", {}),
                "responseElements": resp_elements,
                "errorMessage": record.get("errorMessage", ""),
            }
        ),
    }


def parse_cloudtrail_json_content(
    raw_text: str,
    source: str = "imported_events",
    provenance_label: str = "Imported Events",
) -> ImportedEventsBundle:
    """Validate size, parse JSON, normalize events, and collect diagnostics."""
    if len(raw_text.encode("utf-8")) > MAX_IMPORT_BYTES:
        return ImportedEventsBundle(
            source=source,
            provenance_label=provenance_label,
            events=[],
            diagnostics=["Event payload exceeds maximum allowed size (5 MB)."],
        )

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        return ImportedEventsBundle(
            source=source,
            provenance_label=provenance_label,
            events=[],
            diagnostics=[f"Malformed JSON in event payload: {exc}"],
        )

    if not isinstance(payload, dict):
        return ImportedEventsBundle(
            source=source,
            provenance_label=provenance_label,
            events=[],
            diagnostics=["Root of event JSON must be an object containing 'events' or 'Records'."],
        )

    raw_list = payload.get("events") if "events" in payload else payload.get("Records")
    if not isinstance(raw_list, list):
        return ImportedEventsBundle(
            source=source,
            provenance_label=provenance_label,
            events=[],
            diagnostics=["Event JSON must contain a list under 'events' or 'Records'."],
        )

    valid_events: list[dict[str, Any]] = []
    diagnostics: list[str] = []

    for idx, item in enumerate(raw_list):
        if not isinstance(item, dict):
            diagnostics.append(f"Event[{idx}]: Entry must be a JSON object.")
            continue
        norm = normalize_raw_cloudtrail_record(item)
        check = validate_event_item(norm)
        if check.ok:
            valid_events.append(norm)
        else:
            diagnostics.extend([f"Event[{idx}]: {err}" for err in check.errors])

    return ImportedEventsBundle(
        source=source,
        provenance_label=provenance_label,
        events=valid_events,
        diagnostics=diagnostics,
    )


def import_cloudtrail_file(file_path: str | Path) -> ImportedEventsBundle:
    path = Path(file_path)
    if not path.exists():
        return ImportedEventsBundle(
            source="imported_events",
            provenance_label="Imported Events",
            events=[],
            diagnostics=[f"Event file not found: {path}"],
        )
    return parse_cloudtrail_json_content(path.read_text(encoding="utf-8"))
