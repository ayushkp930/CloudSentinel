import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cloudsentinel.utils.logging_config import get_logger
from cloudsentinel.utils.validation import validate_event_item, validate_resource_item

logger = get_logger(__name__)


@dataclass
class CollectionBundle:
    source: str
    provenance_label: str
    collected_at: str
    resources: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)


def load_demo_bundle(
    resources_path: str | Path = "data/demo/resources.json",
    events_path: str | Path = "data/demo/cloudtrail_events.json",
) -> CollectionBundle:
    """Load and validate synthetic local fixtures without any AWS network calls."""
    res_file = Path(resources_path)
    evt_file = Path(events_path)
    diagnostics: list[str] = []
    valid_resources: list[dict[str, Any]] = []
    valid_events: list[dict[str, Any]] = []
    collected_at = "unknown"

    # 1. Load Resources Fixture
    if not res_file.exists():
        diagnostics.append(f"Resources fixture file not found: {res_file}")
    else:
        try:
            raw_res = json.loads(res_file.read_text(encoding="utf-8"))
            collected_at = str(raw_res.get("collected_at", "unknown"))
            raw_list = raw_res.get("resources", [])
            if not isinstance(raw_list, list):
                diagnostics.append("Field 'resources' in fixture must be a list.")
            else:
                for idx, item in enumerate(raw_list):
                    check = validate_resource_item(item)
                    if check.ok:
                        valid_resources.append(item)
                    else:
                        diagnostics.extend([f"Resource[{idx}]: {err}" for err in check.errors])
        except json.JSONDecodeError as exc:
            diagnostics.append(f"Invalid JSON in resources fixture: {exc}")

    # 2. Load Events Fixture
    if not evt_file.exists():
        diagnostics.append(f"Events fixture file not found: {evt_file}")
    else:
        try:
            raw_evt = json.loads(evt_file.read_text(encoding="utf-8"))
            evt_list = raw_evt.get("events", [])
            if not isinstance(evt_list, list):
                diagnostics.append("Field 'events' in fixture must be a list.")
            else:
                for idx, item in enumerate(evt_list):
                    check = validate_event_item(item)
                    if check.ok:
                        valid_events.append(item)
                    else:
                        diagnostics.extend([f"Event[{idx}]: {err}" for err in check.errors])
        except json.JSONDecodeError as exc:
            diagnostics.append(f"Invalid JSON in events fixture: {exc}")

    logger.info(
        "Loaded synthetic bundle: %d resources, %d events, %d diagnostics",
        len(valid_resources),
        len(valid_events),
        len(diagnostics),
    )

    return CollectionBundle(
        source="synthetic_demo",
        provenance_label="Synthetic Demo",
        collected_at=collected_at,
        resources=valid_resources,
        events=valid_events,
        diagnostics=diagnostics,
    )
