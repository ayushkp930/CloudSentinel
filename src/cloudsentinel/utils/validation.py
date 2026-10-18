from dataclasses import dataclass, field
from typing import Any

REQUIRED_RESOURCE_KEYS = {"resource_id", "resource_type", "name", "region", "configuration"}
REQUIRED_EVENT_KEYS = {"event_id", "event_time", "event_name", "actor", "source_ip", "region", "status"}


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str] = field(default_factory=list)


def validate_resource_item(item: Any) -> ValidationResult:
    """Validate that a normalized resource dictionary contains required fields."""
    if not isinstance(item, dict):
        return ValidationResult(ok=False, errors=["Resource entry must be a JSON object/dict."])

    missing = REQUIRED_RESOURCE_KEYS - set(item.keys())
    if missing:
        return ValidationResult(
            ok=False,
            errors=[f"Missing required resource fields: {sorted(missing)}"],
        )

    if not isinstance(item.get("configuration"), dict):
        return ValidationResult(
            ok=False,
            errors=[f"Resource '{item.get('resource_id')}' configuration must be a dict."],
        )

    return ValidationResult(ok=True)


def validate_event_item(item: Any) -> ValidationResult:
    """Validate that a CloudTrail-style event dictionary contains required fields."""
    if not isinstance(item, dict):
        return ValidationResult(ok=False, errors=["Event entry must be a JSON object/dict."])

    missing = REQUIRED_EVENT_KEYS - set(item.keys())
    if missing:
        return ValidationResult(
            ok=False,
            errors=[f"Missing required event fields: {sorted(missing)}"],
        )

    return ValidationResult(ok=True)
