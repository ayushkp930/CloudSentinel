from pathlib import Path

from cloudsentinel.collectors.demo_provider import load_demo_bundle
from cloudsentinel.utils.validation import validate_event_item, validate_resource_item


def test_default_demo_bundle_loads_cleanly() -> None:
    bundle = load_demo_bundle()
    assert bundle.source == "synthetic_demo"
    assert bundle.provenance_label == "Synthetic Demo"
    assert len(bundle.resources) == 6
    assert len(bundle.events) == 6
    assert bundle.diagnostics == []


def test_validation_rejects_missing_resource_fields() -> None:
    bad_resource = {"resource_id": "sg-123", "resource_type": "aws.ec2.security_group"}
    res = validate_resource_item(bad_resource)
    assert res.ok is False
    assert any("Missing required resource fields" in err for err in res.errors)


def test_validation_rejects_missing_event_fields() -> None:
    bad_event = {"event_id": "evt-1", "event_name": "ConsoleLogin"}
    res = validate_event_item(bad_event)
    assert res.ok is False
    assert any("Missing required event fields" in err for err in res.errors)


def test_corrupt_json_produces_diagnostic_without_crash(tmp_path: Path) -> None:
    bad_json_file = tmp_path / "bad_resources.json"
    bad_json_file.write_text("{invalid_json:", encoding="utf-8")

    bundle = load_demo_bundle(resources_path=bad_json_file)
    assert len(bundle.resources) == 0
    assert any("Invalid JSON" in d for d in bundle.diagnostics)
