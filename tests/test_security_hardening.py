import re
import stat
from pathlib import Path

from cloudsentinel.collectors.cloudtrail_importer import (
    MAX_IMPORT_BYTES,
    parse_cloudtrail_json_content,
)
from cloudsentinel.db.repository import CloudSentinelRepository


def test_tc09_oversized_json_payload_is_rejected_safely() -> None:
    oversized = "{" + (" " * (MAX_IMPORT_BYTES + 100)) + "}"
    bundle = parse_cloudtrail_json_content(oversized)
    assert bundle.events == []
    assert any("exceeds maximum allowed size" in d for d in bundle.diagnostics)


def test_tc09_malformed_root_structure_is_rejected_safely() -> None:
    bundle = parse_cloudtrail_json_content('["not", "a", "dict"]')
    assert bundle.events == []
    assert any("Root of event JSON must be an object" in d for d in bundle.diagnostics)


def test_sqlite_database_enforces_restrictive_owner_permissions(tmp_path: Path) -> None:
    db_file = tmp_path / "hardened.db"
    CloudSentinelRepository(db_path=db_file)
    mode = stat.S_IMODE(db_file.stat().st_mode)
    assert mode == 0o600


def test_repository_contains_no_hardcoded_aws_access_keys() -> None:
    aws_key_pattern = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
    root = Path(__file__).resolve().parent.parent
    checked_files = (
        list((root / "src").rglob("*.py"))
        + list((root / "data").rglob("*.json"))
        + [root / "app.py", root / "config" / "settings.yaml"]
    )
    for file_path in checked_files:
        content = file_path.read_text(encoding="utf-8")
        assert not aws_key_pattern.search(content), f"Potential AWS key found in {file_path}"
