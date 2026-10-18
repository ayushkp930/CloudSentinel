import hashlib
import json
from typing import Any


def compute_finding_fingerprint(
    rule_id: str,
    resource_id: str,
    evidence: dict[str, Any],
) -> str:
    """
    Generate a deterministic SHA-256 fingerprint from rule_id, resource_id,
    and canonicalized configuration evidence (excluding volatile timestamps).
    """
    stable_evidence = {
        k: v for k, v in sorted(evidence.items()) if k not in ("source", "collected_at")
    }
    payload = {
        "rule_id": rule_id.strip(),
        "resource_id": resource_id.strip(),
        "evidence": stable_evidence,
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return f"fp-{digest[:24]}"
