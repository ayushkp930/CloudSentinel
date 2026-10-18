from dataclasses import dataclass, field
from typing import Any


@dataclass
class RuleMatch:
    """Represents a single confirmed security finding match from a rule."""
    matched: bool
    evidence: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    impact_score: int = 0
    exposure_score: int = 0
    privilege_score: int = 0


@dataclass
class RuleEvaluationOutcome:
    """Holds all matches or missing-evidence diagnostics for one resource evaluation."""
    rule_id: str
    resource_id: str
    matches: list[RuleMatch] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)


class DetectionRule:
    """Base contract that every CloudSentinel resource detection rule must implement."""
    rule_id: str = ""
    title: str = ""
    description: str = ""
    applicable_resource_type: str = ""
    default_severity: str = "Medium"
    recommendation: str = ""

    def evaluate(self, resource: dict[str, Any]) -> RuleEvaluationOutcome:
        raise NotImplementedError("Subclasses must implement evaluate().")
