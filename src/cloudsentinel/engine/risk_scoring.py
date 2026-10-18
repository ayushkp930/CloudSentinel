from dataclasses import dataclass


@dataclass
class RiskScoreResult:
    total_score: int | None
    severity: str
    impact: int
    exposure: int
    privilege: int
    explanation: str


def calculate_heuristic_risk(
    impact: int | None,
    exposure: int | None,
    privilege: int | None,
) -> RiskScoreResult:
    """
    Compute illustrative heuristic risk score R = I + E + P (0-100).
    Impact: 0-40, Exposure: 0-30, Privilege: 0-30.
    If any required factor is None, return Unknown/Needs review (Rule #7 & #8).
    """
    if impact is None or exposure is None or privilege is None:
        return RiskScoreResult(
            total_score=None,
            severity="Unknown",
            impact=0,
            exposure=0,
            privilege=0,
            explanation="Missing required evidence for risk calculation; marked as Unknown/Needs review.",
        )

    bounded_i = max(0, min(40, int(impact)))
    bounded_e = max(0, min(30, int(exposure)))
    bounded_p = max(0, min(30, int(privilege)))
    total = bounded_i + bounded_e + bounded_p

    if total >= 80:
        severity = "Critical"
    elif total >= 60:
        severity = "High"
    elif total >= 35:
        severity = "Medium"
    else:
        severity = "Low"

    explanation = (
        f"Heuristic Score {total}/100 (Impact={bounded_i}/40 + Exposure={bounded_e}/30 + "
        f"Privilege={bounded_p}/30) -> {severity}. Note: Project heuristic, not breach probability."
    )

    return RiskScoreResult(
        total_score=total,
        severity=severity,
        impact=bounded_i,
        exposure=bounded_e,
        privilege=bounded_p,
        explanation=explanation,
    )
