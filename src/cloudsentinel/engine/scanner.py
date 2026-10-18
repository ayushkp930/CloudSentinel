from dataclasses import dataclass, field
from typing import Any

from cloudsentinel.collectors.demo_provider import CollectionBundle
from cloudsentinel.engine.deduplication import compute_finding_fingerprint
from cloudsentinel.engine.risk_scoring import calculate_heuristic_risk
from cloudsentinel.rules.base import DetectionRule
from cloudsentinel.rules.event_rules import (
    AccessKeyCreationRule,
    CloudTrailTamperingRule,
    PrivilegedPolicyAttachmentRule,
    RepeatedFailedLoginRule,
)
from cloudsentinel.rules.iam_rules import IAMBroadPermissionsRule
from cloudsentinel.rules.network_rules import (
    PublicIPv6AdminPortRule,
    PublicRDPRule,
    PublicSSHRule,
)
from cloudsentinel.rules.s3_rules import S3EffectivePublicAccessRule


def get_default_resource_rules() -> list[DetectionRule]:
    """Return the catalogue of deterministic resource configuration rules."""
    return [
        PublicSSHRule(),
        PublicRDPRule(),
        PublicIPv6AdminPortRule(),
        S3EffectivePublicAccessRule(),
        IAMBroadPermissionsRule(),
    ]


def get_default_event_rules(
    failed_login_threshold: int = 3,
    failed_login_window_minutes: int = 15,
) -> list[Any]:
    """Return the catalogue of deterministic CloudTrail event detection rules."""
    return [
        CloudTrailTamperingRule(),
        PrivilegedPolicyAttachmentRule(),
        AccessKeyCreationRule(),
        RepeatedFailedLoginRule(
            threshold=failed_login_threshold,
            window_minutes=failed_login_window_minutes,
        ),
    ]


@dataclass
class ScanExecutionResult:
    status: str  # "completed", "partial", or "failed"
    provenance_label: str
    resources_scanned: int
    events_analyzed: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)


def run_resource_scan(
    bundle: CollectionBundle,
    rules: list[DetectionRule] | None = None,
    include_events: bool = True,
    failed_login_threshold: int = 3,
    failed_login_window_minutes: int = 15,
) -> ScanExecutionResult:
    """
    Orchestrate resource configuration rules and CloudTrail event detection rules,
    heuristic risk scoring, and deterministic fingerprinting.
    """
    active_rules = rules if rules is not None else get_default_resource_rules()
    findings: list[dict[str, Any]] = []
    diagnostics: list[str] = list(bundle.diagnostics)

    if len(bundle.resources) == 0 and len(bundle.events) == 0 and len(diagnostics) > 0:
        return ScanExecutionResult(
            status="failed",
            provenance_label=bundle.provenance_label,
            resources_scanned=0,
            events_analyzed=0,
            findings=[],
            diagnostics=diagnostics,
        )

    # 1. Evaluate Resource Configuration Rules
    for resource in bundle.resources:
        res_type = resource.get("resource_type", "")
        res_id = resource.get("resource_id", "unknown")

        for rule in active_rules:
            if rule.applicable_resource_type != res_type:
                continue

            outcome = rule.evaluate(resource)
            if outcome.diagnostics:
                diagnostics.extend(outcome.diagnostics)

            for match in outcome.matches:
                evidence_with_source = dict(match.evidence)
                evidence_with_source["source"] = bundle.source

                risk = calculate_heuristic_risk(
                    impact=match.impact_score,
                    exposure=match.exposure_score,
                    privilege=match.privilege_score,
                )
                fingerprint = compute_finding_fingerprint(
                    rule_id=rule.rule_id,
                    resource_id=res_id,
                    evidence=evidence_with_source,
                )

                findings.append(
                    {
                        "rule_id": rule.rule_id,
                        "title": rule.title,
                        "resource_type": res_type,
                        "resource_id": res_id,
                        "region": resource.get("region", "unknown"),
                        "severity": risk.severity,
                        "risk_score": risk.total_score,
                        "score_breakdown": {
                            "impact": risk.impact,
                            "exposure": risk.exposure,
                            "privilege": risk.privilege,
                            "explanation": risk.explanation,
                        },
                        "status": "Open",
                        "evidence": evidence_with_source,
                        "recommendation": rule.recommendation,
                        "fingerprint": fingerprint,
                    }
                )

    # 2. Evaluate CloudTrail Event Rules (Phase 5)
    if include_events and bundle.events:
        event_rules = get_default_event_rules(
            failed_login_threshold=failed_login_threshold,
            failed_login_window_minutes=failed_login_window_minutes,
        )
        for ev_rule in event_rules:
            outcomes = ev_rule.evaluate_events(bundle.events)
            for outcome in outcomes:
                if outcome.diagnostics:
                    diagnostics.extend(outcome.diagnostics)
                for match in outcome.matches:
                    evidence_with_source = dict(match.evidence)
                    evidence_with_source["source"] = bundle.source

                    risk = calculate_heuristic_risk(
                        impact=match.impact_score,
                        exposure=match.exposure_score,
                        privilege=match.privilege_score,
                    )
                    fingerprint = compute_finding_fingerprint(
                        rule_id=ev_rule.rule_id,
                        resource_id=outcome.resource_id,
                        evidence=evidence_with_source,
                    )

                    findings.append(
                        {
                            "rule_id": ev_rule.rule_id,
                            "title": ev_rule.title,
                            "resource_type": "aws.cloudtrail.event",
                            "resource_id": outcome.resource_id,
                            "region": "us-east-1",
                            "severity": risk.severity,
                            "risk_score": risk.total_score,
                            "score_breakdown": {
                                "impact": risk.impact,
                                "exposure": risk.exposure,
                                "privilege": risk.privilege,
                                "explanation": risk.explanation,
                            },
                            "status": "Open",
                            "evidence": evidence_with_source,
                            "recommendation": ev_rule.recommendation,
                            "fingerprint": fingerprint,
                        }
                    )

    status = "partial" if len(diagnostics) > 0 else "completed"
    return ScanExecutionResult(
        status=status,
        provenance_label=bundle.provenance_label,
        resources_scanned=len(bundle.resources),
        events_analyzed=len(bundle.events) if include_events else 0,
        findings=findings,
        diagnostics=diagnostics,
    )
