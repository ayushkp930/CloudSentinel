from datetime import datetime
from typing import Any

from cloudsentinel.rules.base import RuleEvaluationOutcome, RuleMatch

PRIVILEGED_POLICY_KEYWORDS = ("administratoraccess", "poweruseraccess", "iamfullaccess")
TRAIL_TAMPER_EVENTS = {"StopLogging", "DeleteTrail", "UpdateTrail"}
POLICY_ATTACH_EVENTS = {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy", "PutUserPolicy"}


def _parse_iso_time(ts: str) -> datetime | None:
    try:
        cleaned = ts.strip()
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return None


class CloudTrailTamperingRule:
    """LOG-001: CloudTrail logging is stopped or a trail is modified/deleted."""
    rule_id = "LOG-001"
    title = "CloudTrail audit logging was stopped, modified, or deleted"
    default_severity = "Critical"
    recommendation = (
        "Immediately verify why CloudTrail logging was altered, re-enable the trail, "
        "and restrict cloudtrail:StopLogging/DeleteTrail via SCPs or IAM policies."
    )

    def evaluate_events(self, events: list[dict[str, Any]]) -> list[RuleEvaluationOutcome]:
        outcomes: list[RuleEvaluationOutcome] = []
        for evt in events:
            evt_id = str(evt.get("event_id", "unknown"))
            evt_name = str(evt.get("event_name", ""))
            status = str(evt.get("status", ""))

            if evt_name in TRAIL_TAMPER_EVENTS and status.lower() == "success":
                details = evt.get("details", {})
                trail_name = details.get("trailName") or details.get("name") or "unknown-trail"
                outcome = RuleEvaluationOutcome(rule_id=self.rule_id, resource_id=str(trail_name))
                outcome.matches.append(
                    RuleMatch(
                        matched=True,
                        evidence={
                            "event_id": evt_id,
                            "event_name": evt_name,
                            "event_time": evt.get("event_time"),
                            "actor": evt.get("actor"),
                            "source_ip": evt.get("source_ip"),
                            "trail_name": trail_name,
                        },
                        reason=f"CloudTrail management event '{evt_name}' succeeded by actor '{evt.get('actor')}'.",
                        impact_score=38,
                        exposure_score=20,
                        privilege_score=28,
                    )
                )
                outcomes.append(outcome)
        return outcomes


class PrivilegedPolicyAttachmentRule:
    """IAM-002: Unexpected privileged policy attachment event appears in audit logs."""
    rule_id = "IAM-002"
    title = "Privileged IAM policy attachment detected in audit logs"
    default_severity = "High"
    recommendation = (
        "Review change authorization with the actor, verify whether elevated privileges "
        "were approved, and detach unauthorized policies."
    )

    def evaluate_events(self, events: list[dict[str, Any]]) -> list[RuleEvaluationOutcome]:
        outcomes: list[RuleEvaluationOutcome] = []
        for evt in events:
            evt_id = str(evt.get("event_id", "unknown"))
            evt_name = str(evt.get("event_name", ""))
            status = str(evt.get("status", ""))

            if evt_name in POLICY_ATTACH_EVENTS and status.lower() == "success":
                details = evt.get("details", {})
                policy_arn = str(
                    details.get("policyArn")
                    or details.get("requestParameters", {}).get("policyArn", "")
                )
                target = str(
                    details.get("targetUser")
                    or details.get("targetRole")
                    or evt.get("actor", "unknown")
                )

                if any(k in policy_arn.lower() for k in PRIVILEGED_POLICY_KEYWORDS):
                    outcome = RuleEvaluationOutcome(rule_id=self.rule_id, resource_id=target)
                    outcome.matches.append(
                        RuleMatch(
                            matched=True,
                            evidence={
                                "event_id": evt_id,
                                "event_name": evt_name,
                                "event_time": evt.get("event_time"),
                                "actor": evt.get("actor"),
                                "source_ip": evt.get("source_ip"),
                                "target_identity": target,
                                "policy_arn": policy_arn,
                            },
                            reason=f"Privileged policy '{policy_arn}' attached to '{target}'.",
                            impact_score=32,
                            exposure_score=16,
                            privilege_score=28,
                        )
                    )
                    outcomes.append(outcome)
        return outcomes


class AccessKeyCreationRule:
    """KEY-001: Access key creation event is detected (indicator requiring review)."""
    rule_id = "KEY-001"
    title = "IAM programmatic access key creation event detected"
    default_severity = "Medium"
    recommendation = (
        "Confirm with the identity owner that the CreateAccessKey action was authorized; "
        "prefer temporary IAM role credentials over long-lived access keys."
    )

    def evaluate_events(self, events: list[dict[str, Any]]) -> list[RuleEvaluationOutcome]:
        outcomes: list[RuleEvaluationOutcome] = []
        for evt in events:
            evt_id = str(evt.get("event_id", "unknown"))
            evt_name = str(evt.get("event_name", ""))
            status = str(evt.get("status", ""))

            if evt_name == "CreateAccessKey" and status.lower() == "success":
                details = evt.get("details", {})
                target_user = str(
                    details.get("targetUser")
                    or details.get("requestParameters", {}).get("userName")
                    or evt.get("actor", "unknown")
                )
                outcome = RuleEvaluationOutcome(rule_id=self.rule_id, resource_id=target_user)
                outcome.matches.append(
                    RuleMatch(
                        matched=True,
                        evidence={
                            "event_id": evt_id,
                            "event_name": evt_name,
                            "event_time": evt.get("event_time"),
                            "actor": evt.get("actor"),
                            "source_ip": evt.get("source_ip"),
                            "target_user": target_user,
                            "indicator_note": "Event alone is not proof of malicious activity; review context.",
                        },
                        reason=f"New IAM access key created for '{target_user}' by '{evt.get('actor')}'.",
                        impact_score=20,
                        exposure_score=15,
                        privilege_score=20,
                    )
                )
                outcomes.append(outcome)
        return outcomes


class RepeatedFailedLoginRule:
    """
    AUTH-001: Repeated failed console logins exceed configurable threshold within a time window.
    Aggregates by actor identity to emit a single deduplicated finding per window (TC-06, TC-07).
    """
    rule_id = "AUTH-001"
    title = "Repeated failed AWS Console login attempts exceed threshold within time window"
    default_severity = "High"
    recommendation = (
        "Investigate source IP and actor for credential stuffing or brute-force activity, "
        "enforce MFA, and rotate credentials if compromise is suspected."
    )

    def __init__(self, threshold: int = 3, window_minutes: int = 15) -> None:
        self.threshold = max(2, int(threshold))
        self.window_minutes = max(1, int(window_minutes))

    def evaluate_events(self, events: list[dict[str, Any]]) -> list[RuleEvaluationOutcome]:
        outcomes: list[RuleEvaluationOutcome] = []
        by_actor: dict[str, list[tuple[datetime, dict[str, Any]]]] = {}
        diagnostics: list[str] = []

        for evt in events:
            if str(evt.get("event_name")) != "ConsoleLogin":
                continue
            if str(evt.get("status", "")).lower() != "failure":
                continue

            actor = str(evt.get("actor", "unknown")).strip()
            parsed_time = _parse_iso_time(str(evt.get("event_time", "")))
            if parsed_time is None:
                diagnostics.append(
                    f"{self.rule_id}: Unparseable event_time on failed login event '{evt.get('event_id')}'."
                )
                continue
            by_actor.setdefault(actor, []).append((parsed_time, evt))

        if diagnostics:
            diag_outcome = RuleEvaluationOutcome(rule_id=self.rule_id, resource_id="unknown_actor")
            diag_outcome.diagnostics.extend(diagnostics)
            outcomes.append(diag_outcome)

        window_seconds = self.window_minutes * 60

        for actor, timestamped_events in by_actor.items():
            timestamped_events.sort(key=lambda pair: pair[0])
            n = len(timestamped_events)
            if n < self.threshold:
                continue

            # Sliding window check for >= threshold failures within window_minutes
            for i in range(n):
                start_time = timestamped_events[i][0]
                window_batch = [
                    pair[1]
                    for pair in timestamped_events[i:]
                    if 0 <= (pair[0] - start_time).total_seconds() <= window_seconds
                ]
                if len(window_batch) >= self.threshold:
                    source_ips = sorted({str(e.get("source_ip", "unknown")) for e in window_batch})
                    event_ids = [str(e.get("event_id")) for e in window_batch]
                    outcome = RuleEvaluationOutcome(rule_id=self.rule_id, resource_id=actor)
                    outcome.matches.append(
                        RuleMatch(
                            matched=True,
                            evidence={
                                "actor": actor,
                                "failed_attempts_count": len(window_batch),
                                "threshold": self.threshold,
                                "window_minutes": self.window_minutes,
                                "first_failure_utc": window_batch[0].get("event_time"),
                                "last_failure_utc": window_batch[-1].get("event_time"),
                                "source_ips": source_ips,
                                "event_ids": event_ids,
                            },
                            reason=(
                                f"Detected {len(window_batch)} failed ConsoleLogin attempts for '{actor}' "
                                f"within {self.window_minutes} minutes (threshold={self.threshold})."
                            ),
                            impact_score=26,
                            exposure_score=24,
                            privilege_score=18,
                        )
                    )
                    outcomes.append(outcome)
                    break  # Emit one aggregated finding per identity (Blueprint Section 05B / TC-07)

        return outcomes
