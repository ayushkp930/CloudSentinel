from cloudsentinel.collectors.cloudtrail_importer import parse_cloudtrail_json_content
from cloudsentinel.rules.event_rules import (
    AccessKeyCreationRule,
    CloudTrailTamperingRule,
    PrivilegedPolicyAttachmentRule,
    RepeatedFailedLoginRule,
)


def test_tc06_failed_logins_below_threshold_produces_no_alert() -> None:
    events = [
        {
            "event_id": "e1",
            "event_time": "2026-10-16T09:00:00Z",
            "event_name": "ConsoleLogin",
            "actor": "alice",
            "source_ip": "198.51.100.1",
            "region": "us-east-1",
            "status": "Failure",
        },
        {
            "event_id": "e2",
            "event_time": "2026-10-16T09:05:00Z",
            "event_name": "ConsoleLogin",
            "actor": "alice",
            "source_ip": "198.51.100.1",
            "region": "us-east-1",
            "status": "Failure",
        },
    ]
    rule = RepeatedFailedLoginRule(threshold=3, window_minutes=15)
    outcomes = rule.evaluate_events(events)
    assert outcomes == []


def test_tc07_failed_logins_at_or_above_threshold_within_window_emits_single_aggregated_alert() -> None:
    events = [
        {
            "event_id": "e1",
            "event_time": "2026-10-16T09:01:00Z",
            "event_name": "ConsoleLogin",
            "actor": "bob",
            "source_ip": "198.51.100.9",
            "region": "us-east-1",
            "status": "Failure",
        },
        {
            "event_id": "e2",
            "event_time": "2026-10-16T09:04:00Z",
            "event_name": "ConsoleLogin",
            "actor": "bob",
            "source_ip": "198.51.100.9",
            "region": "us-east-1",
            "status": "Failure",
        },
        {
            "event_id": "e3",
            "event_time": "2026-10-16T09:08:00Z",
            "event_name": "ConsoleLogin",
            "actor": "bob",
            "source_ip": "198.51.100.9",
            "region": "us-east-1",
            "status": "Failure",
        },
        {
            "event_id": "e4",
            "event_time": "2026-10-16T09:10:00Z",
            "event_name": "ConsoleLogin",
            "actor": "bob",
            "source_ip": "198.51.100.9",
            "region": "us-east-1",
            "status": "Failure",
        },
    ]
    rule = RepeatedFailedLoginRule(threshold=3, window_minutes=15)
    outcomes = rule.evaluate_events(events)
    assert len(outcomes) == 1
    assert len(outcomes[0].matches) == 1
    assert outcomes[0].matches[0].evidence["failed_attempts_count"] == 4


def test_tc08_routine_events_produce_no_alerts() -> None:
    routine_events = [
        {
            "event_id": "e-ok-1",
            "event_time": "2026-10-16T10:00:00Z",
            "event_name": "DescribeInstances",
            "actor": "readonly-analyst",
            "source_ip": "192.0.2.10",
            "region": "us-east-1",
            "status": "Success",
            "details": {},
        },
        {
            "event_id": "e-ok-2",
            "event_time": "2026-10-16T10:01:00Z",
            "event_name": "ConsoleLogin",
            "actor": "readonly-analyst",
            "source_ip": "192.0.2.10",
            "region": "us-east-1",
            "status": "Success",
            "details": {},
        },
    ]
    assert CloudTrailTamperingRule().evaluate_events(routine_events) == []
    assert PrivilegedPolicyAttachmentRule().evaluate_events(routine_events) == []
    assert AccessKeyCreationRule().evaluate_events(routine_events) == []
    assert RepeatedFailedLoginRule().evaluate_events(routine_events) == []


def test_log001_iam002_and_key001_detect_positive_events() -> None:
    events = [
        {
            "event_id": "e-stop",
            "event_time": "2026-10-16T09:20:00Z",
            "event_name": "StopLogging",
            "actor": "ops-admin",
            "source_ip": "203.0.113.1",
            "region": "us-east-1",
            "status": "Success",
            "details": {"trailName": "main-trail"},
        },
        {
            "event_id": "e-attach",
            "event_time": "2026-10-16T09:25:00Z",
            "event_name": "AttachUserPolicy",
            "actor": "dev-user",
            "source_ip": "203.0.113.2",
            "region": "us-east-1",
            "status": "Success",
            "details": {
                "targetUser": "temp-user",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            },
        },
        {
            "event_id": "e-key",
            "event_time": "2026-10-16T09:30:00Z",
            "event_name": "CreateAccessKey",
            "actor": "dev-user",
            "source_ip": "203.0.113.2",
            "region": "us-east-1",
            "status": "Success",
            "details": {"targetUser": "service-bot"},
        },
    ]
    assert len(CloudTrailTamperingRule().evaluate_events(events)) == 1
    assert len(PrivilegedPolicyAttachmentRule().evaluate_events(events)) == 1
    assert len(AccessKeyCreationRule().evaluate_events(events)) == 1


def test_cloudtrail_importer_normalizes_and_redacts_secrets() -> None:
    raw_json = """
    {
      "Records": [
        {
          "eventID": "aws-raw-1",
          "eventTime": "2026-10-16T11:00:00Z",
          "eventName": "CreateAccessKey",
          "eventSource": "iam.amazonaws.com",
          "userIdentity": {"userName": "admin-bob"},
          "sourceIPAddress": "198.51.100.77",
          "awsRegion": "us-east-1",
          "responseElements": {"secretAccessKey": "SUPER_SECRET_DO_NOT_STORE"}
        }
      ]
    }
    """
    bundle = parse_cloudtrail_json_content(raw_json)
    assert len(bundle.events) == 1
    assert bundle.events[0]["actor"] == "admin-bob"
    assert (
        bundle.events[0]["details"]["responseElements"]["secretAccessKey"]
        == "[REDACTED]"
    )
