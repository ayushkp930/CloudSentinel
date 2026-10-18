# CloudSentinel — Verification Matrix & Evaluation Plan

## 1. Blueprint Test Case Traceability (`TC-01` to `TC-14`)

| Test ID | Scenario / Condition | Automated Pytest Function | Status |
| :--- | :--- | :--- | :--- |
| **TC-01** | Inbound TCP/22 from `0.0.0.0/0` fixture | `tests/test_network_rules.py::test_net001_detects_public_ssh_ipv4` | Verified (PASS) |
| **TC-02** | Inbound TCP/3389 from `0.0.0.0/0` fixture | `tests/test_network_rules.py::test_net002_detects_public_rdp_ipv4` | Verified (PASS) |
| **TC-03** | Equivalent risky IPv6 `::/0` admin exposure | `tests/test_network_rules.py::test_net003_detects_ipv6_admin_exposure` | Verified (PASS) |
| **TC-04** | S3 effective public-access posture evaluation | `tests/test_s3_rules.py::test_s3001_detects_effective_public_bucket` & `test_s3001_public_acl_blocked_by_pab_is_safe` | Verified (PASS) |
| **TC-05** | Broad IAM policy (`Action:*`, `Resource:*`) | `tests/test_iam_rules.py::test_iam001_detects_wildcard_admin_policy` | Verified (PASS) |
| **TC-06** | Failed login events below threshold | `tests/test_event_rules.py::test_tc06_failed_logins_below_threshold_produces_no_alert` | Verified (PASS) |
| **TC-07** | Failed logins above threshold in time window | `tests/test_event_rules.py::test_tc07_failed_logins_at_or_above_threshold_within_window_emits_single_aggregated_alert` | Verified (PASS) |
| **TC-08** | Routine event with no configured match | `tests/test_event_rules.py::test_tc08_routine_events_produce_no_alerts` | Verified (PASS) |
| **TC-09** | Malformed or oversized JSON rejected safely | `tests/test_phase1_foundation.py::test_corrupt_json_produces_diagnostic_without_crash` & `tests/test_security_hardening.py::test_tc09_oversized_json_payload_is_rejected_safely` | Verified (PASS) |
| **TC-10** | AWS permission denied returns `partial`/`failed` | `tests/test_aws_provider.py::test_tc10_aws_permission_denied_marks_scan_failed_not_clean` | Verified (PASS) |
| **TC-11** | Repeat finding deduplicates via fingerprint | `tests/test_persistence_and_lifecycle.py::test_tc11_repeat_scan_deduplicates_findings` | Verified (PASS) |
| **TC-12** | Condition absent on clean rescan resolves issue | `tests/test_persistence_and_lifecycle.py::test_tc12_clean_rescan_marks_absent_finding_resolved` | Verified (PASS) |
| **TC-13** | Failed rescan does not resolve previous finding | `tests/test_persistence_and_lifecycle.py::test_tc13_failed_scan_does_not_resolve_existing_findings` | Verified (PASS) |
| **TC-14** | JSON/CSV export includes scan/source timestamps | `tests/test_reports_and_filtering.py::test_tc14_json_and_csv_exports_include_provenance_and_timestamps` | Verified (PASS) |

## 2. Measured Evaluation on Synthetic Benchmark Corpus
- **Test Suite Size:** 35 automated unit, integration, and security hardening tests.
- **Synthetic Benchmark Corpus:** 6 labeled AWS resources (4 vulnerable across 5 rules, 2 safe) + 6 labeled CloudTrail events (4 positive scenarios across `AUTH-001`, `LOG-001`, `KEY-001`, `IAM-002`).
- **Measured Results on Labeled Test Dataset:**
  - Expected Positive Findings Emitted: `9 / 9` (5 Resource Findings + 4 Event Findings)
  - False Positives on Labeled Safe Fixtures (`sg-demo-safe-003`, `demo-private-logs-bucket`, routine events): `0`
  - *Note:* These metrics apply strictly to the project's labeled synthetic test corpus and are not a claim of universal cloud security coverage.
