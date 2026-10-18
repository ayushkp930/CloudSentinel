# CloudSentinel — Security & Privacy Threat Model (STRIDE)

## 1. Security Principles & Scope Boundaries
- **Local-First & Offline Default:** Works completely offline using synthetic fixtures (`data/demo/`). Live AWS calls never occur without explicit analyst authorization.
- **Strictly Read-Only Cloud Inspection:** `aws_provider.py` invokes only read/describe/get Boto3 APIs. No resource creation, policy mutation, or automated remediation exists in the codebase.
- **Zero Secret Storage:** The UI and configuration files never accept raw AWS secret keys or passwords.

## 2. STRIDE Threat Matrix & Implemented Mitigations

| Asset / Component | Threat Category | Risk Scenario | Implemented Control / Mitigation |
| :--- | :--- | :--- | :--- |
| **AWS Credentials** | Information Disclosure | Accidental commit of AWS keys in Git or logs | `.gitignore` blocks `.env`/`*.pem`/`*.db`; automated test `test_repository_contains_no_hardcoded_aws_access_keys` scans codebase; AWS collector uses local `~/.aws/credentials` profiles only. |
| **CloudTrail Importer** | Denial of Service / Tampering | Malformed or oversized JSON file upload crashes app or leaks secrets | `MAX_IMPORT_BYTES` caps uploads at 5 MB (`TC-09`); `redact_sensitive_fields()` scrubs `secretAccessKey`, `password`, and `sessionToken` before SQLite storage. |
| **Rule Engine & Scanner** | Integrity / False Negative | Collector `AccessDenied` or missing fields misinterpreted as a "clean" posture | Missing fields emit `diagnostics`; `AccessDenied` marks scan `partial` or `failed` (`TC-10`); `repository.py` refuses to auto-resolve findings unless scan status is `completed` (`TC-13`). |
| **SQLite Database** | Unauthorized Local Access / SQLi | Local database read by other OS users or SQL injection via UI filters | `init_db()` enforces `0o600` (`chmod 600`) owner-only file permissions; all SQLite queries in `repository.py` use parameterized `?` placeholders. |
| **Finding Lifecycle** | Repudiation | Analyst silently suppresses a critical finding | `update_finding_status()` rejects blank suppression reasons (`ValueError`) and writes an immutable record to `audit_log`. |
| **Exported Reports** | Spoofing / Provenance Confusion | Synthetic demo findings mistaken for live production AWS results | Every UI banner, JSON metadata header, and CSV row embeds `provenance_label` (`Synthetic Demo`, `Imported Events`, or `AWS Read-only Scan`) and UTC timestamps (`TC-14`). |
