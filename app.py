import sys
from pathlib import Path

import pandas as pd
import streamlit as st
import yaml

SRC_DIR = Path(__file__).resolve().parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from cloudsentinel.collectors.cloudtrail_importer import parse_cloudtrail_json_content
from cloudsentinel.collectors.demo_provider import CollectionBundle, load_demo_bundle
from cloudsentinel.db.repository import CloudSentinelRepository
from cloudsentinel.engine.scanner import (
    get_default_event_rules,
    get_default_resource_rules,
    run_resource_scan,
)
from cloudsentinel.reports.report_generator import (
    generate_csv_report,
    generate_json_report,
)


def load_settings(config_path: str = "config/settings.yaml") -> dict:
    path = Path(config_path)
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def main() -> None:
    st.set_page_config(
        page_title="CloudSentinel | CSPM & Threat Detection",
        layout="wide",
    )

    settings = load_settings()
    paths_cfg = settings.get("paths", {})
    risk_cfg = settings.get("risk_model", {})
    rules_cfg = settings.get("rules", {})

    db_path = paths_cfg.get("sqlite_db", "data/cloudsentinel.db")
    repo = CloudSentinelRepository(db_path=db_path)

    with st.sidebar:
        st.header("🛡️ CloudSentinel")
        st.caption("Phase 5: CSPM + CloudTrail Threat Detection")
        st.markdown("**Active Source Provenance:** `Synthetic Demo / Imported Events`")
        st.markdown(f"**SQLite DB:** `{db_path}`")
        st.divider()
        if st.button("🔄 Reset Demo Database", help="Clears SQLite tables for a fresh live demo"):
            repo.reset_database()
            st.success("Database reset complete!")
            st.rerun()

    st.title("🛡️ CloudSentinel — Cloud Security Posture & Threat Detection")
    st.caption(risk_cfg.get("heuristic_notice", "Illustrative heuristic risk model (0-100)."))

    scans = repo.list_scans(limit=25)
    all_findings = repo.list_findings()
    persisted_events = repo.list_events()
    latest_scan = scans[0] if scans else None

    if latest_scan:
        status_label = latest_scan["status"].upper()
        banner_text = (
            f"**Latest Scan #{latest_scan['id']}**  |  "
            f"**Provenance:** `{latest_scan['provenance_label']}`  |  "
            f"**Status:** `{status_label}`  |  "
            f"**Resources Assessed:** `{latest_scan['resources_scanned']}`  |  "
            f"**Persisted Audit Events:** `{len(persisted_events)}`  |  "
            f"**Diagnostics/Errors:** `{latest_scan['errors_count']}`"
        )
        if latest_scan["status"] == "completed":
            st.info(banner_text)
        elif latest_scan["status"] == "partial":
            st.warning(f"⚠️ PARTIAL SCAN (Do not treat as clean bill of health): {banner_text}")
        else:
            st.error(f"🚨 FAILED SCAN (No findings auto-resolved): {banner_text}")
    else:
        st.info("**No scans recorded yet.** Go to the **▶️ Run Scan** tab to execute a scan.")

    tabs = st.tabs(
        [
            "📊 Overview",
            "▶️ Run Scan",
            "🔍 Findings Explorer",
            "🕵️ Event Analyzer",
            "🛠️ Remediation & Lifecycle",
            "📥 Reports & Export",
            "⚙️ Settings & Rule Catalogue",
        ]
    )

    # TAB 1: OVERVIEW
    with tabs[0]:
        col1, col2, col3, col4, col5 = st.columns(5)
        open_findings = [f for f in all_findings if f["status"] == "Open"]
        ack_findings = [f for f in all_findings if f["status"] == "Acknowledged"]
        res_findings = [f for f in all_findings if f["status"] == "Resolved"]
        sup_findings = [f for f in all_findings if f["status"] == "Suppressed"]

        col1.metric("Total Tracked Findings", len(all_findings))
        col2.metric("Open (Action Needed)", len(open_findings))
        col3.metric("Acknowledged", len(ack_findings))
        col4.metric("Resolved (Verified)", len(res_findings))
        col5.metric("Suppressed (Exceptions)", len(sup_findings))

        if all_findings:
            c_left, c_right = st.columns(2)
            with c_left:
                st.subheader("Active Findings by Severity")
                active_list = open_findings + ack_findings
                sev_counts = {
                    sev: sum(1 for f in active_list if f["severity"] == sev)
                    for sev in ("Critical", "High", "Medium", "Low", "Unknown")
                }
                sev_df = pd.DataFrame([{"Severity": k, "Count": v} for k, v in sev_counts.items()])
                st.bar_chart(sev_df.set_index("Severity"))

            with c_right:
                st.subheader("Findings by Lifecycle Status")
                status_df = pd.DataFrame(
                    [
                        {"Status": "Open", "Count": len(open_findings)},
                        {"Status": "Acknowledged", "Count": len(ack_findings)},
                        {"Status": "Resolved", "Count": len(res_findings)},
                        {"Status": "Suppressed", "Count": len(sup_findings)},
                    ]
                )
                st.bar_chart(status_df.set_index("Status"))

    # TAB 2: RUN SCAN
    with tabs[1]:
        st.subheader("Execute Posture & CloudTrail Threat Detection Scan")
        sim_mode = st.radio(
            "Select Scan Mode:",
            options=[
                "1. Full Synthetic Demo (6 Resources + 6 CloudTrail Events -> All 9 Rules Evaluated)",
                "2. Remediated / Clean Posture Simulation (Demonstrates TC-12 Auto-Resolution)",
                "3. Simulated Collector Failure (Demonstrates TC-13 Safe Failure Handling)",
            ],
        )

        if st.button("🚀 Launch Selected Scan", type="primary"):
            base_bundle = load_demo_bundle(
                resources_path=paths_cfg.get("demo_resources", "data/demo/resources.json"),
                events_path=paths_cfg.get("demo_events", "data/demo/cloudtrail_events.json"),
            )
            if sim_mode.startswith("1."):
                target_bundle = base_bundle
                repo.save_events(base_bundle.events)
            elif sim_mode.startswith("2."):
                safe_only = [
                    r
                    for r in base_bundle.resources
                    if r["resource_id"] in ("sg-demo-safe-003", "arn:aws:s3:::demo-private-logs-bucket")
                ]
                target_bundle = CollectionBundle(
                    source="synthetic_demo",
                    provenance_label="Synthetic Demo (Remediated)",
                    collected_at=base_bundle.collected_at,
                    resources=safe_only,
                    events=[],
                    diagnostics=[],
                )
            else:
                target_bundle = CollectionBundle(
                    source="synthetic_demo",
                    provenance_label="Synthetic Demo (Collector Error)",
                    collected_at=base_bundle.collected_at,
                    resources=[],
                    events=[],
                    diagnostics=["Simulated API AccessDenied / Collector Failure during resource fetch."],
                )

            scan_res = run_resource_scan(
                target_bundle,
                failed_login_threshold=int(rules_cfg.get("auth_failed_login_threshold", 3)),
                failed_login_window_minutes=int(rules_cfg.get("auth_window_minutes", 15)),
            )
            new_scan_id = repo.save_scan_and_sync_findings(scan_res)
            st.success(
                f"Scan #{new_scan_id} finished with status `{scan_res.status.upper()}` "
                f"({len(scan_res.findings)} matches, {len(scan_res.diagnostics)} diagnostics)."
            )
            st.rerun()

    # TAB 3: FINDINGS EXPLORER
    with tabs[2]:
        st.subheader("Search & Filter Evidence-Backed Findings")
        f_col1, f_col2, f_col3, f_col4 = st.columns(4)
        sel_status = f_col1.selectbox("Lifecycle Status", ["All", "Open", "Acknowledged", "Resolved", "Suppressed"])
        sel_sev = f_col2.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low", "Unknown"])
        sel_family = f_col3.selectbox("Rule Family", ["All", "NET", "S3", "IAM", "LOG", "AUTH", "KEY"])
        search_txt = f_col4.text_input("Search Resource ID / Actor / Rule / Title", "")

        filtered = repo.list_findings(
            status=sel_status,
            severity=sel_sev,
            rule_family=sel_family,
            search_query=search_txt,
        )

        st.caption(f"Showing **{len(filtered)}** matching finding(s) from SQLite.")
        if filtered:
            st.dataframe(
                [
                    {
                        "Rule ID": f["rule_id"],
                        "Severity": f["severity"],
                        "Risk Score": f["risk_score"],
                        "Status": f["status"],
                        "Resource / Identity": f["resource_id"],
                        "Title": f["title"],
                        "Last Seen (UTC)": f["last_seen"],
                        "Fingerprint": f["fingerprint"],
                    }
                    for f in filtered
                ],
                width="stretch",
            )

            st.markdown("### 🔎 Detailed Evidence & Heuristic Breakdown")
            for f in filtered:
                with st.expander(
                    f"[{f['severity']} | Score: {f['risk_score']} | {f['status']}] "
                    f"{f['rule_id']} — {f['resource_id']} ({f['fingerprint']})"
                ):
                    st.write(f"**Title:** {f['title']}")
                    st.write(f"**Risk Breakdown:** {f['score_breakdown']['explanation']}")
                    st.write(f"**Recommended Fix:** {f['recommendation']}")
                    st.json(f["evidence"])

    # TAB 4: EVENT ANALYZER (PHASE 5)
    with tabs[3]:
        st.subheader("🕵️ CloudTrail Audit Event Analyzer & Custom Log Importer")
        st.markdown(
            "Analyze normalized CloudTrail management and authentication events for "
            "`LOG-001` (Trail Tampering), `IAM-002` (Privileged Policy Attachment), "
            "`AUTH-001` (Brute-Force Console Logins), and `KEY-001` (Access Key Creation)."
        )

        uploaded_file = st.file_uploader(
            "Upload Custom CloudTrail JSON File (Supports `events` or AWS `Records` schema, max 5 MB):",
            type=["json"],
        )
        if uploaded_file is not None:
            raw_content = uploaded_file.getvalue().decode("utf-8", errors="replace")
            imp_bundle = parse_cloudtrail_json_content(
                raw_content,
                source="imported_events",
                provenance_label="Imported Events",
            )
            if imp_bundle.diagnostics:
                st.warning("Diagnostics during event import:")
                for d in imp_bundle.diagnostics:
                    st.write(f"- {d}")
            if imp_bundle.events and st.button("🔍 Analyze & Persist Uploaded Events"):
                repo.save_events(imp_bundle.events)
                evt_collection = CollectionBundle(
                    source=imp_bundle.source,
                    provenance_label=imp_bundle.provenance_label,
                    collected_at="uploaded_now",
                    resources=[],
                    events=imp_bundle.events,
                    diagnostics=imp_bundle.diagnostics,
                )
                evt_scan = run_resource_scan(evt_collection, include_events=True)
                scan_id = repo.save_scan_and_sync_findings(evt_scan, provider="imported_events")
                st.success(
                    f"Imported {len(imp_bundle.events)} events and saved Scan #{scan_id} "
                    f"with {len(evt_scan.findings)} event finding(s)!"
                )
                st.rerun()

        st.divider()
        st.subheader(f"Persisted Audit Event Timeline ({len(persisted_events)} Events in SQLite)")
        if persisted_events:
            e_col1, e_col2 = st.columns(2)
            actors = ["All"] + sorted({e["actor"] for e in persisted_events})
            evt_names = ["All"] + sorted({e["event_name"] for e in persisted_events})
            sel_actor = e_col1.selectbox("Filter by Actor Identity", actors)
            sel_evt_name = e_col2.selectbox("Filter by Event Name", evt_names)

            shown_events = repo.list_events(actor=sel_actor, event_name=sel_evt_name)
            st.dataframe(
                [
                    {
                        "Event ID": e["source_event_id"],
                        "Event Time (UTC)": e["event_time"],
                        "Event Name": e["event_name"],
                        "Actor Identity": e["actor"],
                        "Source IP": e["source_ip"],
                        "Region": e["region"],
                        "Status": e["status"],
                        "Redacted Details": str(e["details"]),
                    }
                    for e in shown_events
                ],
                width="stretch",
            )
        else:
            st.info("No events persisted yet. Run the Full Synthetic Demo scan in the **▶️ Run Scan** tab.")

    # TAB 5: REMEDIATION & LIFECYCLE
    with tabs[4]:
        st.subheader("Update Finding Lifecycle Status & Audit Trail")
        if all_findings:
            fp_options = {
                f"{f['rule_id']} | {f['resource_id']} [{f['status']}] ({f['fingerprint']})": f["fingerprint"]
                for f in all_findings
            }
            selected_label = st.selectbox("Select Finding to Review / Transition:", list(fp_options.keys()))
            target_fp = fp_options[selected_label]

            c1, c2, c3 = st.columns(3)
            new_status = c1.selectbox("New Status", ["Open", "Acknowledged", "Suppressed", "Resolved"])
            actor = c2.text_input("Analyst Identifier", value="ayush_analyst")
            note = c3.text_input("Analyst Note / Suppression Justification (Required for Suppressed)")

            if st.button("💾 Apply Status Transition"):
                try:
                    repo.update_finding_status(
                        fingerprint=target_fp,
                        new_status=new_status,
                        actor_label=actor,
                        note_or_reason=note,
                    )
                    st.success(f"Updated `{target_fp}` to **{new_status}** and recorded audit log!")
                    st.rerun()
                except ValueError as err:
                    st.error(str(err))

        st.divider()
        st.subheader("Immutable Workflow Audit Log (`audit_log` Table)")
        audit_rows = repo.list_audit_logs()
        if audit_rows:
            st.dataframe(audit_rows, width="stretch")

    # TAB 6: REPORTS & EXPORT
    with tabs[5]:
        st.subheader("Export Evidence-Backed Assessment Reports (JSON & CSV)")
        if scans:
            scan_choices = {"All Current Persisted Findings (Latest Scan Context)": None}
            for s in scans:
                scan_choices[f"Scan #{s['id']} ({s['status'].upper()} | {s['finished_at']})"] = s["id"]

            chosen_scan_label = st.selectbox("Select Scan Scope for Export:", list(scan_choices.keys()))
            chosen_scan_id = scan_choices[chosen_scan_label]

            if chosen_scan_id is not None:
                export_scan = repo.get_scan_by_id(chosen_scan_id)
                export_findings = repo.list_findings(scan_id=chosen_scan_id)
            else:
                export_scan = latest_scan
                export_findings = all_findings

            json_str = generate_json_report(export_scan, export_findings)
            csv_str = generate_csv_report(export_scan, export_findings)

            dl_col1, dl_col2 = st.columns(2)
            dl_col1.download_button(
                label="📥 Download JSON Report",
                data=json_str,
                file_name=f"cloudsentinel_report_scan_{export_scan['id'] if export_scan else 'all'}.json",
                mime="application/json",
                type="primary",
            )
            dl_col2.download_button(
                label="📊 Download CSV Report",
                data=csv_str,
                file_name=f"cloudsentinel_report_scan_{export_scan['id'] if export_scan else 'all'}.csv",
                mime="text/csv",
            )

    # TAB 7: SETTINGS & RULE CATALOGUE
    with tabs[6]:
        st.subheader("Configured Deterministic Rule Catalogue (9 Rules: 5 Resource + 4 CloudTrail Event)")
        res_rules = get_default_resource_rules()
        evt_rules = get_default_event_rules()
        catalogue_rows = [
            {
                "Rule ID": r.rule_id,
                "Category": "Resource Posture",
                "Target Type": r.applicable_resource_type,
                "Default Severity": r.default_severity,
                "Title": r.title,
                "Recommendation": r.recommendation,
            }
            for r in res_rules
        ] + [
            {
                "Rule ID": er.rule_id,
                "Category": "CloudTrail Audit Event",
                "Target Type": "aws.cloudtrail.event",
                "Default Severity": er.default_severity,
                "Title": er.title,
                "Recommendation": er.recommendation,
            }
            for er in evt_rules
        ]
        st.dataframe(catalogue_rows, width="stretch")


if __name__ == "__main__":
    main()
