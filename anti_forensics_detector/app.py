"""Streamlit dashboard for anti-forensic indicator analysis (defensive prototype)."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from detector.evidence_loader import load_records_from_bytes, load_records_from_path
from detector.integrity_checker import LIMITATIONS as INTEGRITY_LIMITATIONS
from detector.integrity_checker import create_baseline, sha256_file, verify_baseline
from detector.models import AnalysisResult, LoadIssue
from detector.pipeline import run_analysis
from detector.report_generator import report_to_csv, report_to_json
from detector.rules import PROJECT_ROOT, load_rules

WORKSPACE = PROJECT_ROOT / "workspace"
DEMO_FILES = WORKSPACE / "demo_files"
BASELINE_PATH = WORKSPACE / "baselines" / "workspace_baseline.json"
TEST_DATA = PROJECT_ROOT / "test_data"

st.set_page_config(
    page_title="Anti-Forensic Activity Detection System",
    page_icon="🛡️",
    layout="wide",
)

DISCLAIMER = (
    "This prototype reports **investigation indicators** from imported evidence and a dedicated "
    "workspace. Findings are **not** automatic proof of malicious intent, legally authenticated "
    "exhibits, or complete coverage of anti-forensic techniques. Bundled datasets are **synthetic**."
)


def _init_state() -> None:
    defaults = {
        "event_records": [],
        "metadata_records": [],
        "history_records": [],
        "history_snapshot": None,
        "input_sources": [],
        "load_issues": [],
        "result": None,
        "demo_mode": "none",
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _add_source(label: str) -> None:
    if label not in st.session_state.input_sources:
        st.session_state.input_sources.append(label)


def _extend_issues(issues: list[LoadIssue]) -> None:
    st.session_state.load_issues.extend(issues)


def load_json_dataset(path: Path, kind: str) -> None:
    records, issues = load_records_from_path(path, source_label=str(path.name))
    _extend_issues(issues)
    if kind == "events":
        st.session_state.event_records.extend(records)
    elif kind == "metadata":
        st.session_state.metadata_records.extend(records)
    elif kind == "history":
        st.session_state.history_records.extend(records)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and payload.get("trusted_snapshot"):
                st.session_state.history_snapshot = payload["trusted_snapshot"]
        except (OSError, json.JSONDecodeError):
            pass
    _add_source(path.name)


def ingest_uploads(files, kind: str) -> None:
    if not files:
        return
    for uploaded in files:
        records, issues = load_records_from_bytes(
            uploaded.getvalue(),
            uploaded.name,
            source_label=uploaded.name,
        )
        _extend_issues(issues)
        if kind == "events":
            st.session_state.event_records.extend(records)
        elif kind == "metadata":
            st.session_state.metadata_records.extend(records)
        else:
            st.session_state.history_records.extend(records)
        _add_source(f"upload:{uploaded.name}")


def list_workspace_files() -> list[Path]:
    DEMO_FILES.mkdir(parents=True, exist_ok=True)
    return sorted(p for p in DEMO_FILES.rglob("*") if p.is_file())


def findings_table(result: AnalysisResult) -> pd.DataFrame:
    rows = []
    for finding in result.findings:
        rows.append(
            {
                "Finding ID": finding.finding_id,
                "Module": finding.module,
                "Severity": finding.severity,
                "Certainty": finding.certainty,
                "Simulated": finding.simulated,
                "Evidence": finding.evidence_ref,
                "Rule": finding.rule_id,
                "Explanation": finding.explanation,
                "Recommended action": finding.recommended_action,
            }
        )
    return pd.DataFrame(rows)


_init_state()

st.title("Anti-Forensic Activity Detection System")
st.caption("Evidence-Based Detection and Correlation of Potential Anti-Forensic Indicators")
st.info(DISCLAIMER)

tabs = st.tabs(
    [
        "Overview",
        "Evidence Input",
        "Detection Results",
        "Correlated Activity",
        "File Integrity Scanner",
        "Forensic Report",
    ]
)

with tabs[1]:
    st.subheader("Evidence Input")
    st.write(
        "Import structured JSON or CSV records. The application does not execute uploaded files "
        "or imported commands. Original evidence is analyzed read-only."
    )

    col_a, col_b, col_c = st.columns(3)
    with col_a:
        if st.button("Load Scenario 1: Normal (synthetic)", use_container_width=True):
            st.session_state.event_records = []
            st.session_state.metadata_records = []
            st.session_state.history_records = []
            st.session_state.history_snapshot = None
            st.session_state.input_sources = []
            st.session_state.load_issues = []
            load_json_dataset(TEST_DATA / "normal_events.json", "events")
            load_json_dataset(TEST_DATA / "normal_metadata.json", "metadata")
            load_json_dataset(TEST_DATA / "normal_history.json", "history")
            st.session_state.demo_mode = "normal"
            st.success("Loaded synthetic normal-activity datasets.")
    with col_b:
        if st.button("Load Scenario 2–5: Suspicious (synthetic)", use_container_width=True):
            st.session_state.event_records = []
            st.session_state.metadata_records = []
            st.session_state.history_records = []
            st.session_state.history_snapshot = None
            st.session_state.input_sources = []
            st.session_state.load_issues = []
            load_json_dataset(TEST_DATA / "suspicious_events.json", "events")
            load_json_dataset(TEST_DATA / "sample_metadata.json", "metadata")
            load_json_dataset(TEST_DATA / "sample_history.json", "history")
            st.session_state.demo_mode = "suspicious"
            st.success("Loaded synthetic suspicious datasets. All records are labeled simulated.")
    with col_c:
        if st.button("Clear loaded evidence", use_container_width=True):
            st.session_state.event_records = []
            st.session_state.metadata_records = []
            st.session_state.history_records = []
            st.session_state.history_snapshot = None
            st.session_state.input_sources = []
            st.session_state.load_issues = []
            st.session_state.result = None
            st.session_state.demo_mode = "none"

    st.markdown("**Optional uploads** (JSON or CSV, max 2 MB each)")
    u1, u2, u3 = st.columns(3)
    with u1:
        ingest_uploads(st.file_uploader("Event records", type=["json", "csv"], accept_multiple_files=True, key="up_events"), "events")
    with u2:
        ingest_uploads(st.file_uploader("Timestamp metadata", type=["json", "csv"], accept_multiple_files=True, key="up_meta"), "metadata")
    with u3:
        ingest_uploads(st.file_uploader("Command history", type=["json", "csv"], accept_multiple_files=True, key="up_hist"), "history")

    c1, c2, c3 = st.columns(3)
    c1.metric("Event records loaded", len(st.session_state.event_records))
    c2.metric("Metadata records loaded", len(st.session_state.metadata_records))
    c3.metric("History records loaded", len(st.session_state.history_records))

    if st.session_state.load_issues:
        st.warning("Some inputs had recoverable problems:")
        for issue in st.session_state.load_issues:
            st.write(f"- `{issue.source}`: {issue.message}")

    include_integrity = st.checkbox(
        "Include current workspace baseline in this analysis (if it exists)",
        value=True,
    )
    if st.button("Analyze loaded evidence", type="primary"):
        baseline = BASELINE_PATH if include_integrity and BASELINE_PATH.is_file() else None
        result = run_analysis(
            event_records=st.session_state.event_records,
            metadata_records=st.session_state.metadata_records,
            history_records=st.session_state.history_records,
            history_snapshot=st.session_state.history_snapshot,
            input_sources=list(st.session_state.input_sources),
            baseline_path=baseline,
            extra_integrity_paths=list_workspace_files() if baseline else None,
            workspace_root=WORKSPACE,
            rules=load_rules(),
            load_issues=list(st.session_state.load_issues),
        )
        st.session_state.result = result
        st.success(f"Analysis complete at {result.scan_time}. Open the Detection Results tab.")

result: AnalysisResult | None = st.session_state.result

with tabs[0]:
    st.subheader("Overview")
    if result is None:
        st.write("Load evidence and click **Analyze loaded evidence** to populate totals from actual analysis output.")
    else:
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Records analyzed", result.records_analyzed)
        m2.metric("Findings", len(result.findings))
        m3.metric("High/Critical findings", result.high_priority_count())
        m4.metric("Correlated groups", len(result.correlations))
        m5.metric("Files integrity-checked", result.files_checked)
        if result.findings:
            df = findings_table(result)
            fig = px.histogram(df, x="Severity", color="Module", title="Findings by severity and module")
            st.plotly_chart(fig, use_container_width=True)
        for note in result.notes:
            st.caption(note)

with tabs[2]:
    st.subheader("Detection Results")
    if result is None:
        st.write("No analysis results yet.")
    else:
        df = findings_table(result)
        if df.empty:
            st.success(
                "No configured high-priority indicators were produced for this dataset. "
                "That does **not** prove the system is free of anti-forensic activity."
            )
        else:
            modules = ["(all)"] + sorted(df["Module"].unique().tolist())
            severities = ["(all)"] + sorted(df["Severity"].unique().tolist())
            f1, f2 = st.columns(2)
            selected_module = f1.selectbox("Filter by module", modules)
            selected_sev = f2.selectbox("Filter by severity", severities)
            filtered = df
            if selected_module != "(all)":
                filtered = filtered[filtered["Module"] == selected_module]
            if selected_sev != "(all)":
                filtered = filtered[filtered["Severity"] == selected_sev]
            st.dataframe(filtered, use_container_width=True, hide_index=True)

with tabs[3]:
    st.subheader("Correlated Activity")
    if result is None or not result.correlations:
        st.write("No correlated groups. Correlation requires related findings that share path/host context.")
    else:
        for group in result.correlations:
            label = f"{group.group_id} — {group.investigation_priority} (score {group.score})"
            if group.simulated:
                label += " [SIMULATED]"
            with st.expander(label, expanded=True):
                st.write(group.explanation)
                st.json(group.linking_context)
                st.write("Member findings:")
                members = [f for f in result.findings if f.finding_id in group.finding_ids]
                st.dataframe(
                    pd.DataFrame(
                        [
                            {
                                "Finding ID": f.finding_id,
                                "Module": f.module,
                                "Severity": f.severity,
                                "Rule": f.rule_id,
                                "Evidence": f.evidence_ref,
                            }
                            for f in members
                        ]
                    ),
                    use_container_width=True,
                    hide_index=True,
                )
                st.caption(
                    "Investigation priority is a transparent rule-based ordinal label, not a probability."
                )

with tabs[4]:
    st.subheader("File Integrity Scanner")
    st.write(
        "Operations are limited to `workspace/demo_files`. Baseline creation and verification are separate. "
        "Never use this panel on production system files for the academic demonstration."
    )
    for limitation in INTEGRITY_LIMITATIONS:
        st.caption(limitation)

    files = list_workspace_files()
    if not files:
        st.warning("No files found under workspace/demo_files.")
    else:
        labels = [str(p.relative_to(WORKSPACE)) for p in files]
        selected_labels = st.multiselect("Select workspace files", labels, default=labels)
        selected_paths = [WORKSPACE / label for label in selected_labels]

        b1, b2 = st.columns(2)
        with b1:
            if st.button("Create trusted baseline", use_container_width=True):
                if not selected_paths:
                    st.error("Select at least one workspace file.")
                else:
                    manifest = create_baseline(selected_paths, BASELINE_PATH, workspace_root=WORKSPACE)
                    st.success(f"Baseline written to {BASELINE_PATH}")
                    st.json(manifest)
        with b2:
            if st.button("Verify against baseline", use_container_width=True):
                findings = verify_baseline(
                    BASELINE_PATH,
                    extra_paths=selected_paths,
                    workspace_root=WORKSPACE,
                )
                if not findings:
                    st.success("All selected baseline files currently match the trusted hashes.")
                    if selected_paths:
                        demo = selected_paths[0]
                        st.code(f"{demo.name}: SHA-256 {sha256_file(demo)}")
                else:
                    st.error("Integrity differences were detected (confirmed observations relative to the baseline).")
                    st.dataframe(
                        pd.DataFrame(
                            [
                                {
                                    "Finding ID": f.finding_id,
                                    "Rule": f.rule_id,
                                    "Path": f.related_path,
                                    "Expected": (f.observed_evidence or {}).get("expected_sha256"),
                                    "Observed": (f.observed_evidence or {}).get("observed_sha256"),
                                    "Explanation": f.explanation,
                                }
                                for f in findings
                            ]
                        ),
                        use_container_width=True,
                        hide_index=True,
                    )

        st.markdown("**Demonstration helper (workspace file only)**")
        target = DEMO_FILES / "sample_monitored.txt"
        if st.button("Modify sample_monitored.txt for mismatch demo"):
            original = target.read_text(encoding="utf-8") if target.exists() else ""
            if "TAMPERED" not in original:
                target.write_text(original + "\nTAMPERED DEMO LINE\n", encoding="utf-8")
            st.warning("Synthetic modification applied to the demo file only. Click Verify against baseline.")
        if st.button("Restore sample_monitored.txt"):
            target.write_text(
                "Demo monitored file for SHA-256 integrity checks.\n"
                "This file lives in the project workspace only.\n"
                "Original content version A.\n",
                encoding="utf-8",
            )
            st.success("Demo file restored to original demonstration content.")

with tabs[5]:
    st.subheader("Forensic Report")
    st.caption(
        "Exported files are analysis summaries. They are not forensically authenticated images "
        "and are not automatically legally admissible because they were generated."
    )
    if result is None:
        st.write("Run an analysis first.")
    else:
        json_text = report_to_json(result)
        csv_text = report_to_csv(result)
        st.json(json.loads(json_text)["summary"])
        st.download_button(
            "Download JSON report",
            data=json_text,
            file_name="anti_forensic_report.json",
            mime="application/json",
        )
        st.download_button(
            "Download CSV findings",
            data=csv_text,
            file_name="anti_forensic_findings.csv",
            mime="text/csv",
        )
        with st.expander("Limitations included in the report"):
            for item in result.limitations:
                st.write(f"- {item}")
