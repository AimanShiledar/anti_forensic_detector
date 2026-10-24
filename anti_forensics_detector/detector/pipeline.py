"""Orchestrate loaders and detectors into a single analysis result."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from detector.correlation_engine import correlate_findings
from detector.history_analyzer import analyze_history
from detector.integrity_checker import verify_baseline
from detector.log_detector import analyze_log_events
from detector.models import AnalysisResult, Finding, LoadIssue, utc_now_iso
from detector.report_generator import REPORT_LIMITATIONS
from detector.rules import load_rules
from detector.timestamp_analyzer import analyze_timestamps

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def run_analysis(
    *,
    event_records: list[dict[str, Any]] | None = None,
    metadata_records: list[dict[str, Any]] | None = None,
    history_records: list[dict[str, Any]] | None = None,
    history_snapshot: list[dict[str, Any]] | None = None,
    input_sources: list[str] | None = None,
    baseline_path: str | Path | None = None,
    extra_integrity_paths: Iterable[str | Path] | None = None,
    workspace_root: str | Path | None = None,
    rules: dict[str, Any] | None = None,
    load_issues: list[LoadIssue] | None = None,
) -> AnalysisResult:
    rules = rules or load_rules()
    event_records = event_records or []
    metadata_records = metadata_records or []
    history_records = history_records or []
    findings: list[Finding] = []

    findings.extend(analyze_log_events(event_records, rules, source_name="events"))
    findings.extend(analyze_timestamps(metadata_records, rules, source_name="metadata"))
    findings.extend(
        analyze_history(
            history_records,
            rules,
            trusted_snapshot=history_snapshot,
            source_name="history",
        )
    )

    files_checked = 0
    if baseline_path and Path(baseline_path).is_file():
        integrity_findings = verify_baseline(
            baseline_path,
            extra_paths=extra_integrity_paths,
            workspace_root=workspace_root,
        )
        findings.extend(integrity_findings)
        try:
            import json

            manifest = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
            files_checked = len(manifest.get("files") or [])
        except (OSError, json.JSONDecodeError):
            files_checked = 0
        if extra_integrity_paths:
            files_checked = max(files_checked, len(list(extra_integrity_paths)))

    correlations = correlate_findings(findings, rules)
    records_analyzed = len(event_records) + len(metadata_records) + len(history_records)

    notes = [
        "All detections are produced by transparent, configurable rules.",
        "Scores are ordinal investigation priorities, not calibrated probabilities.",
    ]
    if any(f.simulated for f in findings) or _any_simulated(event_records, metadata_records, history_records):
        notes.append("One or more input records are labeled simulated. Treat those results as demonstration data.")

    return AnalysisResult(
        scan_time=utc_now_iso(),
        input_sources=input_sources or [],
        records_analyzed=records_analyzed,
        files_checked=files_checked,
        findings=findings,
        correlations=correlations,
        load_issues=load_issues or [],
        rules_triggered=sorted({f.rule_id for f in findings}),
        limitations=list(REPORT_LIMITATIONS),
        notes=notes,
    )


def _any_simulated(*groups: list[dict[str, Any]]) -> bool:
    for group in groups:
        for item in group:
            if isinstance(item, dict) and item.get("simulated"):
                return True
    return False
