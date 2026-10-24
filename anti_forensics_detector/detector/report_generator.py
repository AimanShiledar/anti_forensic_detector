"""Export analysis results as JSON or CSV. Not a legally authenticated exhibit."""

from __future__ import annotations

import csv
import json
from io import StringIO
from pathlib import Path

from detector.models import AnalysisResult

REPORT_LIMITATIONS = [
    "This report summarizes rule-based indicators from supplied evidence. It is not a court-authenticated forensic image or chain-of-custody package.",
    "Absence of high-priority findings does not prove that anti-forensic activity did not occur.",
    "Presence of findings does not automatically prove malicious intent.",
    "Synthetic demonstration records are labeled simulated=true and must not be presented as live system collection.",
    "SHA-256 baselines are only as trustworthy as their storage and access control.",
]


def build_report_dict(result: AnalysisResult) -> dict:
    payload = result.to_dict()
    payload["limitations"] = list(dict.fromkeys(result.limitations + REPORT_LIMITATIONS))
    payload["rules_triggered"] = sorted({f.rule_id for f in result.findings})
    payload["summary"] = {
        "records_analyzed": result.records_analyzed,
        "files_checked": result.files_checked,
        "findings": len(result.findings),
        "high_or_critical_findings": result.high_priority_count(),
        "correlated_groups": len(result.correlations),
        "simulated_findings": sum(1 for f in result.findings if f.simulated),
    }
    return payload


def report_to_json(result: AnalysisResult) -> str:
    return json.dumps(build_report_dict(result), indent=2)


def report_to_csv(result: AnalysisResult) -> str:
    buffer = StringIO()
    fieldnames = [
        "finding_id",
        "module",
        "severity",
        "certainty",
        "rule_id",
        "evidence_ref",
        "related_path",
        "related_timestamp",
        "host",
        "simulated",
        "explanation",
        "recommended_action",
        "source_dataset",
        "scan_time",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for finding in result.findings:
        writer.writerow(
            {
                "finding_id": finding.finding_id,
                "module": finding.module,
                "severity": finding.severity,
                "certainty": finding.certainty,
                "rule_id": finding.rule_id,
                "evidence_ref": finding.evidence_ref,
                "related_path": finding.related_path or "",
                "related_timestamp": finding.related_timestamp or "",
                "host": finding.host or "",
                "simulated": finding.simulated,
                "explanation": finding.explanation,
                "recommended_action": finding.recommended_action,
                "source_dataset": finding.source_dataset or "",
                "scan_time": result.scan_time,
            }
        )
    return buffer.getvalue()


def write_report_files(result: AnalysisResult, directory: str | Path, stem: str = "forensic_report") -> tuple[Path, Path]:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / f"{stem}.json"
    csv_path = directory / f"{stem}.csv"
    json_path.write_text(report_to_json(result), encoding="utf-8")
    csv_path.write_text(report_to_csv(result), encoding="utf-8")
    return json_path, csv_path
