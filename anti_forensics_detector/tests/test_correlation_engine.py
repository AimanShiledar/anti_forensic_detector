from detector.correlation_engine import correlate_findings
from detector.models import Finding
from detector.pipeline import run_analysis
from detector.report_generator import build_report_dict, report_to_csv, report_to_json
from detector.rules import load_rules


def _finding(**kwargs):
    base = dict(
        finding_id="F",
        module="log_detector",
        evidence_ref="E",
        detection_time="2026-10-18T15:00:00+00:00",
        observed_evidence={},
        rule_id="LOG-EXPLICIT-CLEAR",
        severity="HIGH",
        explanation="demo",
        recommended_action="review",
        certainty="CONFIRMED_OBSERVATION",
        simulated=True,
        related_path="/demo/app.log",
        related_timestamp="2026-10-18T14:05:00Z",
        host="HOST-A",
    )
    base.update(kwargs)
    return Finding(**base)


def test_related_findings_are_grouped_and_priority_raised():
    rules = load_rules()
    findings = [
        _finding(finding_id="L1", module="log_detector", severity="HIGH"),
        _finding(
            finding_id="I1",
            module="integrity_checker",
            rule_id="INT-HASH-MISMATCH",
            severity="HIGH",
            related_timestamp="2026-10-18T14:06:00Z",
        ),
        _finding(
            finding_id="T1",
            module="timestamp_analyzer",
            rule_id="TS-CREATED-AFTER-MODIFIED",
            severity="MEDIUM",
            related_timestamp="2026-10-18T14:06:00Z",
        ),
    ]
    groups = correlate_findings(findings, rules)
    assert len(groups) == 1
    assert set(groups[0].finding_ids) == {"L1", "I1", "T1"}
    assert groups[0].investigation_priority in {"HIGH", "CRITICAL"}
    assert groups[0].score >= 12


def test_unrelated_findings_are_not_grouped():
    rules = load_rules()
    findings = [
        _finding(finding_id="A", host="HOST-A", related_path="/a.log", related_timestamp="2026-10-18T14:00:00Z"),
        _finding(
            finding_id="B",
            module="integrity_checker",
            rule_id="INT-HASH-MISMATCH",
            host="HOST-B",
            related_path="/b.bin",
            related_timestamp="2026-10-18T14:01:00Z",
        ),
    ]
    groups = correlate_findings(findings, rules)
    assert groups == []


def test_same_dataset_alone_does_not_correlate_without_shared_context():
    rules = load_rules()
    findings = [
        _finding(finding_id="A", host=None, related_path=None, related_timestamp="2026-10-18T14:00:00Z"),
        _finding(
            finding_id="B",
            module="history_analyzer",
            rule_id="HIST-EXPLICIT-CLEAR",
            host=None,
            related_path=None,
            related_timestamp="2026-10-18T14:01:00Z",
            evidence_ref="OTHER",
        ),
    ]
    groups = correlate_findings(findings, rules)
    assert groups == []


def test_duplicate_underlying_event_not_double_counted():
    rules = load_rules()
    findings = [
        _finding(finding_id="A1", evidence_ref="SAME", rule_id="LOG-EXPLICIT-CLEAR"),
        _finding(finding_id="A2", evidence_ref="SAME", rule_id="LOG-EXPLICIT-CLEAR", module="log_detector"),
        _finding(
            finding_id="B1",
            module="integrity_checker",
            rule_id="INT-HASH-MISMATCH",
            evidence_ref="FILE",
            related_timestamp="2026-10-18T14:05:30Z",
        ),
    ]
    groups = correlate_findings(findings, rules)
    assert len(groups) == 1
    assert groups[0].finding_ids.count("A1") + groups[0].finding_ids.count("A2") == 1


def test_severity_thresholds_map_from_score():
    rules = load_rules()
    findings = [
        _finding(finding_id="L", severity="LOW", module="log_detector"),
        _finding(
            finding_id="H",
            module="history_analyzer",
            rule_id="HIST-SEQUENCE-GAP",
            severity="LOW",
            related_timestamp="2026-10-18T14:05:10Z",
        ),
    ]
    groups = correlate_findings(findings, rules)
    assert groups[0].investigation_priority in {"LOW", "MEDIUM", "INFORMATIONAL"}


def test_report_generation_contains_disclaimer_and_findings():
    result = run_analysis(
        event_records=[
            {
                "event_id": "E1",
                "timestamp": "2026-10-18T14:05:00Z",
                "event_type": "EVENTLOG_CLEARED",
                "host": "HOST-A",
                "related_path": "/demo/app.log",
                "simulated": True,
            }
        ],
        input_sources=["unit-test"],
    )
    payload = build_report_dict(result)
    assert "not automatic proof" in payload["disclaimer"].lower() or "not" in payload["disclaimer"].lower()
    json_text = report_to_json(result)
    csv_text = report_to_csv(result)
    assert "LOG-EXPLICIT-CLEAR" in json_text
    assert "finding_id" in csv_text
    assert result.high_priority_count() >= 1


def test_normal_pipeline_has_no_high_priority_from_bundled_normal_shape():
    result = run_analysis(
        event_records=[
            {
                "event_id": "N1",
                "timestamp": "2026-10-18T13:00:00Z",
                "event_type": "USER_LOGIN",
                "host": "HOST-A",
                "simulated": True,
            }
        ],
        metadata_records=[
            {
                "record_id": "M1",
                "path": "/demo/app.log",
                "created": "2026-10-01T00:00:00Z",
                "modified": "2026-10-02T00:00:00Z",
                "simulated": True,
            }
        ],
        history_records=[
            {"entry_id": "H1", "sequence": 1, "command": "whoami", "timestamp": "2026-10-18T13:01:00Z"}
        ],
        input_sources=["normal"],
    )
    assert result.high_priority_count() == 0
    assert len(result.findings) == 0 or all(f.severity not in {"HIGH", "CRITICAL"} for f in result.findings)
