from datetime import datetime, timezone

from detector.rules import load_rules
from detector.timeutil import parse_iso8601
from detector.timestamp_analyzer import analyze_timestamps


def test_timezone_normalization():
    dt = parse_iso8601("2026-10-18T14:00:00+05:30")
    assert dt.tzinfo is not None
    assert dt.utcoffset().total_seconds() == 0
    assert dt.hour == 8 and dt.minute == 30


def test_created_after_modified_flagged():
    rules = load_rules()
    records = [
        {
            "record_id": "T1",
            "path": "/demo/app.log",
            "created": "2026-10-18T16:00:00Z",
            "modified": "2026-10-18T10:00:00Z",
            "simulated": True,
        }
    ]
    findings = analyze_timestamps(records, rules)
    assert any(f.rule_id == "TS-CREATED-AFTER-MODIFIED" for f in findings)


def test_future_timestamp_respects_clock_skew():
    rules = load_rules()
    now = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
    records = [
        {
            "record_id": "T2",
            "path": "/demo/future.dat",
            "created": "2026-10-18T12:02:00Z",
            "modified": "2026-10-18T12:02:00Z",
            "simulated": True,
        }
    ]
    findings = analyze_timestamps(records, rules, analysis_time=now)
    assert not any(f.rule_id == "TS-FUTURE-TIMESTAMP" for f in findings)
    records[0]["created"] = "2026-12-01T00:00:00Z"
    records[0]["modified"] = "2026-12-01T00:00:00Z"
    findings = analyze_timestamps(records, rules, analysis_time=now)
    assert any(f.rule_id == "TS-FUTURE-TIMESTAMP" for f in findings)


def test_malformed_and_missing_timestamps():
    rules = load_rules()
    records = [
        {"record_id": "BAD", "path": "/demo/a", "created": "nope", "modified": "2026-10-18T11:00:00Z"},
        {"record_id": "MISS", "path": "/demo/b"},
        "not-a-dict",
    ]
    findings = analyze_timestamps(records, rules)
    assert any(f.rule_id == "TS-MALFORMED-TIMESTAMP" for f in findings)
    assert any(f.rule_id == "TS-METADATA-MISSING" for f in findings)
    assert any(f.rule_id == "TS-MALFORMED-RECORD" for f in findings)


def test_atime_only_change_not_flagged_when_mtime_matches_baseline():
    rules = load_rules()
    records = [
        {
            "record_id": "AT",
            "path": "/demo/app.log",
            "created": "2026-10-01T00:00:00Z",
            "modified": "2026-10-10T00:00:00Z",
            "accessed": "2026-10-18T00:00:00Z",
            "baseline_mtime": "2026-10-10T00:00:00Z",
            "baseline_atime": "2026-10-11T00:00:00Z",
            "simulated": True,
        }
    ]
    findings = analyze_timestamps(records, rules)
    assert not any(f.rule_id == "TS-BASELINE-MTIME-CHANGE" for f in findings)
