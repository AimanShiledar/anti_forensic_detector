from detector.log_detector import analyze_log_events
from detector.rules import load_rules


def test_explicit_log_clear_detected():
    rules = load_rules()
    events = [
        {
            "event_id": "E1",
            "timestamp": "2026-10-18T14:05:00Z",
            "event_type": "EVENTLOG_CLEARED",
            "description": "log cleared",
            "host": "HOST-A",
            "related_path": "/var/log/auth.log",
            "simulated": True,
        }
    ]
    findings = analyze_log_events(events, rules)
    assert any(f.rule_id == "LOG-EXPLICIT-CLEAR" for f in findings)
    match = next(f for f in findings if f.rule_id == "LOG-EXPLICIT-CLEAR")
    assert match.certainty == "CONFIRMED_OBSERVATION"
    assert "EVENTLOG_CLEARED" in match.explanation


def test_normal_events_do_not_trigger_clear_rule():
    rules = load_rules()
    events = [
        {
            "event_id": "N1",
            "timestamp": "2026-10-18T13:00:00Z",
            "event_type": "USER_LOGIN",
            "description": "user logged in",
            "host": "HOST-A",
            "simulated": True,
        }
    ]
    findings = analyze_log_events(events, rules)
    assert not any(f.rule_id == "LOG-EXPLICIT-CLEAR" for f in findings)


def test_invalid_event_records_are_reported_not_crashed():
    rules = load_rules()
    events = ["not-an-object", {"event_id": "x"}, {"event_id": "y", "event_type": "USER_LOGIN", "timestamp": "bad"}]
    findings = analyze_log_events(events, rules)
    assert any(f.rule_id == "LOG-MALFORMED-RECORD" for f in findings)


def test_missing_expected_event_is_inconclusive():
    rules = load_rules()
    events = [
        {
            "event_id": "M1",
            "timestamp": "2026-10-18T14:20:00Z",
            "event_type": "EXPECTED_EVENT_CHECK",
            "expected_event_id": "HB",
            "expected_event_present": False,
            "baseline_coverage": "sufficient",
            "simulated": True,
        }
    ]
    findings = analyze_log_events(events, rules)
    match = next(f for f in findings if f.rule_id == "LOG-MISSING-EXPECTED-EVENT")
    assert match.certainty == "INCONCLUSIVE"
    assert match.severity == "LOW"


def test_word_delete_alone_is_not_enough():
    rules = load_rules()
    events = [
        {
            "event_id": "D1",
            "timestamp": "2026-10-18T14:05:00Z",
            "event_type": "FILE_READ",
            "description": "user mentioned delete and clear in a comment",
            "simulated": True,
        }
    ]
    findings = analyze_log_events(events, rules)
    assert not any(f.rule_id in {"LOG-EXPLICIT-CLEAR", "LOG-MONITORED-FILE-DELETED"} for f in findings)


def test_repeated_suspicious_events():
    rules = load_rules()
    events = [
        {
            "event_id": f"R{i}",
            "timestamp": f"2026-10-18T14:0{i}:00Z",
            "event_type": "LOGGING_SERVICE_STOPPED",
            "host": "HOST-A",
            "simulated": True,
        }
        for i in range(3)
    ]
    findings = analyze_log_events(events, rules)
    assert any(f.rule_id == "LOG-REPEATED-SUSPICIOUS-EVENTS" for f in findings)
