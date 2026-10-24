from detector.history_analyzer import analyze_history
from detector.rules import load_rules


def test_explicit_history_clear():
    rules = load_rules()
    records = [
        {
            "entry_id": "H1",
            "sequence": 4,
            "timestamp": "2026-10-18T14:06:40Z",
            "command": "Clear-History",
            "event_type": "HISTORY_CLEARED",
            "host": "HOST-A",
            "related_path": "/demo/app.log",
            "simulated": True,
        }
    ]
    findings = analyze_history(records, rules)
    match = next(f for f in findings if f.rule_id == "HIST-EXPLICIT-CLEAR")
    assert match.severity == "HIGH"


def test_clear_command_pattern():
    rules = load_rules()
    records = [
        {
            "entry_id": "H2",
            "sequence": 5,
            "timestamp": "2026-10-18T14:06:40Z",
            "command": "history -c",
            "simulated": True,
        }
    ]
    findings = analyze_history(records, rules)
    assert any(f.rule_id == "HIST-CLEAR-COMMAND-PATTERN" for f in findings)


def test_sequence_gap_is_inconclusive():
    rules = load_rules()
    records = [
        {"entry_id": "A", "sequence": 1, "command": "whoami", "timestamp": "2026-10-18T13:00:00Z"},
        {"entry_id": "B", "sequence": 10, "command": "ls", "timestamp": "2026-10-18T13:01:00Z"},
    ]
    findings = analyze_history(records, rules)
    match = next(f for f in findings if f.rule_id == "HIST-SEQUENCE-GAP")
    assert match.certainty == "INCONCLUSIVE"


def test_snapshot_difference():
    rules = load_rules()
    current = [{"entry_id": "A", "sequence": 1, "command": "whoami"}]
    snapshot = [
        {"entry_id": "A", "sequence": 1, "command": "whoami"},
        {"entry_id": "B", "sequence": 2, "command": "id"},
    ]
    findings = analyze_history(current, rules, trusted_snapshot=snapshot)
    assert any(f.rule_id == "HIST-SNAPSHOT-DIFFERENCE" for f in findings)


def test_malformed_history_record():
    rules = load_rules()
    findings = analyze_history(["bad"], rules)
    assert any(f.rule_id == "HIST-MALFORMED-RECORD" for f in findings)
