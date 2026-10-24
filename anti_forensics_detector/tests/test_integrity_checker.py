import hashlib
from pathlib import Path

from detector.integrity_checker import create_baseline, sha256_file, verify_baseline


def test_sha256_calculation(tmp_path: Path):
    target = tmp_path / "a.txt"
    payload = b"integrity-demo"
    target.write_bytes(payload)
    assert sha256_file(target) == hashlib.sha256(payload).hexdigest()


def test_unmodified_file_has_no_mismatch(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    sample = workspace / "ok.txt"
    sample.write_text("same", encoding="utf-8")
    baseline = tmp_path / "base.json"
    create_baseline([sample], baseline, workspace_root=workspace)
    findings = verify_baseline(baseline, workspace_root=workspace)
    assert findings == []


def test_modified_file_detected(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    sample = workspace / "changed.txt"
    sample.write_text("v1", encoding="utf-8")
    baseline = tmp_path / "base.json"
    create_baseline([sample], baseline, workspace_root=workspace)
    sample.write_text("v2", encoding="utf-8")
    findings = verify_baseline(baseline, workspace_root=workspace)
    match = next(f for f in findings if f.rule_id == "INT-HASH-MISMATCH")
    assert match.observed_evidence["expected_sha256"] != match.observed_evidence["observed_sha256"]
    assert match.certainty == "CONFIRMED_OBSERVATION"


def test_missing_monitored_file_detected(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    sample = workspace / "gone.txt"
    sample.write_text("data", encoding="utf-8")
    baseline = tmp_path / "base.json"
    create_baseline([sample], baseline, workspace_root=workspace)
    sample.unlink()
    findings = verify_baseline(baseline, workspace_root=workspace)
    assert any(f.rule_id == "INT-FILE-MISSING" for f in findings)


def test_new_file_detected(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    sample = workspace / "old.txt"
    sample.write_text("data", encoding="utf-8")
    newbie = workspace / "new.txt"
    newbie.write_text("extra", encoding="utf-8")
    baseline = tmp_path / "base.json"
    create_baseline([sample], baseline, workspace_root=workspace)
    findings = verify_baseline(baseline, extra_paths=[sample, newbie], workspace_root=workspace)
    assert any(f.rule_id == "INT-UNEXPECTED-FILE" for f in findings)
