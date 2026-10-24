"""SHA-256 file integrity monitoring against a trusted local baseline."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from detector.models import Certainty, Finding, Severity, utc_now_iso

CHUNK_SIZE = 1024 * 1024
LIMITATIONS = [
    "SHA-256 identifies whether file bytes differ from the recorded baseline. It does not identify who changed a file or when the change occurred.",
    "An attacker who can modify both the monitored file and the baseline manifest can evade this check.",
    "Hash matches do not prove a file is benign; they only show it matches the stored baseline.",
]


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def create_baseline(
    file_paths: Iterable[str | Path],
    baseline_path: str | Path,
    *,
    workspace_root: str | Path | None = None,
) -> dict[str, Any]:
    """Create a trusted baseline for selected files. Writes only the baseline file."""
    root = Path(workspace_root).resolve() if workspace_root else None
    entries: list[dict[str, Any]] = []
    created = utc_now_iso()
    for item in file_paths:
        path = Path(item).resolve()
        _assert_in_workspace(path, root)
        if not path.is_file():
            raise FileNotFoundError(f"Cannot baseline missing file: {path}")
        entries.append(
            {
                "path": str(path),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    manifest = {
        "created_at": created,
        "algorithm": "SHA-256",
        "trusted_reference": True,
        "limitation": LIMITATIONS[1],
        "files": entries,
    }
    baseline = Path(baseline_path)
    baseline.parent.mkdir(parents=True, exist_ok=True)
    baseline.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def verify_baseline(
    baseline_path: str | Path,
    *,
    extra_paths: Iterable[str | Path] | None = None,
    workspace_root: str | Path | None = None,
    id_prefix: str = "INT",
) -> list[Finding]:
    """Compare current hashes with a trusted baseline. Read-only on monitored files."""
    detection_time = utc_now_iso()
    root = Path(workspace_root).resolve() if workspace_root else None
    findings: list[Finding] = []
    baseline_file = Path(baseline_path)
    if not baseline_file.is_file():
        return [
            Finding(
                finding_id=f"{id_prefix}-0001-NOBASE",
                module="integrity_checker",
                evidence_ref=str(baseline_file),
                detection_time=detection_time,
                observed_evidence={"baseline_path": str(baseline_file)},
                rule_id="INT-BASELINE-MISSING",
                severity=Severity.INFORMATIONAL.value,
                explanation="No baseline file was found, so integrity comparison could not be performed.",
                recommended_action="Create a trusted baseline for selected workspace files, then verify.",
                certainty=Certainty.INCONCLUSIVE.value,
            )
        ]

    try:
        manifest = json.loads(baseline_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [
            Finding(
                finding_id=f"{id_prefix}-0001-BADBASE",
                module="integrity_checker",
                evidence_ref=str(baseline_file),
                detection_time=detection_time,
                observed_evidence={"error": str(exc)},
                rule_id="INT-BASELINE-MALFORMED",
                severity=Severity.LOW.value,
                explanation="The baseline manifest could not be parsed as JSON.",
                recommended_action="Restore the baseline from a trusted copy if available.",
                certainty=Certainty.INCONCLUSIVE.value,
            )
        ]

    expected_files = manifest.get("files") or []
    expected_by_path: dict[str, dict[str, Any]] = {}
    for entry in expected_files:
        path = str(Path(entry["path"]).resolve())
        expected_by_path[path] = entry

    observed_paths: set[str] = set(expected_by_path)
    if extra_paths:
        for item in extra_paths:
            path = Path(item).resolve()
            _assert_in_workspace(path, root)
            observed_paths.add(str(path))

    seq = 0
    for path_str, entry in expected_by_path.items():
        seq += 1
        path = Path(path_str)
        related_ts = detection_time
        if not path.is_file():
            findings.append(
                Finding(
                    finding_id=f"{id_prefix}-{seq:04d}-MISS",
                    module="integrity_checker",
                    evidence_ref=path_str,
                    detection_time=detection_time,
                    observed_evidence={
                        "path": path_str,
                        "expected_sha256": entry.get("sha256"),
                        "observed_sha256": None,
                        "scan_time": detection_time,
                    },
                    rule_id="INT-FILE-MISSING",
                    severity=Severity.HIGH.value,
                    explanation=(
                        "A file recorded in the trusted baseline is no longer present. "
                        "This is a confirmed observation relative to the baseline, not proof of who removed it."
                    ),
                    recommended_action="Search recycle/volume shadow/backups and timeline deletion around the last known good scan.",
                    certainty=Certainty.CONFIRMED_OBSERVATION.value,
                    related_path=path_str,
                    related_timestamp=related_ts,
                )
            )
            continue
        current = sha256_file(path)
        expected = entry.get("sha256")
        if current != expected:
            findings.append(
                Finding(
                    finding_id=f"{id_prefix}-{seq:04d}-MOD",
                    module="integrity_checker",
                    evidence_ref=path_str,
                    detection_time=detection_time,
                    observed_evidence={
                        "path": path_str,
                        "expected_sha256": expected,
                        "observed_sha256": current,
                        "size_bytes": path.stat().st_size,
                        "scan_time": detection_time,
                    },
                    rule_id="INT-HASH-MISMATCH",
                    severity=Severity.HIGH.value,
                    explanation=(
                        "The current SHA-256 digest differs from the trusted baseline. "
                        "This confirms the file bytes changed since the baseline was recorded. "
                        "It does not identify the actor or the modification time."
                    ),
                    recommended_action="Preserve the current file, compare with known-good copies, and correlate with nearby log and timestamp findings.",
                    certainty=Certainty.CONFIRMED_OBSERVATION.value,
                    related_path=path_str,
                    related_timestamp=related_ts,
                )
            )

    extra = observed_paths - set(expected_by_path)
    for path_str in sorted(extra):
        seq += 1
        path = Path(path_str)
        if not path.is_file():
            continue
        findings.append(
            Finding(
                finding_id=f"{id_prefix}-{seq:04d}-NEW",
                module="integrity_checker",
                evidence_ref=path_str,
                detection_time=detection_time,
                observed_evidence={
                    "path": path_str,
                    "observed_sha256": sha256_file(path),
                    "scan_time": detection_time,
                },
                rule_id="INT-UNEXPECTED-FILE",
                severity=Severity.MEDIUM.value,
                explanation=(
                    "A file was included in the verification set but is not present in the trusted baseline. "
                    "This may be a newly added monitored file rather than tampering."
                ),
                recommended_action="Confirm whether the file should be added to a new trusted baseline.",
                certainty=Certainty.SUSPICIOUS_INDICATOR.value,
                related_path=path_str,
                related_timestamp=detection_time,
            )
        )
    return findings


def _assert_in_workspace(path: Path, root: Path | None) -> None:
    if root is None:
        return
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise PermissionError(
            f"Refusing to hash files outside the dedicated workspace: {path}"
        ) from exc
