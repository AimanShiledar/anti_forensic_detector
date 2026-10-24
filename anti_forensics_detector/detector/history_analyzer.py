"""Command-history tampering indicators from imported structured records."""

from __future__ import annotations

from typing import Any, Iterable

from detector.models import Certainty, Finding, Severity, utc_now_iso
from detector.timeutil import to_iso, try_parse_iso8601


def analyze_history(
    records: Iterable[dict[str, Any]],
    rules: dict[str, Any],
    *,
    trusted_snapshot: Iterable[dict[str, Any]] | None = None,
    source_name: str = "history",
    id_prefix: str = "HIST",
) -> list[Finding]:
    cfg = rules.get("history_detector", {})
    clear_types = {str(x).upper() for x in cfg.get("clear_event_types", [])}
    clear_patterns = [str(x).lower() for x in cfg.get("clear_command_patterns", [])]
    max_gap = int(cfg.get("max_expected_sequence_gap", 1))

    findings: list[Finding] = []
    detection_time = utc_now_iso()
    entries: list[dict[str, Any]] = []
    seq = 0

    for raw in records:
        seq += 1
        if not isinstance(raw, dict):
            findings.append(
                _hist_finding(
                    f"{id_prefix}-{seq:04d}-PARSE",
                    evidence_ref=f"{source_name}#{seq}",
                    detection_time=detection_time,
                    observed={"raw": str(raw)[:300]},
                    rule_id="HIST-MALFORMED-RECORD",
                    severity=Severity.INFORMATIONAL.value,
                    explanation="History record is not a structured object and was skipped for indicator rules.",
                    recommended_action="Re-export history as JSON objects with command, sequence, and timestamp fields.",
                    certainty=Certainty.INCONCLUSIVE.value,
                    simulated=False,
                    source_dataset=source_name,
                )
            )
            continue

        event_type = str(raw.get("event_type") or "").strip().upper()
        command = str(raw.get("command") or "")
        evidence_ref = str(raw.get("entry_id") or raw.get("event_id") or f"{source_name}#{seq}")
        simulated = bool(raw.get("simulated", False))
        host = raw.get("host")
        related_path = raw.get("history_path") or raw.get("related_path")
        ts = try_parse_iso8601(raw.get("timestamp"))
        related_ts = to_iso(ts) if ts else None
        entries.append({**raw, "_seq_index": seq, "_event_type": event_type, "_command": command})

        if event_type in clear_types:
            findings.append(
                _hist_finding(
                    f"{id_prefix}-{seq:04d}-CLEAR",
                    evidence_ref=evidence_ref,
                    detection_time=detection_time,
                    observed={
                        "event_type": event_type,
                        "command": command,
                        "timestamp": related_ts,
                        "simulated": simulated,
                    },
                    rule_id="HIST-EXPLICIT-CLEAR",
                    severity=Severity.HIGH.value,
                    explanation=(
                        f"Structured history event type '{event_type}' is configured as explicit "
                        "history-clearing activity. History may also be disabled, rotated, or incomplete "
                        "for legitimate reasons; this observation still warrants investigation."
                    ),
                    recommended_action="Preserve remaining history files, shell session logs, and auditd/PowerShell transcription if available.",
                    certainty=Certainty.CONFIRMED_OBSERVATION.value,
                    simulated=simulated,
                    related_path=related_path,
                    related_timestamp=related_ts,
                    host=host,
                    source_dataset=source_name,
                )
            )
        else:
            lowered = command.lower()
            matched = next((p for p in clear_patterns if p and p in lowered), None)
            if matched:
                findings.append(
                    _hist_finding(
                        f"{id_prefix}-{seq:04d}-CMD",
                        evidence_ref=evidence_ref,
                        detection_time=detection_time,
                        observed={
                            "command": command,
                            "matched_pattern": matched,
                            "timestamp": related_ts,
                            "simulated": simulated,
                        },
                        rule_id="HIST-CLEAR-COMMAND-PATTERN",
                        severity=Severity.MEDIUM.value,
                        explanation=(
                            f"The imported command text contains configured history-clearing pattern "
                            f"'{matched}'. Command history can record attempted cleanup without proving "
                            "that evidence was actually destroyed."
                        ),
                        recommended_action="Determine whether the command succeeded and whether other telemetry still retains the session.",
                        certainty=Certainty.SUSPICIOUS_INDICATOR.value,
                        simulated=simulated,
                        related_path=related_path,
                        related_timestamp=related_ts,
                        host=host,
                        source_dataset=source_name,
                    )
                )

    numbered = [e for e in entries if e.get("sequence") is not None]
    numbered.sort(key=lambda e: _safe_int(e.get("sequence"), 0))
    for prev, current in zip(numbered, numbered[1:]):
        prev_n = _safe_int(prev.get("sequence"), None)
        cur_n = _safe_int(current.get("sequence"), None)
        if prev_n is None or cur_n is None:
            continue
        gap = cur_n - prev_n
        if gap > max_gap + 1:
            findings.append(
                _hist_finding(
                    f"{id_prefix}-GAP-{prev_n}-{cur_n}",
                    evidence_ref=f"{prev.get('entry_id')},{current.get('entry_id')}",
                    detection_time=detection_time,
                    observed={
                        "previous_sequence": prev_n,
                        "next_sequence": cur_n,
                        "gap": gap - 1,
                        "max_expected_sequence_gap": max_gap,
                    },
                    rule_id="HIST-SEQUENCE-GAP",
                    severity=Severity.LOW.value,
                    explanation=(
                        f"A sequence gap of {gap - 1} missing number(s) was observed between "
                        f"{prev_n} and {cur_n}. Gaps can result from wrapping, disabled history, "
                        "multiple shells, or incomplete collection. This is not automatically malicious."
                    ),
                    recommended_action="Determine whether a contiguous history source exists (process accounting, SIEM) before inferring wiping.",
                    certainty=Certainty.INCONCLUSIVE.value,
                    simulated=bool(prev.get("simulated") or current.get("simulated")),
                    related_path=current.get("history_path") or current.get("related_path"),
                    related_timestamp=(
                        to_iso(try_parse_iso8601(current.get("timestamp")))
                        if try_parse_iso8601(current.get("timestamp"))
                        else None
                    ),
                    host=current.get("host"),
                    source_dataset=source_name,
                )
            )

    if trusted_snapshot is not None:
        current_cmds = [_norm_cmd(e) for e in entries]
        snap_cmds = [_norm_cmd(e) for e in trusted_snapshot if isinstance(e, dict)]
        if current_cmds != snap_cmds:
            missing = [c for c in snap_cmds if c not in current_cmds]
            extra = [c for c in current_cmds if c not in snap_cmds]
            findings.append(
                _hist_finding(
                    f"{id_prefix}-SNAP-DIFF",
                    evidence_ref=source_name,
                    detection_time=detection_time,
                    observed={
                        "snapshot_length": len(snap_cmds),
                        "current_length": len(current_cmds),
                        "missing_from_current_sample": missing[:20],
                        "extra_in_current_sample": extra[:20],
                    },
                    rule_id="HIST-SNAPSHOT-DIFFERENCE",
                    severity=Severity.MEDIUM.value,
                    explanation=(
                        "The imported history differs from the supplied trusted snapshot. "
                        "Differences can be caused by new activity, rotation, or removal. "
                        "An incomplete history is not automatically labeled malicious."
                    ),
                    recommended_action="Identify which entries disappeared versus which were newly appended.",
                    certainty=Certainty.CONFIRMED_OBSERVATION.value,
                    simulated=any(bool(e.get("simulated")) for e in entries if isinstance(e, dict)),
                    source_dataset=source_name,
                )
            )

    return findings


def _norm_cmd(entry: dict[str, Any]) -> str:
    seq = entry.get("sequence")
    cmd = str(entry.get("command") or "")
    return f"{seq}|{cmd}"


def _safe_int(value: Any, default: int | None) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _hist_finding(
    finding_id: str,
    *,
    evidence_ref: str,
    detection_time: str,
    observed: dict[str, Any],
    rule_id: str,
    severity: str,
    explanation: str,
    recommended_action: str,
    certainty: str,
    simulated: bool,
    related_path: str | None = None,
    related_timestamp: str | None = None,
    host: str | None = None,
    source_dataset: str | None = None,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        module="history_analyzer",
        evidence_ref=evidence_ref,
        detection_time=detection_time,
        observed_evidence=observed,
        rule_id=rule_id,
        severity=severity,
        explanation=explanation,
        recommended_action=recommended_action,
        certainty=certainty,
        simulated=simulated,
        related_path=related_path,
        related_timestamp=related_timestamp,
        host=host,
        source_dataset=source_dataset,
    )
