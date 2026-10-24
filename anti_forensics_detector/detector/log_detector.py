"""Log tampering detection from structured event records."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any, Iterable

from detector.models import Certainty, Finding, Severity, utc_now_iso
from detector.timeutil import TimestampParseError, parse_iso8601, to_iso, try_parse_iso8601


def analyze_log_events(
    events: Iterable[dict[str, Any]],
    rules: dict[str, Any],
    *,
    source_name: str = "events",
    id_prefix: str = "LOG",
) -> list[Finding]:
    """Analyze structured log/event records. Does not execute commands or alter logs."""
    cfg = rules.get("log_detector", {})
    clear_types = set(cfg.get("explicit_clear_event_types", []))
    deleted_types = set(cfg.get("log_file_deleted_event_types", []))
    config_types = set(cfg.get("logging_config_event_types", []))
    repeat_threshold = int(cfg.get("repeat_threshold", 3))
    repeat_window = int(cfg.get("repeat_window_seconds", 600))

    findings: list[Finding] = []
    detection_time = utc_now_iso()
    valid_events: list[dict[str, Any]] = []
    sequence = 0

    for raw in events:
        sequence += 1
        event, issue = _normalize_event(raw, sequence)
        if issue:
            findings.append(
                _finding(
                    finding_id=f"{id_prefix}-{sequence:04d}-PARSE",
                    evidence_ref=str(raw.get("event_id", f"{source_name}#{sequence}")),
                    detection_time=detection_time,
                    observed={"raw_record": _safe_preview(raw), "parse_issue": issue},
                    rule_id="LOG-MALFORMED-RECORD",
                    severity=Severity.INFORMATIONAL.value,
                    explanation=(
                        f"This record could not be fully interpreted ({issue}). "
                        "A malformed record is not treated as proof of log tampering."
                    ),
                    recommended_action=(
                        "Review the original evidence source for encoding or export errors "
                        "before treating this as an anti-forensic indicator."
                    ),
                    certainty=Certainty.INCONCLUSIVE.value,
                    simulated=bool(raw.get("simulated", False)) if isinstance(raw, dict) else False,
                    source_dataset=source_name,
                )
            )
            if event is None:
                continue
        valid_events.append(event)
        event_type = event["event_type"]
        simulated = event["simulated"]
        evidence_ref = event["event_id"]
        related_path = event.get("related_path")
        host = event.get("host")
        ts = event.get("timestamp_iso")

        if event_type in clear_types:
            findings.append(
                _finding(
                    finding_id=f"{id_prefix}-{sequence:04d}-CLEAR",
                    evidence_ref=evidence_ref,
                    detection_time=detection_time,
                    observed=_event_evidence(event),
                    rule_id="LOG-EXPLICIT-CLEAR",
                    severity=Severity.HIGH.value,
                    explanation=(
                        f"Structured event type '{event_type}' matches a configured log-clearing "
                        "indicator. This is an explicit recorded event, not an inference from a "
                        "missing line. It does not by itself prove malicious intent "
                        "(administrators may clear logs during maintenance)."
                    ),
                    recommended_action=(
                        "Preserve remaining logs, identify the account and process that issued "
                        "the clear action, and compare surrounding events for related file or "
                        "history changes."
                    ),
                    certainty=Certainty.CONFIRMED_OBSERVATION.value,
                    simulated=simulated,
                    related_path=related_path,
                    related_timestamp=ts,
                    host=host,
                    source_dataset=source_name,
                )
            )
        if event_type in deleted_types:
            findings.append(
                _finding(
                    finding_id=f"{id_prefix}-{sequence:04d}-DEL",
                    evidence_ref=evidence_ref,
                    detection_time=detection_time,
                    observed=_event_evidence(event),
                    rule_id="LOG-MONITORED-FILE-DELETED",
                    severity=Severity.HIGH.value,
                    explanation=(
                        f"Structured event type '{event_type}' reports deletion of a monitored "
                        "log file or log path. This is a recorded deletion event, not merely "
                        "an absent expected entry."
                    ),
                    recommended_action=(
                        "Locate backups or remote log forwards for the deleted path and document "
                        "the actor, time, and related process if available."
                    ),
                    certainty=Certainty.CONFIRMED_OBSERVATION.value,
                    simulated=simulated,
                    related_path=related_path,
                    related_timestamp=ts,
                    host=host,
                    source_dataset=source_name,
                )
            )
        if event_type in config_types:
            findings.append(
                _finding(
                    finding_id=f"{id_prefix}-{sequence:04d}-CFG",
                    evidence_ref=evidence_ref,
                    detection_time=detection_time,
                    observed=_event_evidence(event),
                    rule_id="LOG-CONFIG-CHANGED",
                    severity=Severity.MEDIUM.value,
                    explanation=(
                        f"Structured event type '{event_type}' indicates a change that can reduce "
                        "logging visibility (service stop, audit policy disable, or forwarding "
                        "disable). This is suspicious in an investigation context but may be "
                        "operationally legitimate."
                    ),
                    recommended_action=(
                        "Confirm whether the change was authorized change-control activity and "
                        "whether equivalent logs were collected elsewhere."
                    ),
                    certainty=Certainty.SUSPICIOUS_INDICATOR.value,
                    simulated=simulated,
                    related_path=related_path,
                    related_timestamp=ts,
                    host=host,
                    source_dataset=source_name,
                )
            )

        expected = event.get("expected_event_id")
        observed_present = event.get("expected_event_present")
        if expected and observed_present is False and event.get("baseline_coverage") == "sufficient":
            findings.append(
                _finding(
                    finding_id=f"{id_prefix}-{sequence:04d}-MISS",
                    evidence_ref=evidence_ref,
                    detection_time=detection_time,
                    observed=_event_evidence(event),
                    rule_id="LOG-MISSING-EXPECTED-EVENT",
                    severity=Severity.LOW.value,
                    explanation=(
                        f"Baseline coverage is marked sufficient and expected event "
                        f"'{expected}' is recorded as not present. Absence can result from "
                        "collection gaps, rotation, filtering, or time-window mismatch. "
                        "This is not treated as confirmed malicious deletion."
                    ),
                    recommended_action=(
                        "Verify collector coverage for the time range and look for independent "
                        "copies of the expected event before concluding log destruction."
                    ),
                    certainty=Certainty.INCONCLUSIVE.value,
                    simulated=simulated,
                    related_path=related_path,
                    related_timestamp=ts,
                    host=host,
                    source_dataset=source_name,
                )
            )

    findings.extend(
        _repeated_suspicious(
            valid_events,
            clear_types | deleted_types | config_types,
            repeat_threshold,
            repeat_window,
            detection_time,
            source_name,
            id_prefix,
        )
    )
    return findings


def _repeated_suspicious(
    events: list[dict[str, Any]],
    suspicious_types: set[str],
    threshold: int,
    window_seconds: int,
    detection_time: str,
    source_name: str,
    id_prefix: str,
) -> list[Finding]:
    by_host: dict[str, list[tuple[object, dict[str, Any]]]] = defaultdict(list)
    for event in events:
        if event["event_type"] not in suspicious_types:
            continue
        ts = try_parse_iso8601(event.get("timestamp"))
        if ts is None:
            continue
        by_host[str(event.get("host") or "unknown")].append((ts, event))

    findings: list[Finding] = []
    group_n = 0
    for host, items in by_host.items():
        items.sort(key=lambda item: item[0])
        used: set[str] = set()
        for i, (start_ts, _) in enumerate(items):
            window_end = start_ts + timedelta(seconds=window_seconds)
            cluster = []
            for later_ts, later_event in items[i:]:
                if later_ts > window_end:
                    break
                if later_event["event_id"] in used:
                    continue
                cluster.append(later_event)
            if len(cluster) < threshold:
                continue
            for event in cluster:
                used.add(event["event_id"])
            group_n += 1
            findings.append(
                _finding(
                    finding_id=f"{id_prefix}-REPEAT-{group_n:04d}",
                    evidence_ref=",".join(e["event_id"] for e in cluster),
                    detection_time=detection_time,
                    observed={
                        "host": host,
                        "count": len(cluster),
                        "window_seconds": window_seconds,
                        "event_ids": [e["event_id"] for e in cluster],
                        "event_types": [e["event_type"] for e in cluster],
                    },
                    rule_id="LOG-REPEATED-SUSPICIOUS-EVENTS",
                    severity=Severity.HIGH.value,
                    explanation=(
                        f"{len(cluster)} configured logging-related events were observed on host "
                        f"'{host}' within {window_seconds} seconds. Repeated logging interference "
                        "increases investigative priority but still does not prove intent."
                    ),
                    recommended_action=(
                        "Timeline the clustered events, identify the responsible account, and "
                        "correlate with file integrity and history evidence in the same window."
                    ),
                    certainty=Certainty.SUSPICIOUS_INDICATOR.value,
                    simulated=any(e.get("simulated") for e in cluster),
                    host=host,
                    related_timestamp=to_iso(start_ts),
                    source_dataset=source_name,
                )
            )
    return findings


def _normalize_event(raw: Any, sequence: int) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(raw, dict):
        return None, "record is not a JSON object"
    event_id = str(raw.get("event_id") or f"generated-{sequence}")
    event_type = str(raw.get("event_type") or "").strip().upper()
    if not event_type:
        return None, "event_type is missing"
    timestamp_iso = None
    parse_issue = None
    if "timestamp" in raw and raw.get("timestamp") not in (None, ""):
        try:
            timestamp_iso = to_iso(parse_iso8601(raw.get("timestamp")))
        except TimestampParseError as exc:
            parse_issue = str(exc)
    event = {
        "event_id": event_id,
        "event_type": event_type,
        "timestamp": raw.get("timestamp"),
        "timestamp_iso": timestamp_iso,
        "description": raw.get("description"),
        "severity": raw.get("severity"),
        "host": raw.get("host"),
        "related_path": raw.get("related_path") or raw.get("log_path"),
        "simulated": bool(raw.get("simulated", False)),
        "expected_event_id": raw.get("expected_event_id"),
        "expected_event_present": raw.get("expected_event_present"),
        "baseline_coverage": raw.get("baseline_coverage"),
        "source": raw.get("source"),
    }
    return event, parse_issue


def _event_evidence(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": event.get("event_id"),
        "event_type": event.get("event_type"),
        "timestamp": event.get("timestamp_iso") or event.get("timestamp"),
        "description": event.get("description"),
        "host": event.get("host"),
        "related_path": event.get("related_path"),
        "simulated": event.get("simulated"),
        "source": event.get("source"),
    }


def _safe_preview(raw: Any) -> Any:
    if isinstance(raw, dict):
        return {str(k): raw[k] for k in list(raw)[:12]}
    return str(raw)[:500]


def _finding(**kwargs: Any) -> Finding:
    if "observed" in kwargs:
        kwargs["observed_evidence"] = kwargs.pop("observed")
    return Finding(module="log_detector", **kwargs)
