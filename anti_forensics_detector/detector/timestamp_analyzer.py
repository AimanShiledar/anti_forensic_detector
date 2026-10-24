"""Timestamp consistency analysis. Does not claim timestomping as proven."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from detector.models import Certainty, Finding, Severity, utc_now_iso
from detector.timeutil import TimestampParseError, parse_iso8601, to_iso, try_parse_iso8601


def analyze_timestamps(
    records: Iterable[dict[str, Any]],
    rules: dict[str, Any],
    *,
    analysis_time: datetime | None = None,
    source_name: str = "metadata",
    id_prefix: str = "TS",
) -> list[Finding]:
    cfg = rules.get("timestamp_detector", {})
    clock_skew = int(rules.get("clock_skew_seconds", 300))
    flag_future = bool(cfg.get("flag_future_timestamps", True))
    flag_created_after_modified = bool(cfg.get("flag_created_after_modified", True))
    flag_baseline_mtime = bool(cfg.get("flag_baseline_mtime_change", True))
    ignore_atime_only = bool(cfg.get("ignore_atime_only_changes", True))
    now = analysis_time or datetime.now(timezone.utc)

    findings: list[Finding] = []
    detection_time = utc_now_iso()
    seq = 0

    for raw in records:
        seq += 1
        if not isinstance(raw, dict):
            findings.append(
                _ts_finding(
                    f"{id_prefix}-{seq:04d}-PARSE",
                    evidence_ref=f"{source_name}#{seq}",
                    detection_time=detection_time,
                    observed={"raw": str(raw)[:300]},
                    rule_id="TS-MALFORMED-RECORD",
                    severity=Severity.INFORMATIONAL.value,
                    explanation="Metadata record is not a JSON object, so timestamps could not be evaluated.",
                    recommended_action="Inspect the export format and re-import valid structured metadata.",
                    certainty=Certainty.INCONCLUSIVE.value,
                    simulated=False,
                    source_dataset=source_name,
                )
            )
            continue

        evidence_ref = str(raw.get("record_id") or raw.get("path") or f"{source_name}#{seq}")
        simulated = bool(raw.get("simulated", False))
        path = raw.get("path")
        host = raw.get("host")

        created = _optional_dt(raw.get("created"), findings, seq, evidence_ref, detection_time, simulated, source_name, "created")
        modified = _optional_dt(raw.get("modified"), findings, seq, evidence_ref, detection_time, simulated, source_name, "modified")
        accessed = _optional_dt(raw.get("accessed"), findings, seq, evidence_ref, detection_time, simulated, source_name, "accessed")
        event_time = _optional_dt(raw.get("event_time"), findings, seq, evidence_ref, detection_time, simulated, source_name, "event_time")
        independent_time = _optional_dt(
            raw.get("independent_event_time"),
            findings,
            seq,
            evidence_ref,
            detection_time,
            simulated,
            source_name,
            "independent_event_time",
        )

        related_ts = to_iso(modified or created or event_time or now)

        if created is None and modified is None and accessed is None and event_time is None:
            if raw.get("created") in (None, "") and raw.get("modified") in (None, ""):
                findings.append(
                    _ts_finding(
                        f"{id_prefix}-{seq:04d}-MISSING",
                        evidence_ref=evidence_ref,
                        detection_time=detection_time,
                        observed={"path": path, "note": "no comparable timestamps present"},
                        rule_id="TS-METADATA-MISSING",
                        severity=Severity.INFORMATIONAL.value,
                        explanation=(
                            "No comparable timestamps were present. Missing metadata is not treated "
                            "as an anomalous timestamp relationship."
                        ),
                        recommended_action="Collect file metadata from an additional source if available.",
                        certainty=Certainty.INCONCLUSIVE.value,
                        simulated=simulated,
                        related_path=path,
                        host=host,
                        source_dataset=source_name,
                    )
                )
                continue

        if flag_created_after_modified and created and modified and created > modified + timedelta(seconds=clock_skew):
            findings.append(
                _ts_finding(
                    f"{id_prefix}-{seq:04d}-ORDER",
                    evidence_ref=evidence_ref,
                    detection_time=detection_time,
                    observed={
                        "path": path,
                        "created": to_iso(created),
                        "modified": to_iso(modified),
                        "clock_skew_seconds": clock_skew,
                    },
                    rule_id="TS-CREATED-AFTER-MODIFIED",
                    severity=Severity.MEDIUM.value,
                    explanation=(
                        "The recorded created timestamp is later than the modified timestamp beyond "
                        "the configured clock-skew allowance. This is an inconsistent relationship "
                        "and may indicate metadata manipulation, clock issues, or copy artifacts. "
                        "It does not prove timestomping."
                    ),
                    recommended_action="Compare $SI/$FN or equivalent timestamps from an independent volume parser and check the system clock history.",
                    certainty=Certainty.SUSPICIOUS_INDICATOR.value,
                    simulated=simulated,
                    related_path=path,
                    related_timestamp=related_ts,
                    host=host,
                    source_dataset=source_name,
                )
            )

        if flag_future:
            for label, value in (("created", created), ("modified", modified), ("accessed", accessed), ("event_time", event_time)):
                if value and value > now + timedelta(seconds=clock_skew):
                    findings.append(
                        _ts_finding(
                            f"{id_prefix}-{seq:04d}-FUTURE-{label.upper()}",
                            evidence_ref=evidence_ref,
                            detection_time=detection_time,
                            observed={
                                "path": path,
                                "field": label,
                                "timestamp": to_iso(value),
                                "analysis_time": to_iso(now),
                                "clock_skew_seconds": clock_skew,
                            },
                            rule_id="TS-FUTURE-TIMESTAMP",
                            severity=Severity.MEDIUM.value,
                            explanation=(
                                f"The {label} timestamp is later than the analysis time after allowing "
                                f"{clock_skew} seconds of clock skew. This can be caused by clock drift, "
                                "timezone conversion errors, or metadata alteration."
                            ),
                            recommended_action="Verify host time synchronization and whether the timestamp was converted incorrectly.",
                            certainty=Certainty.SUSPICIOUS_INDICATOR.value,
                            simulated=simulated,
                            related_path=path,
                            related_timestamp=to_iso(value),
                            host=host,
                            source_dataset=source_name,
                        )
                    )

        baseline_mtime = try_parse_iso8601(raw.get("baseline_mtime"))
        if flag_baseline_mtime and baseline_mtime and modified and modified != baseline_mtime:
            atime_only = False
            if ignore_atime_only and accessed and raw.get("baseline_atime"):
                baseline_atime = try_parse_iso8601(raw.get("baseline_atime"))
                if baseline_atime and accessed != baseline_atime and modified == baseline_mtime:
                    atime_only = True
            if not atime_only:
                findings.append(
                    _ts_finding(
                        f"{id_prefix}-{seq:04d}-BASE",
                        evidence_ref=evidence_ref,
                        detection_time=detection_time,
                        observed={
                            "path": path,
                            "baseline_mtime": to_iso(baseline_mtime),
                            "observed_mtime": to_iso(modified),
                        },
                        rule_id="TS-BASELINE-MTIME-CHANGE",
                        severity=Severity.LOW.value,
                        explanation=(
                            "The modified timestamp differs from a previously recorded metadata baseline. "
                            "Ordinary writes also change mtime; this is a change observation, not proof of anti-forensics."
                        ),
                        recommended_action="Correlate with integrity hashes. If the hash is unchanged, mtime-only change is more interesting.",
                        certainty=Certainty.CONFIRMED_OBSERVATION.value,
                        simulated=simulated,
                        related_path=path,
                        related_timestamp=related_ts,
                        host=host,
                        source_dataset=source_name,
                    )
                )

        if event_time and independent_time:
            delta = abs((event_time - independent_time).total_seconds())
            if delta > clock_skew:
                findings.append(
                    _ts_finding(
                        f"{id_prefix}-{seq:04d}-CROSS",
                        evidence_ref=evidence_ref,
                        detection_time=detection_time,
                        observed={
                            "path": path,
                            "event_time": to_iso(event_time),
                            "independent_event_time": to_iso(independent_time),
                            "delta_seconds": delta,
                            "clock_skew_seconds": clock_skew,
                        },
                        rule_id="TS-INDEPENDENT-TIME-DISCREPANCY",
                        severity=Severity.MEDIUM.value,
                        explanation=(
                            "Two independently recorded timestamps that are supposed to describe the same "
                            "event differ beyond the configured clock-skew window. This is a discrepancy "
                            "indicator, not proof that either value was forged."
                        ),
                        recommended_action="Identify which clock produced each timestamp and whether log delay or queueing explains the gap.",
                        certainty=Certainty.SUSPICIOUS_INDICATOR.value,
                        simulated=simulated,
                        related_path=path,
                        related_timestamp=to_iso(event_time),
                        host=host,
                        source_dataset=source_name,
                    )
                )

        if ignore_atime_only:
            # No finding is raised for atime-only notes; documented by design.
            pass

    return findings


def _optional_dt(
    value: Any,
    findings: list[Finding],
    seq: int,
    evidence_ref: str,
    detection_time: str,
    simulated: bool,
    source_name: str,
    field_name: str,
) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        return parse_iso8601(value)
    except TimestampParseError as exc:
        findings.append(
            _ts_finding(
                f"TS-{seq:04d}-BAD-{field_name.upper()}",
                evidence_ref=evidence_ref,
                detection_time=detection_time,
                observed={"field": field_name, "value": value, "error": str(exc)},
                rule_id="TS-MALFORMED-TIMESTAMP",
                severity=Severity.INFORMATIONAL.value,
                explanation=(
                    f"Field '{field_name}' is present but is not a valid ISO 8601 timestamp. "
                    "Malformed values are reported separately from anomalous relationships."
                ),
                recommended_action="Correct the export or inspect the original metadata source.",
                certainty=Certainty.INCONCLUSIVE.value,
                simulated=simulated,
                source_dataset=source_name,
            )
        )
        return None


def _ts_finding(
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
        module="timestamp_analyzer",
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
