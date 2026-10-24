"""Rule-based correlation of findings from multiple detection modules."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable

from detector.models import CorrelationGroup, Finding, SEVERITY_ORDER, Severity, higher_severity
from detector.timeutil import try_parse_iso8601


def correlate_findings(findings: Iterable[Finding], rules: dict[str, Any]) -> list[CorrelationGroup]:
    cfg = rules.get("correlation", {})
    window = int(cfg.get("window_seconds", 900))
    require_shared = bool(cfg.get("require_shared_context", True))
    min_findings = int(cfg.get("min_findings", 2))
    min_modules = int(cfg.get("min_distinct_modules", 2))
    bonus = int(cfg.get("score_bonus_per_extra_module", 4))
    thresholds = cfg.get("priority_thresholds", {})
    points = rules.get("severity_points", {})

    items = [f for f in findings if f.rule_id not in {"LOG-MALFORMED-RECORD", "TS-MALFORMED-RECORD", "HIST-MALFORMED-RECORD", "TS-MALFORMED-TIMESTAMP"}]
    parent = {f.finding_id: f.finding_id for f in items}
    by_id = {f.finding_id: f for f in items}

    def find(fid: str) -> str:
        while parent[fid] != fid:
            parent[fid] = parent[parent[fid]]
            fid = parent[fid]
        return fid

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    n = len(items)
    for i in range(n):
        for j in range(i + 1, n):
            a, b = items[i], items[j]
            if _related(a, b, window_seconds=window, require_shared=require_shared):
                union(a.finding_id, b.finding_id)

    clusters: dict[str, list[Finding]] = defaultdict(list)
    for finding in items:
        clusters[find(finding.finding_id)].append(finding)

    groups: list[CorrelationGroup] = []
    group_n = 0
    for cluster in clusters.values():
        modules = sorted({f.module for f in cluster})
        if len(cluster) < min_findings or len(modules) < min_modules:
            continue
        # Deduplicate by evidence_ref + rule_id so the same underlying event is not scored twice
        unique: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for finding in cluster:
            key = (finding.evidence_ref, finding.rule_id)
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        if len(unique) < min_findings:
            continue

        group_n += 1
        score = sum(int(points.get(f.severity, 1)) for f in unique)
        extra_modules = max(0, len(modules) - 1)
        score += extra_modules * bonus
        priority = _priority_from_score(score, thresholds)
        max_individual = unique[0].severity
        for finding in unique[1:]:
            max_individual = higher_severity(max_individual, finding.severity)
        if SEVERITY_ORDER[Severity(priority)] < SEVERITY_ORDER[Severity(max_individual)]:
            # Combined investigation priority is at least the strongest member, and may be higher.
            pass

        paths = sorted({f.related_path for f in unique if f.related_path})
        hosts = sorted({f.host for f in unique if f.host})
        timestamps = [try_parse_iso8601(f.related_timestamp) for f in unique]
        timestamps = [t for t in timestamps if t is not None]
        window_note = {
            "correlation_window_seconds": window,
            "shared_paths": paths,
            "shared_hosts": hosts,
            "earliest_related_timestamp": min(timestamps).isoformat() if timestamps else None,
            "latest_related_timestamp": max(timestamps).isoformat() if timestamps else None,
            "max_individual_severity": max_individual,
            "score_is_not_a_probability": True,
        }
        explanation = (
            f"Grouped {len(unique)} findings from modules {', '.join(modules)} because they share "
            f"contextual identifiers (path and/or host) and fall within a {window}-second correlation "
            "window (or share the same path when timestamps are unavailable). "
            f"Rule-based score={score} maps to investigation priority {priority}. "
            "This raises investigative attention; it does not prove a single coordinated anti-forensic campaign."
        )
        groups.append(
            CorrelationGroup(
                group_id=f"CORR-{group_n:04d}",
                finding_ids=[f.finding_id for f in unique],
                modules=modules,
                investigation_priority=priority,
                score=score,
                explanation=explanation,
                linking_context=window_note,
                simulated=any(f.simulated for f in unique),
            )
        )
    groups.sort(key=lambda g: g.group_id)
    return groups


def _related(a: Finding, b: Finding, *, window_seconds: int, require_shared: bool) -> bool:
    if a.finding_id == b.finding_id:
        return False
    shared_path = bool(a.related_path and b.related_path and a.related_path == b.related_path)
    shared_host = bool(a.host and b.host and a.host == b.host)
    shared_ref = bool(a.evidence_ref and b.evidence_ref and a.evidence_ref == b.evidence_ref)
    if require_shared and not (shared_path or shared_host or shared_ref):
        return False
    ta = try_parse_iso8601(a.related_timestamp)
    tb = try_parse_iso8601(b.related_timestamp)
    if ta and tb:
        return abs((ta - tb).total_seconds()) <= window_seconds
    # If timestamps cannot be compared, only relate on an exact shared path or evidence reference.
    return shared_path or shared_ref


def _priority_from_score(score: int, thresholds: dict[str, Any]) -> str:
    ordered = [
        (Severity.CRITICAL.value, int(thresholds.get("CRITICAL", 20))),
        (Severity.HIGH.value, int(thresholds.get("HIGH", 12))),
        (Severity.MEDIUM.value, int(thresholds.get("MEDIUM", 7))),
        (Severity.LOW.value, int(thresholds.get("LOW", 3))),
        (Severity.INFORMATIONAL.value, int(thresholds.get("INFORMATIONAL", 0))),
    ]
    for label, threshold in ordered:
        if score >= threshold:
            return label
    return Severity.INFORMATIONAL.value
