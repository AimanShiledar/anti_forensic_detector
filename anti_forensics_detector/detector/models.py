"""Shared data structures for findings, correlation groups, and analysis results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Certainty(str, Enum):
    CONFIRMED_OBSERVATION = "CONFIRMED_OBSERVATION"
    SUSPICIOUS_INDICATOR = "SUSPICIOUS_INDICATOR"
    INCONCLUSIVE = "INCONCLUSIVE"


SEVERITY_ORDER = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def higher_severity(a: str, b: str) -> str:
    sa = Severity(a)
    sb = Severity(b)
    return sa.value if SEVERITY_ORDER[sa] >= SEVERITY_ORDER[sb] else sb.value


@dataclass
class Finding:
    finding_id: str
    module: str
    evidence_ref: str
    detection_time: str
    observed_evidence: dict[str, Any]
    rule_id: str
    severity: str
    explanation: str
    recommended_action: str
    certainty: str
    simulated: bool = False
    related_path: str | None = None
    related_timestamp: str | None = None
    host: str | None = None
    source_dataset: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CorrelationGroup:
    group_id: str
    finding_ids: list[str]
    modules: list[str]
    investigation_priority: str
    score: int
    explanation: str
    linking_context: dict[str, Any]
    simulated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LoadIssue:
    source: str
    message: str
    recoverable: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    scan_time: str
    input_sources: list[str]
    records_analyzed: int
    files_checked: int
    findings: list[Finding] = field(default_factory=list)
    correlations: list[CorrelationGroup] = field(default_factory=list)
    load_issues: list[LoadIssue] = field(default_factory=list)
    rules_triggered: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def high_priority_count(self) -> int:
        return sum(
            1
            for f in self.findings
            if f.severity in (Severity.HIGH.value, Severity.CRITICAL.value)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_time": self.scan_time,
            "input_sources": self.input_sources,
            "records_analyzed": self.records_analyzed,
            "files_checked": self.files_checked,
            "findings": [f.to_dict() for f in self.findings],
            "correlations": [c.to_dict() for c in self.correlations],
            "load_issues": [i.to_dict() for i in self.load_issues],
            "rules_triggered": self.rules_triggered,
            "limitations": self.limitations,
            "notes": self.notes,
            "disclaimer": (
                "Findings are investigation indicators derived from the supplied evidence. "
                "They are not automatic proof of malicious intent, legal admissibility, "
                "or a complete reconstruction of attacker activity."
            ),
        }
