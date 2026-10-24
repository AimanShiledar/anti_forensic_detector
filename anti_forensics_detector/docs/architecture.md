# System architecture

## Purpose

The system is a **defensive analysis pipeline**. It consumes investigator-supplied records and workspace files, emits explainable findings, and correlates those findings. It does not attack systems, wipe logs, or bypass forensic controls.

## Logical architecture

```
                INPUT EVIDENCE
                      |
         +------------+------------+
         |            |            |
         v            v            v
      Log Data     File Data    Metadata and
                                History Data
         |            |            |
         v            v            v
   Log Detector  Integrity     Anomaly and
                 Checker       History Analysis
         |            |            |
         +------------+------------+
                      |
                      v
             NORMALIZED FINDINGS
                      |
                      v
             CORRELATION ENGINE
                      |
                      v
             SEVERITY ASSESSMENT
                      |
                      v
              STREAMLIT DASHBOARD
                      |
                      v
             FORENSIC REPORT EXPORT
```

## Module responsibilities

| Component | File | Responsibility |
|-----------|------|----------------|
| Models | `detector/models.py` | `Finding`, `CorrelationGroup`, `AnalysisResult`, severity and certainty enumerations |
| Rules | `detector/rules.py`, `config/detection_rules.json` | Configurable event types, windows, and score thresholds |
| Evidence loader | `detector/evidence_loader.py` | JSON/CSV import, size/type checks, recoverable errors |
| Log detector | `detector/log_detector.py` | Structured event-type rules for clearing, deletion, config change, missing expected events, repeats |
| Integrity checker | `detector/integrity_checker.py` | SHA-256 baseline create/verify inside a workspace root |
| Timestamp analyzer | `detector/timestamp_analyzer.py` | ISO 8601 parsing, impossible order, future times, independent-time discrepancy |
| History analyzer | `detector/history_analyzer.py` | Clear events, sequence gaps, snapshot diff |
| Correlation | `detector/correlation_engine.py` | Shared path/host/ref + time window clustering and scoring |
| Pipeline | `detector/pipeline.py` | Orchestrates detectors; used by the UI and tests |
| Reports | `detector/report_generator.py` | JSON/CSV export with limitations |
| UI | `app.py` | Streamlit dashboard only; no embedded detection algorithms |

## Data flow

1. The user loads bundled synthetic JSON or uploads JSON/CSV.
2. `evidence_loader` returns dictionaries plus `LoadIssue` objects for bad files.
3. `run_analysis` calls each detector with the same rule document.
4. Each detector returns `Finding` instances. Detectors do not invent host activity that was not in the input.
5. `correlate_findings` clusters related findings and assigns investigation priority.
6. The dashboard reads `AnalysisResult` metrics from the actual object (no hardcoded totals).
7. Report export serializes that same object.

## Finding schema

Each finding includes: ID, module, evidence reference, detection time, observed evidence, rule ID, severity, explanation, recommended action, certainty, optional path/host/timestamp, simulated flag, and source dataset name.

Certainty values:

- `CONFIRMED_OBSERVATION` — a measurable difference or an explicit structured event is present in the input (for example a hash mismatch).
- `SUSPICIOUS_INDICATOR` — a configured pattern that warrants review but has benign explanations.
- `INCONCLUSIVE` — missing, malformed, or insufficient evidence (for example a history gap).

## Input formats

JSON may be an array of objects or an object with `events`, `records`, `entries`, `history`, or `metadata` arrays. CSV must have a header row. Maximum upload size is 2 MB.

Event fields commonly used: `event_id`, `timestamp`, `event_type`, `description`, `host`, `related_path`, `simulated`.

Metadata fields: `record_id`, `path`, `created`, `modified`, `accessed`, `event_time`, `independent_event_time`, `baseline_mtime`.

History fields: `entry_id`, `sequence`, `command`, `event_type`, `timestamp`, `host`.

## Output formats

- Dashboard tables derived from findings
- JSON report with summary, findings, correlations, rules triggered, limitations, disclaimer
- CSV of findings for spreadsheet review

## Design decisions

- **Rule-based, not ML.** Scoring is documented and inspectable for a viva voce.
- **Workspace jail for hashing.** Integrity checks refuse paths outside `workspace/` when a root is supplied.
- **Read-only evidence.** Loaders never execute imported commands.
- **Synthetic labels.** Demonstration records set `simulated` so evaluators are not told the data came from a live breach.
- **JSON instead of SQLite.** The prototype does not need concurrent multi-user storage.
- **Separate baseline create vs verify.** Matches forensic practice of recording a known-good reference before comparison.

## Component interactions

`app.py` → `load_records_*` / `run_analysis` / `create_baseline` / `verify_baseline` / `report_to_*`.

Tests import detector modules directly and do not go through Streamlit.
