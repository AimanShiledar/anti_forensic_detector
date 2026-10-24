# Detection methodology

## What anti-forensic activity means in this project

Anti-forensics is activity intended to conceal, alter, destroy, or manipulate digital evidence. This prototype **does not** implement anti-forensic techniques. It looks for **indicators** that such activity *might* have occurred, based on evidence the user supplies.

A single indicator never proves intent. Administrators clear logs, applications rotate files, clocks drift, and command history is often incomplete for ordinary reasons.

## What each detector identifies

### Log detector

Uses **structured `event_type` values** from `config/detection_rules.json`:

- `LOG-EXPLICIT-CLEAR` — types such as `EVENTLOG_CLEARED`
- `LOG-MONITORED-FILE-DELETED` — recorded deletion of a monitored log path
- `LOG-CONFIG-CHANGED` — logging service stop or audit policy disable
- `LOG-MISSING-EXPECTED-EVENT` — only when `baseline_coverage` is `sufficient` and `expected_event_present` is false; certainty is **inconclusive**
- `LOG-REPEATED-SUSPICIOUS-EVENTS` — several configured logging events on one host inside `repeat_window_seconds`

The words “delete” or “clear” in a description are **not** sufficient by themselves.

### Integrity checker

Computes SHA-256 of workspace files.

- Baseline create stores path, digest, and size.
- Verify reports modified (digest mismatch), missing, or unexpected files.
- A mismatch is a **confirmed observation relative to the baseline**.
- SHA-256 does **not** identify who changed the file or when.
- An attacker who changes both the file and the baseline can evade the check.

### Timestamp analyzer

Parses ISO 8601; naive timestamps are treated as UTC.

- Created after modified beyond clock skew
- Timestamp later than analysis time beyond clock skew
- Modified time different from a recorded metadata baseline
- Discrepancy between `event_time` and `independent_event_time`
- Missing metadata is reported as missing, not as an anomaly
- Ordinary access-time-only change is not treated as mtime tampering when mtime still matches the baseline
- Inconsistencies are **not** proof of timestomping

### History analyzer

- Explicit `HISTORY_CLEARED` (and related configured types)
- Command text matching configured clear patterns (suspicious, not confirmed destruction)
- Sequence gaps (inconclusive)
- Difference versus a trusted snapshot (observation of difference only)

History may be disabled, rotated, or collected incompletely.

### Correlation engine

Two findings are related only if they share `related_path`, `host`, or `evidence_ref`, **and** their `related_timestamp` values fall within `correlation.window_seconds` (default 900). If timestamps cannot be compared, an exact shared path or evidence reference is required. Findings are **not** grouped merely because they came from the same uploaded file.

Duplicate pairs of `(evidence_ref, rule_id)` are scored once.

## Severity scoring

Individual finding severity comes from the triggering rule (for example explicit log clear is HIGH).

Correlation **score** (not a probability):

1. Sum `severity_points` for unique findings in the group  
   INFORMATIONAL=1, LOW=2, MEDIUM=4, HIGH=7, CRITICAL=10
2. Add `score_bonus_per_extra_module` (default 4) for each module beyond the first
3. Map score to investigation priority using thresholds:

| Priority | Minimum score |
|----------|----------------|
| CRITICAL | 20 |
| HIGH | 12 |
| MEDIUM | 7 |
| LOW | 3 |
| INFORMATIONAL | 0 |

Investigation priority can be higher than any single member because multiple independent modules agreeing is treated as more urgent to review. It is still not a calibrated risk estimate.

## False positives

Typical benign causes:

- Authorized log rotation or log-clear after a support ticket
- Application upgrades rewriting files (hash change)
- Copying files across filesystems (timestamp reordering)
- Multiple concurrent shells (history sequence gaps)
- Clock not synchronized (NTP failure)

## Known limitations

- Coverage is only as good as imported evidence.
- No deleted-file carving, memory forensics, or prefetch analysis.
- No attribution.
- Rules can be tuned; they are not statistically validated on a large corpus.
- Synthetic demo data will produce findings because it was authored to exercise rules.

## Ethical boundary

The code analyzes data. It does not include exploits, log wipers, timestomp utilities, or instructions to hide from investigators.
