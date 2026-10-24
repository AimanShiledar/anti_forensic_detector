# Demonstration guide (university evaluator)

All bundled datasets are **synthetic**. Say that out loud during the demo. Do not claim the laptop was compromised or that the report would be admissible in court.

## 0. Launch

```powershell
cd C:\Users\shile\Desktop\anti_forensics_detector
.\.venv\Scripts\Activate.ps1
streamlit run app.py
```

Open the printed local URL.

Optional: in another terminal, `python -m pytest -q` to show tests passing.

## 1. Explain the architecture (60 seconds)

Evidence in → four detectors → normalized findings → correlation → dashboard/report. Detection code is in `detector/`, not in the Streamlit widgets.

## 2. Scenario 1 — Normal activity

1. Open **Evidence Input**.
2. Click **Load Scenario 1: Normal (synthetic)**.
3. Click **Analyze loaded evidence**.
4. Open **Overview** and **Detection Results**.

**Expected:** records are counted from the loaded JSON. There should be **no HIGH or CRITICAL** findings from this dataset. Say: *“No configured high-priority indicators were detected. That does not prove the system is clean.”*

## 3. Scenario 2 — Suspicious log activity

1. Click **Load Scenario 2–5: Suspicious (synthetic)** then **Analyze**.
2. Filter Detection Results to module `log_detector`.

**Expected:** a finding with rule `LOG-EXPLICIT-CLEAR` for `EVENTLOG_CLEARED`, plus related logging-config / deletion events. Each row explains the structured event type. Rows should show **Simulated = True**.

## 4. Scenario 3 — File modification (real bytes in the demo folder)

Stay on **File Integrity Scanner**. Only `workspace/demo_files` is used.

1. Select `demo_files/sample_monitored.txt`.
2. **Create trusted baseline.**
3. **Verify against baseline** — should match.
4. Click **Modify sample_monitored.txt for mismatch demo**.
5. **Verify against baseline** — SHA-256 expected vs observed should differ (`INT-HASH-MISMATCH`).
6. Click **Restore sample_monitored.txt** so the next run is clean.

Say: *“The hash mismatch confirms the file bytes changed versus our baseline. It does not tell us who changed it or when.”*

## 5. Scenario 4 — Timestamp anomaly

In Detection Results, filter module `timestamp_analyzer`.

**Expected:** `TS-CREATED-AFTER-MODIFIED` on `/demo/workspace/monitored/app.log` because created is later than modified. Also a future timestamp on a **different** host (`WORKSTATION-OTHER`) and a malformed timestamp reported separately from anomalies.

Say: *“This is an inconsistent relationship, not proof of timestomping.”*

## 6. Scenario 5 — Correlation

Open **Correlated Activity**.

**Expected:** a group that combines log, timestamp, and history findings sharing `WORKSTATION-DEMO` and `/demo/workspace/monitored/app.log` inside the 900-second window. The explanation cites the window and shared context. Score is labeled as **not a probability**. The future-timestamp finding on `WORKSTATION-OTHER` should **not** be forced into that group.

## 7. Export a report

**Forensic Report** tab → download JSON and CSV.

Point to:

- scan time and input sources
- summary counts taken from the analysis
- limitations and the disclaimer that findings are indicators

## 8. Accurate talking points if asked

- Confirmed observation: hash mismatch, explicit `EVENTLOG_CLEARED` record in the file.
- Suspicious: logging service stopped, clear-history command pattern.
- Inconclusive: missing heartbeat, history sequence gap, missing metadata.
- An attacker who edits the baseline JSON can evade integrity checking.
- We never ran attacker tools; we analyzed labeled demo evidence.
