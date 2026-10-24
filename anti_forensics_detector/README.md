# Detection of Anti-Forensic Activity on Compromised Systems

A locally runnable Python/Streamlit prototype that analyzes **imported** evidence and a **dedicated workspace** for indicators of possible anti-forensic activity. It is an academic demonstration system for digital-forensics and incident-response coursework.

## Abstract

Anti-forensics includes techniques that conceal, alter, destroy, or manipulate digital evidence. This project implements transparent, rule-based detectors for log-tampering indicators, SHA-256 file-integrity mismatches, timestamp inconsistencies, and command-history anomalies. A correlation engine groups related findings that share host/path context inside a configurable time window and assigns an ordinal investigation priority. The dashboard displays results produced by the detection engine and can export JSON/CSV summaries. Findings are investigation indicators, not proof of malicious intent.

## Problem statement

Investigators often receive mixed evidence: event exports, file hashes, metadata, and shell history. Individual anomalies are easy to over-interpret. The problem addressed here is how to **detect configured indicators**, **preserve the original evidence values**, **explain each rule**, and **correlate related indicators** without claiming that a single anomaly proves an attacker.

## Objectives

- Import structured JSON/CSV evidence without executing commands or modifying source files.
- Detect explicit log-clearing and related logging interference using event types, not keyword guessing alone.
- Maintain a trusted SHA-256 baseline for files in a project workspace and detect modified, missing, and newly appearing files.
- Flag impossible or inconsistent timestamp relationships with timezone-aware parsing.
- Flag history-clearing events, sequence gaps, and snapshot differences with cautious language.
- Correlate multi-module findings that share context and raise investigation priority using documented score thresholds.
- Provide a Streamlit demonstration interface and pytest coverage.

## Key features

- Rule file: `config/detection_rules.json`
- Normalized `Finding` objects with certainty labels: confirmed observation, suspicious indicator, or inconclusive
- Synthetic demonstration datasets labeled `simulated: true`
- File integrity operations confined to `workspace/`
- JSON and CSV report export with explicit limitations

## Technology stack

- Python 3.11+
- Streamlit dashboard
- hashlib SHA-256
- pandas and Plotly for tables/charts
- pytest
- JSON file storage (no required database)

## Architecture overview

Evidence is loaded, passed to independent detectors, normalized into findings, correlated, scored, shown in Streamlit, and exported. Detection logic lives in `detector/`; `app.py` only orchestrates the interface.

See `docs/architecture.md` and `docs/detection_methodology.md`.

## Folder structure

```
anti_forensics_detector/
  app.py
  requirements.txt
  detector/
  config/detection_rules.json
  test_data/
  workspace/demo_files/
  tests/
  docs/
```

## Installation (Windows)

Open PowerShell in the project folder:

```powershell
cd C:\Users\shile\Desktop\anti_forensics_detector
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If script execution is blocked:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Start the application

From the project root, with the virtual environment activated:

```powershell
streamlit run app.py
```

Then open the URL shown in the terminal (typically http://localhost:8501).

## Testing

```powershell
python -m pytest -q
```

## Demonstration

Follow `docs/demonstration_guide.md`. Short path:

1. Start Streamlit.
2. Evidence Input → **Load Scenario 1: Normal (synthetic)** → Analyze. Expect no HIGH/CRITICAL findings.
3. Load **Scenario 2–5: Suspicious (synthetic)** → Analyze. Expect log-clear, timestamp, history, and correlation results labeled simulated.
4. File Integrity Scanner: create baseline for `workspace/demo_files/sample_monitored.txt`, verify (pass), modify via the demo button, verify (hash mismatch).
5. Export JSON and CSV reports.

## Limitations

- Not a live EDR product and not a court-authenticated forensic tool.
- Does not reconstruct deleted data or attribute actions to a person.
- Hash baselines are only as trustworthy as their storage.
- Clock skew, log rotation, disabled history, and incomplete collection cause false positives and false negatives.
- Bundled datasets are synthetic.

## Future enhancements

- Optional read-only collection of selected Windows Event Log exports
- Additional structured event catalogs (Sysmon, auditd)
- Signed baseline manifests
- Timeline visualization with independent evidence sources
