"""Read-only import of JSON/CSV evidence with validation and recoverable errors."""

from __future__ import annotations

import csv
import json
from io import StringIO
from pathlib import Path
from typing import Any

from detector.models import LoadIssue

MAX_UPLOAD_BYTES = 2 * 1024 * 1024
ALLOWED_SUFFIXES = {".json", ".csv"}


def load_records_from_path(path: str | Path, *, source_label: str | None = None) -> tuple[list[dict[str, Any]], list[LoadIssue]]:
    file_path = Path(path)
    label = source_label or str(file_path)
    if not file_path.is_file():
        return [], [LoadIssue(source=label, message=f"File not found: {file_path}", recoverable=True)]
    size = file_path.stat().st_size
    if size > MAX_UPLOAD_BYTES:
        return [], [LoadIssue(source=label, message=f"File exceeds {MAX_UPLOAD_BYTES} byte limit", recoverable=True)]
    suffix = file_path.suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        return [], [LoadIssue(source=label, message=f"Unsupported file type '{suffix}'", recoverable=True)]
    text = file_path.read_text(encoding="utf-8", errors="replace")
    return parse_records(text, suffix=suffix, source_label=label)


def load_records_from_bytes(
    data: bytes,
    filename: str,
    *,
    source_label: str | None = None,
) -> tuple[list[dict[str, Any]], list[LoadIssue]]:
    label = source_label or filename
    if len(data) > MAX_UPLOAD_BYTES:
        return [], [LoadIssue(source=label, message=f"Upload exceeds {MAX_UPLOAD_BYTES} byte limit", recoverable=True)]
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        return [], [LoadIssue(source=label, message=f"Unsupported file type '{suffix}'", recoverable=True)]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
    return parse_records(text, suffix=suffix, source_label=label)


def parse_records(text: str, *, suffix: str, source_label: str) -> tuple[list[dict[str, Any]], list[LoadIssue]]:
    issues: list[LoadIssue] = []
    if suffix == ".json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            return [], [LoadIssue(source=source_label, message=f"Invalid JSON: {exc}", recoverable=True)]
        records, unwrap_issues = unwrap_json_payload(payload, source_label)
        issues.extend(unwrap_issues)
        return records, issues

    reader = csv.DictReader(StringIO(text))
    if reader.fieldnames is None:
        return [], [LoadIssue(source=source_label, message="CSV has no header row", recoverable=True)]
    records: list[dict[str, Any]] = []
    for index, row in enumerate(reader, start=2):
        cleaned = {k: (v if v != "" else None) for k, v in row.items()}
        if all(v is None for v in cleaned.values()):
            continue
        _coerce_flags(cleaned)
        records.append(cleaned)
        if index > 20000:
            issues.append(LoadIssue(source=source_label, message="CSV truncated after 20000 data rows", recoverable=True))
            break
    return records, issues


def unwrap_json_payload(payload: Any, source_label: str) -> tuple[list[dict[str, Any]], list[LoadIssue]]:
    issues: list[LoadIssue] = []
    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict):
        for key in ("events", "records", "entries", "files", "history", "metadata"):
            if isinstance(payload.get(key), list):
                records = payload[key]
                break
        else:
            records = [payload]
    else:
        return [], [LoadIssue(source=source_label, message="JSON root must be an object or array", recoverable=True)]

    valid: list[dict[str, Any]] = []
    for index, item in enumerate(records, start=1):
        if isinstance(item, dict):
            valid.append(item)
        else:
            issues.append(
                LoadIssue(
                    source=source_label,
                    message=f"Skipped non-object record at position {index}",
                    recoverable=True,
                )
            )
    return valid, issues


def _coerce_flags(row: dict[str, Any]) -> None:
    for key in ("simulated", "expected_event_present"):
        if key in row and isinstance(row[key], str):
            lowered = row[key].strip().lower()
            if lowered in {"true", "1", "yes"}:
                row[key] = True
            elif lowered in {"false", "0", "no"}:
                row[key] = False
