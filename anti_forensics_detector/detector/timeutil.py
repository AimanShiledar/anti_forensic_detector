"""ISO 8601 timestamp parsing with consistent timezone handling."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class TimestampParseError(ValueError):
    pass


def parse_iso8601(value: Any) -> datetime:
    """Parse an ISO 8601 timestamp. Naive values are treated as UTC."""
    if value is None:
        raise TimestampParseError("timestamp is missing")
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if not text:
            raise TimestampParseError("timestamp is empty")
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise TimestampParseError(f"invalid ISO 8601 timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def try_parse_iso8601(value: Any) -> datetime | None:
    try:
        return parse_iso8601(value)
    except TimestampParseError:
        return None
