"""Shared helpers for every sub-collector.

Kept deliberately tiny. Anything that grows beyond utility-helper status belongs
in its own module. See HOW_TO_BUILD.md §8.1 for the FILETIME epoch rationale.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import functools
import json
import os
import subprocess
from typing import Any, Iterable, Iterator, Optional


@functools.lru_cache(maxsize=None)
def dotnet_available() -> bool:
    """Return True if the dotnet runtime is on PATH and responds to --version."""
    try:
        r = subprocess.run(["dotnet", "--version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# 100-nanosecond intervals between 1601-01-01 (Windows epoch) and 1970-01-01 (Unix).
_FILETIME_EPOCH_DIFF = 116_444_736_000_000_000
_MIN_VALID_DT = _dt.datetime(1700, 1, 1, tzinfo=_dt.timezone.utc)
_MAX_VALID_DT = _dt.datetime(2100, 1, 1, tzinfo=_dt.timezone.utc)


def windows_filetime_to_utc(ft: int) -> Optional[_dt.datetime]:
    """Convert a Windows FILETIME (100ns intervals since 1601-01-01 UTC) to a tz-aware datetime.

    Returns None for null/zero/invalid values rather than 1601-01-01, which is a sentinel
    used by NTFS for "never". Out-of-range values also return None so downstream
    serialization stays clean.
    """
    if not ft or ft <= 0:
        return None
    try:
        unix_ts = (ft - _FILETIME_EPOCH_DIFF) / 10_000_000
        dt = _dt.datetime.fromtimestamp(unix_ts, tz=_dt.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    if dt < _MIN_VALID_DT or dt > _MAX_VALID_DT:
        return None
    return dt


def chrome_webkit_us_to_utc(us: int) -> Optional[_dt.datetime]:
    """Chrome/Edge timestamp: microseconds since 1601-01-01 UTC."""
    if not us or us <= 0:
        return None
    try:
        return windows_filetime_to_utc(us * 10)
    except Exception:
        return None


def firefox_unix_us_to_utc(us: int) -> Optional[_dt.datetime]:
    """Firefox places.sqlite timestamp: microseconds since 1970-01-01 UTC."""
    if not us or us <= 0:
        return None
    try:
        dt = _dt.datetime.fromtimestamp(us / 1_000_000, tz=_dt.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    if dt < _MIN_VALID_DT or dt > _MAX_VALID_DT:
        return None
    return dt


def to_iso8601(dt: Optional[_dt.datetime]) -> str:
    """ISO8601 in UTC, 'Z' suffix, second precision. Empty string for None."""
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_iso() -> str:
    return to_iso8601(_dt.datetime.now(tz=_dt.timezone.utc))


def escape_field(value: Any) -> str:
    """Render a value for the `key=value` line format.

    Quotes the value if it contains whitespace, '=', or '"'. Backslashes inside
    quoted strings are doubled so the line is unambiguous on round-trip.
    """
    s = str(value)
    if not s:
        return ""
    needs_quote = any(c in s for c in (" ", "\t", "=", '"'))
    if not needs_quote:
        return s
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


def format_find_evil_record(record_type: str, **fields: Any) -> str:
    """Serialize one FIND_EVIL_DISK record as a single line.

    `type=` is always emitted first. Empty / None values are dropped. Field order
    is preserved from the kwargs (Python 3.7+ dict insertion order).
    """
    parts = [f"type={escape_field(record_type)}"]
    for k, v in fields.items():
        if v is None or v == "":
            continue
        if isinstance(v, bool):
            v = "true" if v else "false"
        parts.append(f"{k}={escape_field(v)}")
    return " ".join(parts)


@contextlib.contextmanager
def open_records_writer(path: str) -> Iterator:
    """Open `path` for writing UTF-8, creating parent dirs as needed."""
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    f = open(path, "w", encoding="utf-8", newline="\n")
    try:
        yield f
    finally:
        f.close()


def write_records_to_file(records: Iterable[dict], out_path: str,
                          limit: Optional[int] = None) -> int:
    """Serialize every record dict (must contain 'type') and write to out_path.

    Returns the number of records written. If limit is set, stops after that many.
    """
    n = 0
    with open_records_writer(out_path) as f:
        for r in records:
            if limit is not None and n >= limit:
                break
            record_type = r.pop("type", None) or r.pop("record_type", None)
            if not record_type:
                continue
            line = format_find_evil_record(record_type, **r)
            f.write(line + "\n")
            n += 1
    return n


def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def setup_cli(description: str, default_out: str) -> argparse.ArgumentParser:
    """Standard argument parser shape shared by every collector.

    Each collector adds its own --input-style flags on top; this just guarantees
    --out and --config exist with consistent names.
    """
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--out", default=default_out,
                   help=f"Output file path (default: {default_out})")
    p.add_argument("--config", default=None,
                   help="Optional config.json path; sub-collectors may read keys from it")
    return p


def safe_int(value: Any, default: int = 0) -> int:
    try:
        if isinstance(value, str) and value.startswith("0x"):
            return int(value, 16)
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()
