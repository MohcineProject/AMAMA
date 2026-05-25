"""Parse Windows event logs via Zimmerman's EvtxECmd.

Replaces the python-evtx eventlog_collector.py for speed. EvtxECmd processes
a full directory of .evtx files (including archives) in minutes vs hours.

Uses EvtxECmd's --maps directory for 453 known event type maps, then converts
its CSV output into type=event FIND_EVIL_DISK records filtered to
high_signal_event_ids. Output files mirror the python-evtx collector:
  eventlog_security.txt, eventlog_system.txt, eventlog_application.txt

Command key: zevtx
"""
from __future__ import annotations

import csv
import io
import os
import subprocess
import sys
import tempfile
from typing import Iterator

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _common as _c  # type: ignore
else:
    from . import _common as _c

_EVTX_DLL = "EvtxeCmd/EvtxECmd.dll"

# Maps EvtxECmd's Channel field to our output bucket filenames.
_CHANNEL_MAP = {
    "security":    "eventlog_security.txt",
    "system":      "eventlog_system.txt",
    "application": "eventlog_application.txt",
}

# Fields EvtxECmd may populate — we pick what's forensically useful.
_EVTX_FIELDS = [
    ("TimeCreated",       "time"),
    ("EventId",           "id"),
    ("Channel",           "channel"),
    ("Computer",          "computer"),
    ("UserName",          "user"),
    ("RemoteHost",        "src_ip"),
    ("MapDescription",    "description"),
    ("PayloadData1",      "detail1"),
    ("PayloadData2",      "detail2"),
    ("PayloadData3",      "detail3"),
    ("ExecutableInfo",    "cmdline"),
    ("SourceFile",        "artifact_source"),
]


def _bucket_for(channel: str) -> str:
    ch = channel.lower()
    for key, fname in _CHANNEL_MAP.items():
        if key in ch:
            return fname
    return "eventlog_other.txt"


def _csv_to_records(csv_path: str, allow_set: set,
                    always_emit: set) -> Iterator[dict]:
    """Yield type=event dicts from one EvtxECmd CSV output file."""
    try:
        with open(csv_path, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    eid = int(row.get("EventId") or 0)
                except ValueError:
                    eid = 0
                if allow_set and eid not in allow_set and eid not in always_emit:
                    continue
                rec: dict = {"type": "event", "id": eid}
                for csv_col, our_key in _EVTX_FIELDS:
                    val = (row.get(csv_col) or "").strip()
                    if val and val != "-":
                        rec[our_key] = val
                # Normalise logon_type out of PayloadData fields if present
                for detail_key in ("detail1", "detail2", "detail3"):
                    v = rec.get(detail_key, "")
                    if v.lower().startswith("logon type:"):
                        rec["logon_type"] = v.split(":", 1)[1].strip()
                yield rec
    except Exception as e:
        print(f"[zimm_evtx] failed to read {csv_path}: {e}", file=sys.stderr)


def run_from_config(config: dict, out_dir: str) -> dict:
    base_dir = (config.get("zimmerman_tools") or {}).get("base_dir", "/opt/zimmermantools")
    evtx_dll = os.path.join(base_dir, _EVTX_DLL)
    if not os.path.isfile(evtx_dll):
        return {"error": f"EvtxECmd DLL not found: {evtx_dll}",
                "output_files": [], "record_count": 0}

    evtx_dir = (config.get("eventlog") or {}).get("evtx_dir")
    if not evtx_dir or not os.path.isdir(evtx_dir):
        return {"error": f"eventlog.evtx_dir not found: {evtx_dir!r}",
                "output_files": [], "record_count": 0}

    maps_dir = os.path.join(base_dir, "EvtxeCmd", "Maps")
    allow_set = set(int(x) for x in (config.get("high_signal_event_ids") or []))
    always_emit = set(int(x) for x in (config.get("always_emit_event_ids") or [1102, 104]))
    max_recs = config.get("max_records")

    with tempfile.TemporaryDirectory(prefix="dfir_evtx_") as tmp:
        cmd = [
            "dotnet", evtx_dll,
            "-d", evtx_dir,
            "--csv", tmp,
            "--csvf", "evtx_out.csv",
        ]
        if os.path.isdir(maps_dir):
            cmd += ["--maps", maps_dir]

        print(f"[zimm_evtx] running EvtxECmd on {evtx_dir} ...", file=sys.stderr)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
        except subprocess.TimeoutExpired:
            return {"error": "EvtxECmd timed out after 20 min",
                    "output_files": [], "record_count": 0}

        csv_path = os.path.join(tmp, "evtx_out.csv")
        if not os.path.isfile(csv_path):
            # EvtxECmd sometimes names the file differently; find any CSV
            csvs = [f for f in os.listdir(tmp) if f.endswith(".csv")]
            if not csvs:
                stderr_tail = result.stderr[-500:] if result.stderr else ""
                return {"error": f"EvtxECmd produced no CSV. stderr: {stderr_tail}",
                        "output_files": [], "record_count": 0}
            csv_path = os.path.join(tmp, csvs[0])

        print(f"[zimm_evtx] parsing CSV output ...", file=sys.stderr)

        # Split records into per-channel buckets
        buckets: dict[str, list] = {}
        for rec in _csv_to_records(csv_path, allow_set, always_emit):
            bucket = _bucket_for(rec.pop("channel", ""))
            buckets.setdefault(bucket, []).append(rec)

    os.makedirs(out_dir, exist_ok=True)
    out_files = []
    total = 0
    for fname, recs in buckets.items():
        out_path = os.path.join(out_dir, fname)
        n = _c.write_records_to_file(iter(recs), out_path, limit=max_recs)
        out_files.append(out_path)
        total += n
        print(f"[zimm_evtx] {fname}: {n} records", file=sys.stderr)

    return {"output_files": out_files, "record_count": total}
