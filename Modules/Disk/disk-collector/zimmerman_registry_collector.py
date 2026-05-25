"""Registry collector using RECmd (Eric Zimmerman) with DFIRBatch.reb.

Replaces registry_collector.py for the SYSTEM/SOFTWARE/SAM/SECURITY hives and
NTUSER.DAT user hives.  Uses RECmd's DFIRBatch.reb which covers 200+ registry
keys across all DFIR-relevant categories in a single pass, avoiding the NK
record errors that plagued the python-registry based collector.

Output files:
  registry_autoruns.txt   — Autostart Execution Points (Run keys, services, etc.)
  registry_misc.txt       — Everything else (system info, user activity, cloud storage, ...)
"""
from __future__ import annotations

import csv
import io
import os
import subprocess
import sys
import tempfile
from typing import Iterator, List, Optional

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _common as _c  # type: ignore
else:
    from . import _common as _c

_AUTORUN_CATEGORIES = {
    "autoruns", "services", "program execution", "user activity",
}

_TOOL_RELPATH = "RECmd/RECmd.dll"


def _dotnet(tool_dll: str, args: list[str], timeout: int = 300) -> Optional[str]:
    cmd = ["dotnet", tool_dll] + args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode not in (0, 1):
            print(f"[zimm_reg] RECmd exited {r.returncode}: {r.stderr[:400]}", file=sys.stderr)
        return r.stdout
    except FileNotFoundError:
        print("[zimm_reg] dotnet not found in PATH", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print(f"[zimm_reg] RECmd timed out after {timeout}s", file=sys.stderr)
        return None


def _run_recmd(hive_dir: str, batch_file: str, tool_dll: str,
               out_tmp: str, extra_dirs: list[str]) -> List[str]:
    """Run RECmd against hive_dir (and any extra_dirs) using batch_file.

    Returns list of CSV files written to out_tmp.
    """
    for directory in [hive_dir] + extra_dirs:
        if not directory or not os.path.isdir(directory):
            continue
        _dotnet(tool_dll, ["-d", directory, "--bn", batch_file,
                            "--csv", out_tmp, "--nl"], timeout=600)

    csv_files = []
    for fname in os.listdir(out_tmp):
        if fname.endswith(".csv"):
            csv_files.append(os.path.join(out_tmp, fname))
    return csv_files


def _csv_to_records(csv_path: str) -> Iterator[dict]:
    try:
        with open(csv_path, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                yield row
    except Exception as e:
        print(f"[zimm_reg] failed to parse {csv_path}: {e}", file=sys.stderr)


def _row_to_find_evil(row: dict) -> dict:
    """Convert one RECmd CSV row to a FIND_EVIL_DISK registry record."""
    hive_path = row.get("HivePath") or row.get("hivepath") or ""
    hive_type = row.get("HiveType") or row.get("hivetype") or ""
    key_path  = row.get("KeyPath")  or row.get("keypath")  or ""
    val_name  = row.get("ValueName") or row.get("valuename") or ""
    val_data  = row.get("ValueData") or row.get("valuedata") or ""
    category  = row.get("Category") or row.get("category") or ""
    desc      = row.get("Description") or row.get("description") or ""
    ts        = row.get("LastWriteTimestamp") or row.get("lastwritetimestamp") or ""

    full_key = f"{hive_type}\\{key_path}" if hive_type else key_path

    return {
        "type": "registry",
        "key": full_key,
        "value": val_name or None,
        "data": val_data or None,
        "modified": ts or None,
        "category": category or None,
        "description": desc or None,
        "artifact_source": os.path.basename(hive_path) if hive_path else "registry",
    }


def collect(config: dict) -> tuple[Iterator[dict], Iterator[dict]]:
    """Yield (autorun_records, misc_records) from RECmd DFIRBatch output."""
    zimm = config.get("zimmerman_tools") or {}
    base_dir = zimm.get("base_dir") or "/opt/zimmermantools"
    tool_dll = os.path.join(base_dir, _TOOL_RELPATH)
    batch_file = zimm.get("regedit_batch") or os.path.join(
        base_dir, "RECmd/BatchExamples/DFIRBatch.reb")

    if not os.path.isfile(tool_dll):
        print(f"[zimm_reg] RECmd not found: {tool_dll}", file=sys.stderr)
        return iter([]), iter([])
    if not os.path.isfile(batch_file):
        print(f"[zimm_reg] DFIRBatch.reb not found: {batch_file}", file=sys.stderr)
        return iter([]), iter([])

    hive_dir = (config.get("registry") or {}).get("hive_dir") or ""

    # Find user NTUSER.DAT hives
    extra_dirs: list[str] = []
    ntuser_search = zimm.get("ntuser_search_dirs") or []
    ntuser_fname = zimm.get("user_hive_filename") or "NTUSER.DAT"
    for search_root in ntuser_search:
        if not search_root or not os.path.isdir(search_root):
            continue
        for user_dir in os.listdir(search_root):
            user_path = os.path.join(search_root, user_dir)
            ntuser = os.path.join(user_path, ntuser_fname)
            if os.path.isfile(ntuser):
                extra_dirs.append(user_path)

    autoruns: list[dict] = []
    misc: list[dict] = []

    with tempfile.TemporaryDirectory(prefix="dfir_recmd_") as tmp:
        csv_files = _run_recmd(hive_dir, batch_file, tool_dll, tmp, extra_dirs)
        if not csv_files:
            print("[zimm_reg] RECmd produced no CSV output", file=sys.stderr)
            return iter([]), iter([])
        for csv_path in csv_files:
            for raw_row in _csv_to_records(csv_path):
                rec = _row_to_find_evil(raw_row)
                cat_lower = (rec.get("category") or "").lower()
                if any(c in cat_lower for c in _AUTORUN_CATEGORIES):
                    autoruns.append(rec)
                else:
                    misc.append(rec)

    return iter(autoruns), iter(misc)


def run_from_config(config: dict, out_dir: str) -> dict:
    max_recs = config.get("max_records")
    autoruns_iter, misc_iter = collect(config)
    out_autoruns = os.path.join(out_dir, "registry_autoruns.txt")
    out_misc     = os.path.join(out_dir, "registry_misc.txt")
    n_auto = _c.write_records_to_file(autoruns_iter, out_autoruns, limit=max_recs)
    n_misc = _c.write_records_to_file(misc_iter, out_misc, limit=max_recs)
    total = n_auto + n_misc
    print(f"[zimm_reg] {n_auto} autorun + {n_misc} misc records", file=sys.stderr)
    return {
        "output_files": [out_autoruns, out_misc],
        "record_count": total,
    }
