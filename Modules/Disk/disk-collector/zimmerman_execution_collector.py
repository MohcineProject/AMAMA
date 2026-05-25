"""Execution artifact collector using Zimmerman tools.

Collects shimcache (AppCompatCacheParser) and amcache (AmcacheParser).
These fix the NK record errors in the Python-registry based collector.

Output files:
  registry_shimcache.txt  — AppCompatCache / shimcache entries
  amcache_records.txt     — Amcache file execution history
"""
from __future__ import annotations

import csv
import os
import subprocess
import sys
import tempfile
from typing import Iterator, Optional

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _common as _c  # type: ignore
else:
    from . import _common as _c


def _dotnet(dll_path: str, args: list[str], timeout: int = 180) -> Optional[str]:
    cmd = ["dotnet", dll_path] + args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode not in (0, 1):
            print(f"[zimm_exec] {os.path.basename(dll_path)} exited {r.returncode}: "
                  f"{r.stderr[:300]}", file=sys.stderr)
        return r.stdout
    except FileNotFoundError:
        print("[zimm_exec] dotnet not found in PATH", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print(f"[zimm_exec] {dll_path} timed out after {timeout}s", file=sys.stderr)
        return None


def _read_csv_files(directory: str) -> list[tuple[str, list[dict]]]:
    """Return [(filename, [row_dicts])] for every CSV in directory."""
    results = []
    for fname in os.listdir(directory):
        if not fname.endswith(".csv"):
            continue
        rows = []
        try:
            with open(os.path.join(directory, fname), encoding="utf-8-sig", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    rows.append(row)
        except Exception as e:
            print(f"[zimm_exec] failed to read {fname}: {e}", file=sys.stderr)
        results.append((fname, rows))
    return results


# ----------------------------- Shimcache -----------------------------

def collect_shimcache(system_hive: str, base_dir: str) -> Iterator[dict]:
    dll = os.path.join(base_dir, "AppCompatCacheParser.dll")
    if not os.path.isfile(dll):
        print(f"[zimm_exec] AppCompatCacheParser.dll not found: {dll}", file=sys.stderr)
        return
    if not system_hive or not os.path.isfile(system_hive):
        print(f"[zimm_exec] SYSTEM hive not found: {system_hive!r}", file=sys.stderr)
        return

    with tempfile.TemporaryDirectory(prefix="dfir_shim_") as tmp:
        _dotnet(dll, ["-f", system_hive, "--csv", tmp, "--nl"])
        for fname, rows in _read_csv_files(tmp):
            for row in rows:
                path = row.get("Path") or row.get("path") or ""
                ts   = row.get("LastModifiedTimeUTC") or row.get("lastmodifiedtimeutc") or \
                       row.get("DateTime") or ""
                executed = row.get("Executed") or row.get("executed") or ""
                controlset = row.get("ControlSet") or row.get("controlset") or ""
                if not path:
                    continue
                yield {
                    "type": "execution",
                    "path": path,
                    "last_modified": ts or None,
                    "executed": executed or None,
                    "controlset": controlset or None,
                    "artifact_source": "shimcache",
                }


# ----------------------------- Amcache -----------------------------

# Amcache produces several CSV files — we only want file execution entries.
_AMCACHE_FILE_MARKERS = ("applicationfile", "unassociatedfile", "fileentry")


def collect_amcache(amcache_hive: str, base_dir: str) -> Iterator[dict]:
    dll = os.path.join(base_dir, "AmcacheParser.dll")
    if not os.path.isfile(dll):
        print(f"[zimm_exec] AmcacheParser.dll not found: {dll}", file=sys.stderr)
        return
    if not amcache_hive or not os.path.isfile(amcache_hive):
        print(f"[zimm_exec] Amcache.hve not found: {amcache_hive!r}", file=sys.stderr)
        return

    with tempfile.TemporaryDirectory(prefix="dfir_amc_") as tmp:
        _dotnet(dll, ["-f", amcache_hive, "--csv", tmp, "--nl"])
        for fname, rows in _read_csv_files(tmp):
            fname_lower = fname.lower()
            if not any(m in fname_lower for m in _AMCACHE_FILE_MARKERS):
                continue
            for row in rows:
                path = row.get("FullPath") or row.get("Path") or row.get("path") or \
                       row.get("ApplicationName") or ""
                sha256 = row.get("Sha256") or row.get("sha256") or \
                         row.get("FileID") or row.get("fileid") or ""
                ts     = row.get("FileKeyLastWriteTimestamp") or \
                         row.get("LastModifiedDateTimeUtc") or \
                         row.get("DateTime") or ""
                link_date = row.get("LinkDate") or row.get("linkdate") or ""
                company   = row.get("CompanyName") or row.get("companyname") or ""
                if not path and not sha256:
                    continue
                rec = {
                    "type": "execution",
                    "path": path or None,
                    "last_modified": ts or None,
                    "link_date": link_date or None,
                    "company": company or None,
                    "artifact_source": "amcache",
                }
                if sha256:
                    prefix = "sha256:" if not sha256.startswith("sha256:") else ""
                    rec["hash"] = prefix + sha256.lower()
                yield rec


# ----------------------------- Orchestration -----------------------------

def run_from_config(config: dict, out_dir: str) -> dict:
    zimm = config.get("zimmerman_tools") or {}
    base_dir = zimm.get("base_dir") or "/opt/zimmermantools"
    exec_cfg  = config.get("execution") or {}
    system_hive  = exec_cfg.get("system_hive") or ""
    amcache_hive = exec_cfg.get("amcache") or ""
    max_recs = config.get("max_records")

    out_shim = os.path.join(out_dir, "registry_shimcache.txt")
    out_amc  = os.path.join(out_dir, "amcache_records.txt")

    n_shim = _c.write_records_to_file(
        collect_shimcache(system_hive, base_dir), out_shim, limit=max_recs)
    n_amc  = _c.write_records_to_file(
        collect_amcache(amcache_hive, base_dir), out_amc, limit=max_recs)

    print(f"[zimm_exec] shimcache={n_shim} amcache={n_amc}", file=sys.stderr)
    return {
        "output_files": [out_shim, out_amc],
        "record_count": n_shim + n_amc,
    }
