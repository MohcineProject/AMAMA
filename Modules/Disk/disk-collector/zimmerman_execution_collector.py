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
import struct
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


# ─────────────────── Python-registry fallbacks ───────────────────────────────

def _shimcache_python(system_hive: str) -> Iterator[dict]:
    """Parse AppCompatCache from SYSTEM hive binary value using python-registry.

    Supports Windows 10/11 format only (magic b'CACHE' at offset 0).
    Older formats (Win7/Vista) emit a warning and yield nothing — this matches
    the current behaviour when AppCompatCacheParser.dll is unavailable.
    """
    try:
        from Registry import Registry
    except ImportError:
        print("[zimm_exec] python-registry not installed; cannot parse shimcache",
              file=sys.stderr)
        return

    if not system_hive or not os.path.isfile(system_hive):
        return

    try:
        reg = Registry.Registry(system_hive)
    except Exception as e:
        print(f"[zimm_exec] Cannot open SYSTEM hive: {e}", file=sys.stderr)
        return

    data: Optional[bytes] = None
    controlset_used = ""
    for ccs in ("ControlSet001", "ControlSet002", "CurrentControlSet"):
        key_path = rf"{ccs}\Control\Session Manager\AppCompatCache"
        try:
            key = reg.open(key_path)
            raw = key.value("AppCompatCache").value()
            if isinstance(raw, bytes) and raw:
                data = raw
                controlset_used = ccs
                break
        except Exception:
            continue

    if data is None:
        print("[zimm_exec] AppCompatCache value not found in any ControlSet", file=sys.stderr)
        return

    # Supported AppCompatCache binary formats (both use a 128-byte header and the
    # same per-entry layout):
    #   Win10 / Server 2016+          magic b"CACH" (4 bytes ASCII)
    #   Win8 / Server 2012 / 2012 R2  magic b"\x80\x00\x00\x00"
    #
    # Per-entry layout (little-endian):
    #   offset +0:  uint16 data_size  (extra data after the path)
    #   offset +2:  uint16 flags
    #   offset +4:  uint64 filetime   (Windows FILETIME)
    #   offset +12: uint16 path_len   (byte length of UTF-16LE path string)
    #   offset +14: <path_len bytes>  path (UTF-16LE)
    #   offset +14+path_len: <data_size bytes> extra data
    magic = data[:4]
    if magic == b"CACH":
        pass  # Win10 / Server 2016+
    elif magic == b"\x80\x00\x00\x00":
        pass  # Win8 / Server 2012 / Server 2012 R2
    else:
        print(
            f"[zimm_exec] AppCompatCache: unrecognised magic {magic!r} "
            "(not Win10/11 or Win8/Server2012R2) — shimcache fallback skipped",
            file=sys.stderr,
        )
        return

    offset = 128  # fixed 128-byte header for all supported formats
    while offset < len(data):
        try:
            data_size = struct.unpack_from("<H", data, offset)[0]
            filetime  = struct.unpack_from("<Q", data, offset + 4)[0]
            path_len  = struct.unpack_from("<H", data, offset + 12)[0]
            if path_len == 0:
                break
            path = data[offset + 14: offset + 14 + path_len].decode(
                "utf-16-le", errors="replace")
            ts = _c.to_iso8601(_c.windows_filetime_to_utc(filetime))
            yield {
                "type": "execution",
                "path": path,
                "last_modified": ts or None,
                "executed": None,
                "controlset": controlset_used,
                "artifact_source": "shimcache",
            }
            offset += 14 + path_len + data_size
        except struct.error:
            break


def _amcache_python(amcache_hive: str) -> Iterator[dict]:
    """Parse Amcache.hve via python-registry.

    Amcache.hve is a Windows registry hive. Supports both the modern
    InventoryApplicationFile format (Win10+) and the older Root\\File format.
    Yields nothing gracefully if the hive is corrupt or unavailable.
    """
    try:
        from Registry import Registry
    except ImportError:
        print("[zimm_exec] python-registry not installed; cannot parse Amcache",
              file=sys.stderr)
        return

    if not amcache_hive or not os.path.isfile(amcache_hive):
        return

    try:
        reg = Registry.Registry(amcache_hive)
    except Exception as e:
        print(f"[zimm_exec] Cannot open Amcache.hve: {e}", file=sys.stderr)
        return

    def _val(key, name: str) -> str:
        try:
            return str(key.value(name).value() or "")
        except Exception:
            return ""

    def _ts(key) -> str:
        try:
            import datetime as _dt
            t = key.timestamp()
            if t.tzinfo is None:
                t = t.replace(tzinfo=_dt.timezone.utc)
            return _c.to_iso8601(t)
        except Exception:
            return ""

    # Modern format: Root\InventoryApplicationFile (Win8.1 / Win10+)
    inv_key = None
    try:
        inv_key = reg.open("Root\\InventoryApplicationFile")
    except Exception:
        pass

    seen: set = set()

    def _dedup_key(path: str, hash_val: str) -> tuple:
        return (path.lower() if path else "", hash_val.lower() if hash_val else "")

    if inv_key is not None:
        for subkey in inv_key.subkeys():
            try:
                path = _val(subkey, "FullPath") or _val(subkey, "Name")
                sha256 = _val(subkey, "Sha256")
                link_date = _val(subkey, "LinkDate")
                company = _val(subkey, "CompanyName")
                ts = _ts(subkey)
                if not path and not sha256:
                    continue
                dk = _dedup_key(path, sha256)
                if dk in seen:
                    continue
                seen.add(dk)
                rec = {
                    "type": "execution",
                    "path": path or None,
                    "last_modified": ts or None,
                    "link_date": link_date or None,
                    "company": company or None,
                    "artifact_source": "amcache",
                }
                if sha256:
                    prefix = "" if sha256.startswith("sha256:") else "sha256:"
                    rec["hash"] = prefix + sha256.lower()
                yield rec
            except Exception:
                continue
        return  # do not fall through to old format if key existed

    # Older format: Root\File\{volume-guid}\{sequence} (Win7/Win8)
    try:
        root_file = reg.open("Root\\File")
    except Exception:
        print("[zimm_exec] Amcache.hve: no known key structure found", file=sys.stderr)
        return

    for volume_key in root_file.subkeys():
        for entry in volume_key.subkeys():
            try:
                path = _val(entry, "15") or _val(entry, "17")  # field indices vary
                sha1 = _val(entry, "101")
                link_date = _val(entry, "f")
                ts = _ts(entry)
                if not path and not sha1:
                    continue
                dk = _dedup_key(path, sha1)
                if dk in seen:
                    continue
                seen.add(dk)
                rec = {
                    "type": "execution",
                    "path": path or None,
                    "last_modified": ts or None,
                    "link_date": link_date or None,
                    "company": None,
                    "artifact_source": "amcache",
                }
                if sha1:
                    rec["hash"] = "sha1:" + sha1.lower()
                yield rec
            except Exception:
                continue


# ----------------------------- Shimcache -----------------------------

def collect_shimcache(system_hive: str, base_dir: str) -> Iterator[dict]:
    dll = os.path.join(base_dir, "AppCompatCacheParser.dll")
    if not os.path.isfile(dll) or not _c.dotnet_available():
        reason = "DLL not found" if not os.path.isfile(dll) else "dotnet unavailable"
        print(f"[zimm_exec] AppCompatCacheParser not available ({reason}) "
              "— using python-registry shimcache fallback", file=sys.stderr)
        yield from _shimcache_python(system_hive)
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
    if not os.path.isfile(dll) or not _c.dotnet_available():
        reason = "DLL not found" if not os.path.isfile(dll) else "dotnet unavailable"
        print(f"[zimm_exec] AmcacheParser not available ({reason}) "
              "— using python-registry amcache fallback", file=sys.stderr)
        yield from _amcache_python(amcache_hive)
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
