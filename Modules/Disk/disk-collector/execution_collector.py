"""Prefetch collector.

Amcache and shimcache are handled by zimmerman_execution_collector.py
(AppCompatCacheParser + AmcacheParser via dotnet).

Produces:
  Disk_Artifacts/prefetch_records.txt — one record per .pf file

Library dependencies:
  - libscca-python (pyscca): REQUIRED for Win10/11 (XPRESS-Huffman-compressed prefetch).
    Without pyscca, falls back to header-only metadata for uncompressed files.
"""
from __future__ import annotations

import os
import struct
import sys
from typing import Iterator, List

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _common as _c  # type: ignore
else:
    from . import _common as _c

try:
    import pyscca
    _HAS_SCCA = True
except ImportError:
    pyscca = None  # type: ignore
    _HAS_SCCA = False


# -------------------------- Prefetch --------------------------

def _parse_prefetch_libscca(pf_path: str) -> List[dict]:
    """Use pyscca to extract executable name + run count + last 8 run times."""
    out: List[dict] = []
    try:
        f = pyscca.file()
        f.open(pf_path)
    except Exception as e:
        print(f"[execution_collector] pyscca failed on {pf_path}: {e}", file=sys.stderr)
        return out
    try:
        exec_name = f.get_executable_filename() or ""
        run_count = f.get_run_count() or 0
        last_run_times: List[str] = []
        for i in range(8):
            try:
                t = f.get_last_run_time(i)
                if t is None:
                    continue
                last_run_times.append(_c.to_iso8601(t))
            except Exception:
                continue
        last_run = last_run_times[0] if last_run_times else ""
        out.append({
            "type": "execution",
            "path": exec_name,
            "last_run": last_run,
            "run_count": run_count,
            "previous_runs": ";".join(last_run_times[1:]) if len(last_run_times) > 1 else None,
            "artifact_source": "prefetch",
            "source_file": os.path.basename(pf_path),
        })
    finally:
        try:
            f.close()
        except Exception:
            pass
    return out


_PREFETCH_HEADER_FMT = "<I4sI"   # version (4), 'SCCA' (4), file size (4)


def _parse_prefetch_header_only(pf_path: str) -> List[dict]:
    """Header-only fallback when pyscca is unavailable.

    Uncompressed prefetch (Win XP–7): read version + executable name at offset 16.
    Win 8+ MAM-compressed: record filename and a needs_libscca marker.
    """
    out: List[dict] = []
    try:
        with open(pf_path, "rb") as f:
            head = f.read(8)
    except OSError:
        return out

    if head[:4] == b"MAM\x04":
        out.append({
            "type": "execution",
            "path": "",
            "last_run": "",
            "run_count": None,
            "artifact_source": "prefetch",
            "source_file": os.path.basename(pf_path),
            "needs_libscca": True,
        })
        return out

    try:
        with open(pf_path, "rb") as f:
            version, signature, _size = struct.unpack(_PREFETCH_HEADER_FMT, f.read(12))
            if signature != b"SCCA":
                return out
            f.seek(16)
            name_bytes = f.read(60)
            name = name_bytes.decode("utf-16le", errors="replace").rstrip("\x00")
            last_run_iso = ""
            run_count = None
            try:
                if version == 17:   # Windows XP
                    f.seek(0x78)
                    ft = struct.unpack("<Q", f.read(8))[0]
                    f.seek(0x90)
                    run_count = struct.unpack("<I", f.read(4))[0]
                elif version == 23:  # Vista / 7
                    f.seek(0x80)
                    ft = struct.unpack("<Q", f.read(8))[0]
                    f.seek(0x98)
                    run_count = struct.unpack("<I", f.read(4))[0]
                else:
                    ft = 0
                if ft:
                    last_run_iso = _c.to_iso8601(_c.windows_filetime_to_utc(ft))
            except Exception:
                pass
            out.append({
                "type": "execution",
                "path": name,
                "last_run": last_run_iso,
                "run_count": run_count,
                "artifact_source": "prefetch",
                "source_file": os.path.basename(pf_path),
                "version": version,
            })
    except Exception as e:
        print(f"[execution_collector] header-only parse failed: {e}", file=sys.stderr)
    return out


def collect_prefetch(prefetch_dir: str) -> Iterator[dict]:
    if not os.path.isdir(prefetch_dir):
        return
    if not _HAS_SCCA:
        print("[execution_collector] WARNING: pyscca not installed; prefetch "
              "parsing will be header-only for uncompressed files.", file=sys.stderr)
    for entry in sorted(os.listdir(prefetch_dir)):
        if not entry.lower().endswith(".pf"):
            continue
        full = os.path.join(prefetch_dir, entry)
        recs = _parse_prefetch_libscca(full) if _HAS_SCCA else _parse_prefetch_header_only(full)
        yield from recs


# -------------------------- Public API --------------------------

def run_from_config(config: dict, out_dir: str) -> dict:
    section = config.get("execution") or {}
    prefetch_dir = section.get("prefetch_dir")
    limit = config.get("max_records")

    if not prefetch_dir or not os.path.isdir(prefetch_dir):
        return {"error": f"execution.prefetch_dir not found: {prefetch_dir!r}",
                "output_files": [], "record_count": 0}

    out_path = os.path.join(out_dir, "prefetch_records.txt")
    n = _c.write_records_to_file(collect_prefetch(prefetch_dir), out_path, limit=limit)
    return {"output_files": [out_path], "record_count": n}


def main() -> None:
    parser = _c.setup_cli(
        "Collect prefetch execution evidence.",
        default_out="Disk_Artifacts/",
    )
    parser.add_argument("--prefetch-dir", default=None)
    args = parser.parse_args()
    config = _c.load_json(args.config) if args.config else {}
    if args.prefetch_dir:
        config.setdefault("execution", {})["prefetch_dir"] = args.prefetch_dir
    res = run_from_config(config, args.out if os.path.isdir(args.out) else "Disk_Artifacts")
    print(f"[execution_collector] wrote {res['record_count']} records → {res['output_files']}")


if __name__ == "__main__":
    main()
