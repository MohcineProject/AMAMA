"""Top-level disk-forensics collector orchestrator.

Invokes every sub-collector in-process (no subprocesses), each from its
`run_from_config(config, out_dir)` entrypoint. Failures in one sub-collector
do not abort the others — each error is reported in the JSON summary.

Usage:
  python disk_collector.py --config disk-collector/config.example.json
  python disk_collector.py --config <cfg> --only mft browser
  python disk_collector.py --config <cfg> --out-dir /tmp/artifacts
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _common as _c  # type: ignore
    import mft_collector as _mft
    import eventlog_collector as _evt
    import execution_collector as _exec
    import persistence_collector as _pers
    import browser_collector as _brow
    import zimmerman_registry_collector as _zreg
    import zimmerman_execution_collector as _zexec
    import zimmerman_eventlog_collector as _zevtx
else:
    from . import _common as _c
    from . import mft_collector as _mft
    from . import eventlog_collector as _evt
    from . import execution_collector as _exec
    from . import persistence_collector as _pers
    from . import browser_collector as _brow
    from . import zimmerman_registry_collector as _zreg
    from . import zimmerman_execution_collector as _zexec
    from . import zimmerman_eventlog_collector as _zevtx


# Phase 1: fast collectors — run in parallel (blocking). Agent 1 uses their output.
_PHASE1_RUNNERS = {
    "persistence": _pers.run_from_config,   # pure Python XML/WMI
    "browser":     _brow.run_from_config,   # SQLite read-only
    "execution":   _exec.run_from_config,   # pyscca prefetch
    "zregistry":   _zreg.run_from_config,   # RECmd or python-registry
}

# Phase 2: slow collectors — run in parallel (background thread). Agent 2 uses their output.
_PHASE2_RUNNERS = {
    "mft":         _mft.run_from_config,    # SLOWEST: full MFT parse
    "zevtx":       _zevtx.run_from_config,  # EvtxECmd or python-evtx
    "zexecution":  _zexec.run_from_config,  # AppCompatCacheParser + AmcacheParser
}

# Kept for --only backward-compat (direct access to any collector by name)
_RUNNERS = {
    "mft":         _mft.run_from_config,
    "eventlog":    _evt.run_from_config,
    "execution":   _exec.run_from_config,
    "persistence": _pers.run_from_config,
    "browser":     _brow.run_from_config,
    "zregistry":   _zreg.run_from_config,
    "zexecution":  _zexec.run_from_config,
    "zevtx":       _zevtx.run_from_config,
}

_FALLBACK_WARNED = False


def _warn_fallback_once() -> None:
    global _FALLBACK_WARNED
    if not _FALLBACK_WARNED and not _c.dotnet_available():
        print(
            "[disk_collector] WARNING: dotnet/Zimmerman not available. "
            "Python fallbacks active for zregistry, zexecution, zevtx. "
            "Run install.sh to enable full Zimmerman coverage.",
            file=sys.stderr,
        )
        _FALLBACK_WARNED = True


def _write_sentinel(out_dir: str, name: str) -> None:
    try:
        with open(os.path.join(out_dir, f".{name}"), "w") as f:
            f.write(_c.now_iso())
    except OSError:
        pass


def _run_one(name: str, runner, config: dict, out_dir: str) -> dict:
    print(f"[disk_collector] === {name} ===", file=sys.stderr)
    return runner(config, out_dir)


def _run_phase(config: dict, out_dir: str, runners: dict,
               workers: int, label: str) -> Dict[str, dict]:
    summary: Dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_run_one, name, fn, dict(config), out_dir): name
            for name, fn in runners.items()
        }
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                summary[name] = fut.result()
            except Exception as e:
                tb = traceback.format_exc(limit=3)
                summary[name] = {"error": str(e), "traceback": tb}
                print(f"[disk_collector] [{label}] {name} failed: {e}", file=sys.stderr)
    return summary


def _run_sequential(config: dict, out_dir: str, names: List[str]) -> Dict[str, dict]:
    """Run the given collector names sequentially (used by --only)."""
    summary: Dict[str, dict] = {}
    for name in names:
        runner = _RUNNERS.get(name)
        if runner is None:
            summary[name] = {"error": f"unknown collector: {name}"}
            continue
        try:
            summary[name] = _run_one(name, runner, config, out_dir)
        except Exception as e:
            tb = traceback.format_exc(limit=3)
            summary[name] = {"error": str(e), "traceback": tb}
            print(f"[disk_collector] {name} failed: {e}", file=sys.stderr)
    return summary


def run(config: dict, out_dir: str, only: List[str],
        mode: str = "fast", workers: int = 4) -> Dict[str, dict]:
    os.makedirs(out_dir, exist_ok=True)
    _warn_fallback_once()

    # --only: backward-compatible sequential run
    if only:
        return _run_sequential(config, out_dir, only)

    # Build a mode-specific config copy (no cross-thread mutation)
    cfg = dict(config)
    if mode == "fast":
        cfg.setdefault("mft_write_only_suspicious", True)
        cfg["mft_fast_mode"] = True
        if cfg.get("max_archive_age_days") is None:
            cfg["max_archive_age_days"] = 30

    # Phase 1: parallel, blocking
    print("[disk_collector] Phase 1 starting (persistence / browser / execution / registry)...",
          file=sys.stderr)
    phase1 = _run_phase(cfg, out_dir, _PHASE1_RUNNERS, workers=workers, label="Phase 1")
    _write_sentinel(out_dir, "phase1_done")
    print("[disk_collector] Phase 1 complete.", file=sys.stderr)

    # Phase 2: parallel, background thread
    phase2_done: threading.Event = threading.Event()
    phase2_results: Dict[str, dict] = {}

    def _run_phase2_bg() -> None:
        try:
            print("[disk_collector] Phase 2 starting (mft / zevtx / zexecution)...",
                  file=sys.stderr)
            phase2_results.update(
                _run_phase(cfg, out_dir, _PHASE2_RUNNERS, workers=workers, label="Phase 2")
            )
            print("[disk_collector] Phase 2 complete.", file=sys.stderr)
        finally:
            phase2_done.set()
            _write_sentinel(out_dir, "phase2_done")

    threading.Thread(target=_run_phase2_bg, name="disk-phase2", daemon=True).start()

    return {
        "phase1": phase1,
        "phase2_event": phase2_done,
        "phase2_results": phase2_results,
    }


def check_deps(config: dict) -> None:
    """Print a status table of all runtime dependencies and exit."""
    zimm = (config.get("zimmerman_tools") or {})
    base_dir = zimm.get("base_dir") or "/opt/zimmermantools"

    rows: list[tuple[str, bool, str]] = [
        ("dotnet",            _c.dotnet_available(),
         "add Microsoft APT repo + apt install dotnet-sdk-9.0"),
        ("RECmd.dll",         os.path.isfile(os.path.join(base_dir, "RECmd/RECmd.dll")),
         "Zimmerman tools (install.sh)"),
        ("EvtxECmd.dll",      os.path.isfile(os.path.join(base_dir, "EvtxeCmd/EvtxECmd.dll")),
         "Zimmerman tools (install.sh)"),
        ("AppCompatCacheP.",  os.path.isfile(os.path.join(base_dir, "AppCompatCacheParser.dll")),
         "Zimmerman tools (install.sh)"),
        ("AmcacheParser.dll", os.path.isfile(os.path.join(base_dir, "AmcacheParser.dll")),
         "Zimmerman tools (install.sh)"),
        ("ewfmount",          bool(shutil.which("ewfmount")),   "apt install ewf-tools"),
        ("mmls / icat",       bool(shutil.which("mmls")),       "apt install sleuthkit"),
        ("ntfs-3g",           bool(shutil.which("ntfs-3g")),    "apt install ntfs-3g"),
        ("qemu-nbd",          bool(shutil.which("qemu-nbd")),   "apt install qemu-utils"),
    ]

    # Python packages
    for pkg, mod in [("python-registry", "Registry"),
                     ("python-evtx",     "Evtx.Evtx"),
                     ("pyscca",          "pyscca"),
                     ("pefile",          "pefile")]:
        try:
            __import__(mod)
            rows.append((pkg, True, "pip install -r requirements.txt"))
        except ImportError:
            rows.append((pkg, False, "run install.sh first"))

    print("\nDependency status:")
    for name, ok, fix in rows:
        status = "OK      " if ok else f"MISSING  → {fix}"
        print(f"  {name:<22} {status}")

    mode = "FULL (dotnet + Zimmerman)" if _c.dotnet_available() else "PYTHON-FALLBACK"
    print(f"\nMode: {mode}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run disk-forensics collectors in parallel phases."
    )
    parser.add_argument("--config", required=True,
                        help="Path to config.json (see disk-collector/config.example.json)")
    parser.add_argument("--only", nargs="*",
                        choices=list(_RUNNERS.keys()),
                        help="Run only these collectors sequentially (default: all in phases)")
    parser.add_argument("--out-dir", default="Disk_Artifacts",
                        help="Output directory (default: Disk_Artifacts)")
    parser.add_argument("--summary-out", default=None,
                        help="Also write the JSON summary to this path")
    parser.add_argument("--max-records", type=int, default=None,
                        help="Stop each collector after N records (for quick testing)")
    parser.add_argument("--workers", type=int, default=4,
                        help="Parallel workers per phase (default: 4)")
    parser.add_argument("--check-deps", action="store_true",
                        help="Print dependency status and exit")

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--fast", dest="mode", action="store_const", const="fast", default="fast",
        help="Fast mode: Phase 1 parallel + MFT suspicious-paths only + skip PE analysis (default)",
    )
    mode_group.add_argument(
        "--full", dest="mode", action="store_const", const="full",
        help="Full mode: Phase 1 parallel + complete MFT parse with PE analysis",
    )

    args = parser.parse_args()

    config = _c.load_json(args.config)

    if args.check_deps:
        check_deps(config)
        return

    if args.max_records is not None:
        config["max_records"] = args.max_records

    result = run(config, args.out_dir, args.only or [],
                 mode=args.mode, workers=args.workers)

    # If phases are running, wait for Phase 2 before writing summary
    if isinstance(result, dict) and "phase2_event" in result:
        phase2_event: threading.Event = result["phase2_event"]
        if not phase2_event.is_set():
            print("[disk_collector] Waiting for Phase 2 to finish...", file=sys.stderr)
            phase2_event.wait()
        summary = {**result["phase1"], **result["phase2_results"]}
    else:
        summary = result  # type: ignore[assignment]

    out = json.dumps(summary, indent=2, default=str)
    print(out)
    if args.summary_out:
        with open(args.summary_out, "w", encoding="utf-8") as f:
            f.write(out)


if __name__ == "__main__":
    main()
