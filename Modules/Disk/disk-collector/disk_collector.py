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
import sys
import traceback
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


_RUNNERS = {
    "mft":         _mft.run_from_config,
    "eventlog":    _evt.run_from_config,    # python-evtx (slow on archives)
    "execution":   _exec.run_from_config,   # prefetch only
    "persistence": _pers.run_from_config,
    "browser":     _brow.run_from_config,
    "zregistry":   _zreg.run_from_config,   # RECmd + DFIRBatch.reb (replaces registry_collector)
    "zexecution":  _zexec.run_from_config,  # AppCompatCacheParser + AmcacheParser
    "zevtx":       _zevtx.run_from_config,  # EvtxECmd (replaces eventlog — fast, handles archives)
}


def run(config: dict, out_dir: str, only: List[str]) -> Dict[str, dict]:
    os.makedirs(out_dir, exist_ok=True)
    selected = only or list(_RUNNERS.keys())
    summary: Dict[str, dict] = {}
    for name in selected:
        runner = _RUNNERS.get(name)
        if runner is None:
            summary[name] = {"error": f"unknown collector: {name}"}
            continue
        print(f"[disk_collector] === {name} ===", file=sys.stderr)
        try:
            summary[name] = runner(config, out_dir)
        except Exception as e:
            tb = traceback.format_exc(limit=3)
            summary[name] = {"error": str(e), "traceback": tb}
            print(f"[disk_collector] {name} failed: {e}", file=sys.stderr)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run every disk-forensics sub-collector in-process."
    )
    parser.add_argument("--config", required=True,
                        help="Path to config.json (see disk-collector/config.example.json)")
    parser.add_argument("--only", nargs="*",
                        choices=list(_RUNNERS.keys()),
                        help="Only run these collectors (default: all)")
    parser.add_argument("--out-dir", default="Disk_Artifacts",
                        help="Output directory (default: Disk_Artifacts)")
    parser.add_argument("--summary-out", default=None,
                        help="Optional: also write the JSON summary to this path")
    parser.add_argument("--max-records", type=int, default=None,
                        help="Stop each collector after this many records (for quick testing)")
    parser.add_argument("--triage-mode", action="store_true",
                        help="Enable aggressive filtering: MFT suspicious-paths only, "
                             "event log archives capped to last 30 days")
    args = parser.parse_args()

    config = _c.load_json(args.config)
    if args.max_records is not None:
        config["max_records"] = args.max_records
    if args.triage_mode:
        config["mft_write_only_suspicious"] = True
        if config.get("max_archive_age_days") is None:
            config["max_archive_age_days"] = 30
    summary = run(config, args.out_dir, args.only or [])

    out = json.dumps(summary, indent=2, default=str)
    print(out)
    if args.summary_out:
        with open(args.summary_out, "w", encoding="utf-8") as f:
            f.write(out)


if __name__ == "__main__":
    main()
