#!/usr/bin/env python3
"""
End-to-end RAM forensic pipeline: extract → collect → analyse.

Optimised flow:
  Phase 1  Mandatory Volatility plugins run first (parallel, blocking).
  Phase 2  Extended plugins launch in a background thread.
  Phase 3  Collector runs immediately (reads mandatory artifacts → chunks).
  Phase 4  Per chunk: Agent 1 starts right away; pivot grep waits for the
           extended-plugins event; Agent 2 follows.
  Phase 5  Aggregate → scan_result.json.

Extraction modes (--fast is the default):
  --fast   Mandatory (9) + fast-extended (15) = 24 plugins.
           Covers all pivot-grep file lists.  ~5–10 min, 4 workers.
  --full   Mandatory + fast-extended + full-extended = ~65 plugins.
           Adds kernel, VAD, full registry, extra malware variants.
           ~15–25 min, 4 workers.

The existing run_pipeline.py (assumes artifacts + chunks already present) is
unchanged — still useful for partial/test runs.

Usage:
  python full_pipeline.py --image /path/to/image.elf [options]
  python full_pipeline.py --image /path/to/image.elf --fast --no-handles --no-llm
  python full_pipeline.py --image /path/to/image.elf --full --workers 8
"""

from __future__ import annotations

import argparse
import glob
import logging
import os
import shutil
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

_RAM_DIR = os.path.dirname(os.path.abspath(__file__))
_SCRIPTS_DIR = os.path.join(_RAM_DIR, "ram-agentic-architecture", "scripts")
_COLLECTOR_DIR = os.path.join(_RAM_DIR, "ram-collector")

# Allow `import extractor` and `from collector import run_collector`
for _p in (_RAM_DIR, _COLLECTOR_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _run(cmd: list) -> None:
    subprocess.check_call(cmd)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="End-to-end RAM forensic pipeline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--image", required=True, metavar="PATH",
        help="Path to Windows memory image (.elf, .img, .vmem, …).",
    )

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--fast", dest="mode", action="store_const", const="fast", default="fast",
        help="Fast mode: mandatory + fast-extended = 24 plugins (default).",
    )
    mode_group.add_argument(
        "--full", dest="mode", action="store_const", const="full",
        help="Full mode: mandatory + fast-extended + full-extended (~65 plugins).",
    )

    parser.add_argument(
        "--artifacts-dir",
        default=os.path.join(_RAM_DIR, "RAM_Artifacts"),
        metavar="DIR",
        help="Directory for Volatility output files (default: RAM/RAM_Artifacts/).",
    )
    parser.add_argument(
        "--input-dir",
        default=os.path.join(_RAM_DIR, "INPUT"),
        metavar="DIR",
        help="Directory for collector chunks (default: RAM/INPUT/).",
    )
    parser.add_argument(
        "--out-dir",
        default=os.path.join(_RAM_DIR, "ram-agentic-architecture", "output"),
        metavar="DIR",
        help="Pipeline output root (default: ram-agentic-architecture/output/).",
    )
    parser.add_argument("--case-id", default="local-test",
                        help="Case identifier stamped in scan_result.json.")
    parser.add_argument(
        "--vol-path", default=None, metavar="PATH",
        help="Path to vol.py — overrides VOL3_PATH env var.",
    )
    parser.add_argument(
        "--no-handles", action="store_true",
        help="Skip windows.handles.Handles from mandatory plugins (faster collector start).",
    )
    parser.add_argument(
        "--no-llm", action="store_true",
        help="Rule-based fallback only — disables all LLM calls.",
    )
    parser.add_argument(
        "--workers", type=int, default=4, metavar="N",
        help="Parallel Volatility workers per phase (default: 4).",
    )
    parser.add_argument(
        "--config",
        default=os.path.join(_RAM_DIR, "ram-agentic-architecture", "config.json"),
        metavar="PATH",
    )
    parser.add_argument(
        "--llm-config",
        default=os.path.join(_RAM_DIR, "ram-agentic-architecture", "llm_config.json"),
        metavar="PATH",
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        stream=sys.stderr,
    )

    if args.vol_path:
        os.environ["VOL3_PATH"] = args.vol_path

    import extractor
    from collector import run_collector

    image_path = str(Path(args.image).expanduser().resolve())
    artifacts_dir = Path(args.artifacts_dir)
    input_dir = Path(args.input_dir)
    out_dir = Path(args.out_dir)

    # Clean artifacts and chunks from any previous run before starting fresh.
    for d in (artifacts_dir, input_dir):
        if d.exists():
            shutil.rmtree(d)
    for d in (artifacts_dir, input_dir, out_dir):
        d.mkdir(parents=True, exist_ok=True)

    started_at = _now_iso()
    _banner(args, image_path, artifacts_dir, input_dir, out_dir)

    # ------------------------------------------------------------------
    # Phase 1: Mandatory plugins (blocking — collector needs these)
    # ------------------------------------------------------------------
    _section("Phase 1/5 — Mandatory plugins")
    extractor.run_mandatory(
        image_path, artifacts_dir,
        no_handles=args.no_handles,
        workers=args.workers,
    )
    print("[full_pipeline] Phase 1 complete.", file=sys.stderr)

    # ------------------------------------------------------------------
    # Phase 2: Extended plugins in a background thread
    # ------------------------------------------------------------------
    _section("Phase 2/5 — Extended plugins (background)")
    extended_done = threading.Event()
    extended_errors: list[Exception] = []

    def _run_extended_bg() -> None:
        try:
            if args.mode == "full":
                extractor.run_full_extended(image_path, artifacts_dir, workers=args.workers)
            else:
                extractor.run_fast_extended(image_path, artifacts_dir, workers=args.workers)
        except Exception as exc:
            extended_errors.append(exc)
            logging.getLogger(__name__).error("[full_pipeline] Extended plugins failed: %s", exc)
        finally:
            extended_done.set()
            print("\n[full_pipeline] Background: extended plugins finished.", file=sys.stderr)

    bg = threading.Thread(target=_run_extended_bg, name="extended-plugins", daemon=True)
    bg.start()
    print(
        f"[full_pipeline] {args.mode.upper()} extended plugins running in background "
        f"({args.workers} workers).",
        file=sys.stderr,
    )

    # ------------------------------------------------------------------
    # Phase 3: Collector (reads mandatory artifacts → writes chunks)
    # ------------------------------------------------------------------
    _section("Phase 3/5 — Collector")
    n_chunks = run_collector(
        folder_path=str(artifacts_dir),
        output_dir=str(input_dir),
        include_handles=not args.no_handles,
        force=True,
    )
    if n_chunks == 0:
        print("[full_pipeline] ERROR: Collector produced no chunks. Check logs.", file=sys.stderr)
        sys.exit(1)
    print(f"[full_pipeline] Collector wrote {n_chunks} chunk(s) to {input_dir}.", file=sys.stderr)

    # ------------------------------------------------------------------
    # Phase 4: Per-chunk pipeline (Agent 1 → wait → pivot grep → Agent 2)
    # ------------------------------------------------------------------
    _section(f"Phase 4/5 — Pipeline ({n_chunks} chunk(s))")

    chunks = sorted(glob.glob(str(input_dir / "chunk_*.txt")))
    if not chunks:
        print("[full_pipeline] ERROR: No chunk files found in input_dir.", file=sys.stderr)
        sys.exit(1)

    triage_script  = os.path.join(_SCRIPTS_DIR, "triage_agent.py")
    pivot_script   = os.path.join(_SCRIPTS_DIR, "pivot_grep.py")
    analyst_script = os.path.join(_SCRIPTS_DIR, "pivot_analyst.py")

    analyst_files: list[tuple[int, str, str]] = []

    for idx, chunk_path in enumerate(chunks, start=1):
        chunk_name  = os.path.basename(chunk_path)
        chunk_label = os.path.splitext(chunk_name)[0]
        chunk_out   = out_dir / chunk_label
        chunk_out.mkdir(exist_ok=True)

        triage_path  = str(chunk_out / "triage.txt")
        pivot_path   = str(chunk_out / "pivot.txt")
        analyst_path = str(chunk_out / "analyst.txt")

        print(
            f"\n[full_pipeline] --- Chunk {idx}/{len(chunks)}: {chunk_name} ---",
            file=sys.stderr,
        )

        # Stage 1: Agent 1 — no dependency on extended plugins
        print("[full_pipeline]   Stage 1 — triage_agent.py", file=sys.stderr)
        triage_cmd = [
            sys.executable, triage_script,
            "--input",      chunk_path,
            "--out",        triage_path,
            "--llm-config", args.llm_config,
            "--config",     args.config,
        ]
        if args.no_llm:
            triage_cmd.append("--no-llm")
        _run(triage_cmd)

        # Stage 2: Pivot grep — wait for extended plugins if still running
        if not extended_done.is_set():
            print(
                "[full_pipeline]   Stage 2 — waiting for extended plugins…",
                file=sys.stderr,
            )
            extended_done.wait()
        print("[full_pipeline]   Stage 2 — pivot_grep.py", file=sys.stderr)
        _run([
            sys.executable, pivot_script,
            "--triage", triage_path,
            "--config", args.config,
            "--out",    pivot_path,
        ])

        # Stage 3: Agent 2
        print("[full_pipeline]   Stage 3 — pivot_analyst.py", file=sys.stderr)
        analyst_cmd = [
            sys.executable, analyst_script,
            "--triage",     triage_path,
            "--pivot",      pivot_path,
            "--out",        analyst_path,
            "--llm-config", args.llm_config,
        ]
        if args.no_llm:
            analyst_cmd.append("--no-llm")
        _run(analyst_cmd)

        analyst_files.append((idx, chunk_name, analyst_path))

    # ------------------------------------------------------------------
    # Phase 5: Aggregate + emit JSON
    # ------------------------------------------------------------------
    _section("Phase 5/5 — Aggregate + emit scan_result.json")

    aggregated_path = str(out_dir / "aggregated_analyst.txt")
    with open(aggregated_path, "w", encoding="utf-8") as agg:
        for idx, chunk_name, analyst_path in analyst_files:
            agg.write(f"=== CHUNK {idx}: {chunk_name} ===\n")
            try:
                with open(analyst_path, encoding="utf-8", errors="ignore") as f:
                    agg.write(f.read())
            except FileNotFoundError:
                agg.write(f"(analyst.txt not found for {chunk_name})\n")
            agg.write("\n")

    scan_result_path = str(out_dir / "scan_result.json")
    sys.path.insert(0, _SCRIPTS_DIR)
    from scan_result_emitter import emit_scan_result
    emit_scan_result(
        aggregated_path=aggregated_path,
        case_id=args.case_id,
        out_path=scan_result_path,
        per_chunk_paths=[ap for _, _, ap in analyst_files],
        started_at=started_at,
    )

    bg.join(timeout=5)

    print("\n[full_pipeline] === Pipeline complete ===", file=sys.stderr)
    print(f"  Mode             : {args.mode}", file=sys.stderr)
    print(f"  Case ID          : {args.case_id}", file=sys.stderr)
    print(f"  Chunks processed : {len(chunks)}", file=sys.stderr)
    print(f"  Artifacts dir    : {artifacts_dir}", file=sys.stderr)
    print(f"  Output root      : {out_dir}", file=sys.stderr)
    print(f"  Scan result JSON : {scan_result_path}", file=sys.stderr)
    if extended_errors:
        print(
            f"  WARNING: extended plugins had {len(extended_errors)} error(s) — "
            "see logs above.",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _section(title: str) -> None:
    print(f"\n[full_pipeline] {title}", file=sys.stderr)


def _banner(args, image_path, artifacts_dir, input_dir, out_dir) -> None:
    print("\n[full_pipeline] ===================================================", file=sys.stderr)
    print(f"[full_pipeline]  RAM Forensic Pipeline — {args.mode.upper()} mode", file=sys.stderr)
    print("[full_pipeline] ===================================================", file=sys.stderr)
    print(f"  Image        : {image_path}", file=sys.stderr)
    print(f"  Artifacts    : {artifacts_dir}", file=sys.stderr)
    print(f"  Chunks       : {input_dir}", file=sys.stderr)
    print(f"  Output       : {out_dir}", file=sys.stderr)
    print(f"  Case ID      : {args.case_id}", file=sys.stderr)
    print(f"  Workers      : {args.workers}", file=sys.stderr)
    print(f"  Handles      : {'skip' if args.no_handles else 'include'}", file=sys.stderr)
    print(f"  LLM          : {'disabled' if args.no_llm else 'enabled'}", file=sys.stderr)


if __name__ == "__main__":
    main()
