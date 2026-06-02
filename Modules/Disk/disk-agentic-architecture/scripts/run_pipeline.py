#!/usr/bin/env python3
"""
End-to-end pipeline runner.

Stages:
  1.  preprocess.py          → TRIAGE_INPUT_PERSISTENCE.txt
                                TRIAGE_INPUT_EVENTS.txt
                                TRIAGE_INPUT_MFT.txt
  2.  triage_agent --mode persistence → triage_persistence.txt
  2b. triage_agent --mode events      → triage_events.txt
  2c. triage_agent --mode mft         → triage_mft.txt
  2d. merge                           → triage_combined.txt
  3.  pivot_search.py        → pivot.txt
  4.  pivot_analyst.py       → analyst.txt

Usage:
    python run_pipeline.py [--base-dir <dir>] [--artifact-dir <dir>]
                           [--from-stage <1|2|3|4>] [--no-llm]

    --from-stage N   Skip stages before N.
    --no-llm         Dry-run the LLM stages (print prompts, don't call the API).
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
ARTIFACT_DIR = BASE_DIR.parent / "Disk_Artifacts"


def _run(label: str, cmd: list[str]) -> None:
    print(f"\n{'='*60}", flush=True)
    print(f"[pipeline] {label}", flush=True)
    print(f"[pipeline] $ {' '.join(cmd)}", flush=True)
    print(f"{'='*60}", flush=True)
    t0 = time.monotonic()
    result = subprocess.run(cmd, check=False)
    elapsed = time.monotonic() - t0
    if result.returncode != 0:
        sys.exit(f"[pipeline] Stage failed (rc={result.returncode}) after {elapsed:.1f}s — aborting.")
    print(f"[pipeline] Stage done in {elapsed:.1f}s", flush=True)


def _merge_triage_outputs(base: str, cfg: dict) -> None:
    """Concatenate the 3 specialized triage outputs into triage_combined.txt.

    Each [FINDING] block already has triage_source injected by triage_agent.py.
    The merge step concatenates them with source-labelled separators.
    """
    output_dir = os.path.normpath(os.path.join(base, cfg.get("output_dir", "output")))
    sources = [
        (os.path.join(base, cfg.get("triage_output_persistence", "output/triage_persistence.txt")), "persistence"),
        (os.path.join(base, cfg.get("triage_output_events",      "output/triage_events.txt")),      "events"),
        (os.path.join(base, cfg.get("triage_output_mft",         "output/triage_mft.txt")),         "mft"),
    ]
    combined_path = os.path.join(base, cfg.get("triage_combined", "output/triage_combined.txt"))
    os.makedirs(output_dir, exist_ok=True)

    total_findings = 0
    parts = []
    for source_path, source_name in sources:
        if not os.path.exists(source_path):
            print(f"[pipeline/merge] WARN: {source_name} output missing: {source_path}", flush=True)
            continue
        text = open(source_path, encoding="utf-8", errors="replace").read()
        finding_count = text.count("[FINDING]")
        total_findings += finding_count
        parts.append(f"# ========== TRIAGE SOURCE: {source_name.upper()} ({finding_count} findings) ==========\n{text.strip()}")
        print(f"[pipeline/merge] {source_name}: {finding_count} finding(s)", flush=True)

    with open(combined_path, "w", encoding="utf-8") as f:
        f.write("\n\n".join(parts))
        if not parts:
            f.write("# (no triage outputs found)\n")

    size_kb = os.path.getsize(combined_path) // 1024
    print(f"[pipeline/merge] Combined: {total_findings} total findings → {combined_path} ({size_kb} KB)", flush=True)


def _merge_triage_no_llm(base: str, cfg: dict) -> None:
    """Write a stub combined file in dry-run mode."""
    combined_path = os.path.join(base, cfg.get("triage_combined", "output/triage_combined.txt"))
    os.makedirs(os.path.dirname(combined_path), exist_ok=True)
    with open(combined_path, "w", encoding="utf-8") as f:
        f.write("# triage_combined.txt (DRY RUN — no LLM calls made)\n")
        f.write("# Run without --no-llm to generate real triage findings.\n")
    print(f"[pipeline/merge] Dry-run stub → {combined_path}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the full disk DFIR pipeline")
    ap.add_argument("--base-dir", default=str(BASE_DIR))
    ap.add_argument("--artifact-dir", default=str(ARTIFACT_DIR))
    ap.add_argument("--from-stage", type=int, default=1, choices=[1, 2, 3, 4])
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--collector-config", default=None,
                    help="If set, run disk_collector.py before pipeline stages. "
                         "Pass the path to config.json used by the collector.")
    mode_group = ap.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--fast", dest="collector_mode", action="store_const", const="fast", default="fast",
        help="Collector fast mode: MFT suspicious-paths only + skip PE analysis (default)",
    )
    mode_group.add_argument(
        "--full", dest="collector_mode", action="store_const", const="full",
        help="Collector full mode: complete MFT parse with PE analysis",
    )
    ap.add_argument("--workers", type=int, default=4,
                    help="Parallel workers for each collector phase (default: 4)")
    args = ap.parse_args()

    base = args.base_dir
    artifacts = args.artifact_dir
    py = sys.executable

    # Optional: run disk_collector.py before pipeline stages
    if args.collector_config and args.from_stage == 1:
        collector_script = str(Path(base).parent / "disk-collector" / "disk_collector.py")
        if not os.path.isfile(collector_script):
            sys.exit(f"[pipeline] disk_collector.py not found: {collector_script}")
        print(f"\n[pipeline] Running disk collector ({args.collector_mode} mode)...", flush=True)
        _run("Collection phase", [
            py, collector_script,
            "--config", args.collector_config,
            "--out-dir", artifacts,
            f"--{args.collector_mode}",
            "--workers", str(args.workers),
        ])

    # Load config for merge step
    cfg_path = os.path.join(base, "config.json")
    cfg: dict = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)

    def run_if(stage_num: int, label: str, cmd: list[str]) -> None:
        if stage_num < args.from_stage:
            print(f"[pipeline] Skipping stage {stage_num}: {label}")
            return
        _run(f"Stage {stage_num}: {label}", cmd)

    # Stage 1: preprocess → 3 TRIAGE_INPUT files
    run_if(1, "preprocess → TRIAGE_INPUT_*.txt", [
        py, str(SCRIPT_DIR / "preprocess.py"),
        "--base-dir", base,
        "--artifact-dir", artifacts,
    ])

    # Stage 2: 3 specialized triage agents
    if args.from_stage <= 2:
        print(f"\n{'='*60}", flush=True)
        print(f"[pipeline] Stage 2: Triage agents (3 specialized)", flush=True)
        print(f"{'='*60}", flush=True)
        t0 = time.monotonic()
        for mode in ("persistence", "events", "mft"):
            _run(f"Stage 2/{mode}: triage_agent --mode {mode} → triage_{mode}.txt", [
                py, str(SCRIPT_DIR / "triage_agent.py"),
                "--mode", mode,
                "--base-dir", base,
                *(["--no-llm"] if args.no_llm else []),
            ])
        elapsed = time.monotonic() - t0
        print(f"[pipeline] Stage 2 (all 3 agents) done in {elapsed:.1f}s", flush=True)

        # Stage 2d: merge
        print(f"\n[pipeline] Stage 2d: merge → triage_combined.txt", flush=True)
        if args.no_llm:
            _merge_triage_no_llm(base, cfg)
        else:
            _merge_triage_outputs(base, cfg)

    # Stage 3: pivot search
    run_if(3, "pivot_search → pivot.txt", [
        py, str(SCRIPT_DIR / "pivot_search.py"),
        "--base-dir", base,
        "--artifact-dir", artifacts,
    ])

    # Stage 4: pivot analyst
    run_if(4, "Agent 2 (pivot analyst) → analyst.txt", [
        py, str(SCRIPT_DIR / "pivot_analyst.py"),
        "--base-dir", base,
        *(["--no-llm"] if args.no_llm else []),
    ])

    print(f"\n[pipeline] Pipeline complete.")
    output_dir = Path(base) / "output"
    for fname in (
        "TRIAGE_INPUT_PERSISTENCE.txt",
        "TRIAGE_INPUT_EVENTS.txt",
        "TRIAGE_INPUT_MFT.txt",
        "triage_persistence.txt",
        "triage_events.txt",
        "triage_mft.txt",
        "triage_combined.txt",
        "pivot.txt",
        "analyst.txt",
    ):
        p = output_dir / fname
        size = f"{p.stat().st_size:,} bytes" if p.exists() else "MISSING"
        print(f"  {fname:<40} {size}")


if __name__ == "__main__":
    main()
