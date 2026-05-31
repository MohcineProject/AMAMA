#!/usr/bin/env python3
"""
Pipeline orchestrator — runs all 4 stages over every input chunk.

Flow per chunk:
  triage_agent.py  →  output/chunk_N/triage.txt
  pivot_grep.py    →  output/chunk_N/pivot.txt
  pivot_analyst.py →  output/chunk_N/analyst.txt

Then:
  Aggregate all analyst.txt → output/aggregated_analyst.txt
  report_agent.py  →  output/report.md
"""
import argparse
import glob
import json
import os
import subprocess
import sys

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_DIR = os.path.dirname(_SCRIPTS_DIR)


def _run(cmd: list) -> None:
    subprocess.check_call(cmd)


def main() -> None:
    parser = argparse.ArgumentParser(description="Forensic pipeline orchestrator")
    parser.add_argument(
        "--config",
        default=os.path.join(_REPO_DIR, "config.json"),
        help="Path to config.json (default: agentic-architecture/config.json)",
    )
    parser.add_argument(
        "--llm-config",
        default=os.path.join(_REPO_DIR, "llm_config.json"),
        help="Path to llm_config.json",
    )
    parser.add_argument(
        "--out",
        default=os.path.join(_REPO_DIR, "output"),
        help="Root output directory (default: agentic-architecture/output/)",
    )
    parser.add_argument(
        "--use-llm",
        action="store_true",
        help="Enable LLM for all stages (triage, analyst, report)",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM for all stages (rule-based fallback only)",
    )
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        config = json.load(f)

    # Resolve input_dir from config (relative to _REPO_DIR)
    raw_input = config.get("input_dir", "../INPUT")
    if os.path.isabs(raw_input):
        input_dir = raw_input
    else:
        input_dir = os.path.normpath(os.path.join(_REPO_DIR, raw_input))

    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    # --- Discover chunks ---
    chunk_pattern = os.path.join(input_dir, "chunk_*.txt")
    chunks = sorted(glob.glob(chunk_pattern))
    if not chunks:
        print(f"[pipeline] ERROR: no chunk_*.txt files found in {input_dir}", file=sys.stderr)
        sys.exit(1)
    print(f"[pipeline] Found {len(chunks)} chunk(s) in {input_dir}", file=sys.stderr)

    analyst_files: list = []

    # --- Per-chunk loop ---
    for idx, chunk_path in enumerate(chunks, start=1):
        chunk_name = os.path.basename(chunk_path)
        chunk_label = os.path.splitext(chunk_name)[0]  # e.g. chunk_001
        chunk_out = os.path.join(out_dir, chunk_label)
        os.makedirs(chunk_out, exist_ok=True)

        triage_path  = os.path.join(chunk_out, "triage.txt")
        pivot_path   = os.path.join(chunk_out, "pivot.txt")
        analyst_path = os.path.join(chunk_out, "analyst.txt")

        print(f"\n[pipeline] === Chunk {idx}/{len(chunks)}: {chunk_name} ===", file=sys.stderr)

        # Stage 1: Triage Agent
        print(f"[pipeline]   Stage 1 — triage_agent.py", file=sys.stderr)
        triage_cmd = [
            sys.executable,
            os.path.join(_SCRIPTS_DIR, "triage_agent.py"),
            "--input",      chunk_path,
            "--out",        triage_path,
            "--llm-config", args.llm_config,
            "--config",     args.config,
        ]
        if args.no_llm:
            triage_cmd.append("--no-llm")
        _run(triage_cmd)

        # Stage 2: Grep Pivot (deterministic, no LLM)
        print(f"[pipeline]   Stage 2 — pivot_grep.py", file=sys.stderr)
        _run([
            sys.executable,
            os.path.join(_SCRIPTS_DIR, "pivot_grep.py"),
            "--triage", triage_path,
            "--config", args.config,
            "--out",    pivot_path,
        ])

        # Stage 3: Pivot Analyst (Agent 2)
        print(f"[pipeline]   Stage 3 — pivot_analyst.py", file=sys.stderr)
        analyst_cmd = [
            sys.executable,
            os.path.join(_SCRIPTS_DIR, "pivot_analyst.py"),
            "--triage",     triage_path,
            "--pivot",      pivot_path,
            "--out",        analyst_path,
            "--llm-config", args.llm_config,
        ]
        if args.no_llm:
            analyst_cmd.append("--no-llm")
        _run(analyst_cmd)

        analyst_files.append((idx, chunk_name, analyst_path))

    # --- Aggregate all analyst.txt files ---
    aggregated_path = os.path.join(out_dir, "aggregated_analyst.txt")
    print(f"\n[pipeline] Aggregating {len(analyst_files)} analyst file(s) → {aggregated_path}", file=sys.stderr)

    with open(aggregated_path, "w", encoding="utf-8") as agg:
        for idx, chunk_name, analyst_path in analyst_files:
            agg.write(f"=== CHUNK {idx}: {chunk_name} ===\n")
            try:
                with open(analyst_path, "r", encoding="utf-8", errors="ignore") as f:
                    agg.write(f.read())
            except FileNotFoundError:
                agg.write(f"(analyst.txt not found for {chunk_name})\n")
            agg.write("\n")

    # --- Stage 4: Report Writer (Agent 3) ---
    report_path = os.path.join(out_dir, "report.md")
    print(f"[pipeline] Stage 4 — report_agent.py → {report_path}", file=sys.stderr)
    report_cmd = [
        sys.executable,
        os.path.join(_SCRIPTS_DIR, "report_agent.py"),
        "--analyst", aggregated_path,
        "--out",     report_path,
    ]
    if args.use_llm and not args.no_llm:
        report_cmd.extend(["--use-llm", "--llm-config", args.llm_config])
    _run(report_cmd)

    # --- Summary ---
    print("\n[pipeline] Pipeline complete.", file=sys.stderr)
    print(f"  Chunks processed : {len(chunks)}", file=sys.stderr)
    print(f"  Output root      : {out_dir}", file=sys.stderr)
    print(f"  Aggregated TXT   : {aggregated_path}", file=sys.stderr)
    print(f"  Final report     : {report_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
