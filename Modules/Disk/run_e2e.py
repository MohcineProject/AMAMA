#!/usr/bin/env python3
"""
End-to-end wrapper for the Disk DFIR pipeline.

Runs all four stages in sequence:
  1. mount_image.py          — mount forensic image, write config.json
  2. disk_collector.py       — extract Windows artifacts to Disk_Artifacts/
  3. run_pipeline.py         — preprocess → triage → pivot → analyst
  4. scan.py                 — emit scan_result.json (ModuleScanResult)

Must be run as root (sudo) — mounting and collection require it.

Usage:
    sudo .venv/bin/python run_e2e.py [options]

Options:
    --case-id   Case identifier (default: timestamp, e.g. case-20260602-143201)
    --out       Output directory for scan_result.json (default: results/)
    --image-dir Directory containing the forensic image (default: Disk_image/)
    --no-llm    Skip LLM API calls — dry-run the pipeline (default: on)
    --llm       Enable LLM API calls (requires ANTHROPIC_API_KEY)
    --fast      Fast collection: MFT suspicious-paths only, skip PE analysis (default)
    --full      Full collection: complete MFT parse with PE entropy analysis
"""

import argparse
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable  # already the venv python when invoked via .venv/bin/python


def _run(label: str, cmd: list[str]) -> None:
    width = 60
    print(f"\n{'=' * width}", flush=True)
    print(f"[e2e] {label}", flush=True)
    print(f"[e2e] $ {' '.join(cmd)}", flush=True)
    print(f"{'=' * width}", flush=True)
    t0 = time.monotonic()
    result = subprocess.run(cmd, check=False)
    elapsed = time.monotonic() - t0
    if result.returncode != 0:
        sys.exit(f"[e2e] Stage failed (rc={result.returncode}) after {elapsed:.1f}s — aborting.")
    print(f"[e2e] Done in {elapsed:.1f}s", flush=True)


def run_all(
    case_id: str,
    out_dir: Path,
    image_dir: Path,
    no_llm: bool,
    fast: bool,
) -> None:
    agentic_dir = ROOT / "disk-agentic-architecture"
    artifact_dir = ROOT / "Disk_Artifacts"
    config_path = ROOT / "config.json"

    out_dir.mkdir(parents=True, exist_ok=True)

    # Stage 1: mount image
    _run("Stage 1: mount image → config.json", [
        PY,
        str(ROOT / "disk-image-mounter" / "mount_image.py"),
        "--image-dir", str(image_dir),
        "--out-config", str(config_path),
    ])

    # Stage 2: collect artifacts
    collector_mode = "--fast" if fast else "--full"
    _run(f"Stage 2: collect artifacts ({collector_mode})", [
        PY,
        str(ROOT / "disk-collector" / "disk_collector.py"),
        "--config", str(config_path),
        collector_mode,
        "--out-dir", str(artifact_dir),
        "--summary-out", str(artifact_dir / "collector_summary.json"),
    ])

    # Stage 3: run agentic pipeline
    pipeline_cmd = [
        PY,
        str(agentic_dir / "scripts" / "run_pipeline.py"),
        "--base-dir", str(agentic_dir),
        "--artifact-dir", str(artifact_dir),
    ]
    if no_llm:
        pipeline_cmd.append("--no-llm")
    _run("Stage 3: agentic pipeline (preprocess → triage → pivot → analyst)", pipeline_cmd)

    # Stage 4: emit scan_result.json
    _run("Stage 4: scan → scan_result.json", [
        PY,
        str(agentic_dir / "scripts" / "scan.py"),
        "--case-id", case_id,
        "--out", str(out_dir),
        "--base-dir", str(agentic_dir),
        "--artifact-dir", str(artifact_dir),
    ])

    print(f"\n[e2e] Pipeline complete.")
    print(f"[e2e] Output: {out_dir / 'scan_result.json'}")


def main() -> None:
    default_case_id = f"case-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    ap = argparse.ArgumentParser(
        description="End-to-end Disk DFIR pipeline: mount → collect → analyze → scan"
    )
    ap.add_argument("--case-id", default=default_case_id,
                    help=f"Case identifier (default: {default_case_id})")
    ap.add_argument("--out", default="results/",
                    help="Output directory for scan_result.json (default: results/)")
    ap.add_argument("--image-dir", default="Disk_image/",
                    help="Directory containing the forensic image (default: Disk_image/)")

    llm_group = ap.add_mutually_exclusive_group()
    llm_group.add_argument("--no-llm", dest="no_llm", action="store_true", default=True,
                           help="Dry-run: skip LLM API calls (default)")
    llm_group.add_argument("--llm", dest="no_llm", action="store_false",
                           help="Enable LLM API calls (requires ANTHROPIC_API_KEY)")

    mode_group = ap.add_mutually_exclusive_group()
    mode_group.add_argument("--fast", dest="fast", action="store_true", default=True,
                            help="Fast collection mode (default)")
    mode_group.add_argument("--full", dest="fast", action="store_false",
                            help="Full collection mode: complete MFT parse + PE entropy")

    args = ap.parse_args()

    run_all(
        case_id=args.case_id,
        out_dir=Path(args.out).resolve(),
        image_dir=Path(args.image_dir).resolve(),
        no_llm=args.no_llm,
        fast=args.fast,
    )


if __name__ == "__main__":
    main()
