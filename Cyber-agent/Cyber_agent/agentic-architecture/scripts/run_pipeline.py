#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_DIR = os.path.dirname(_SCRIPTS_DIR)


def main() -> None:
    parser = argparse.ArgumentParser(description="Forensic triage pipeline orchestrator")
    parser.add_argument("--collector",      required=True,  help="Path to collector JSON")
    parser.add_argument("--artifact-root",  required=True,  help="Directory containing Volatility .txt files")
    parser.add_argument("--out",            required=True,  help="Output directory")
    parser.add_argument("--llm-config",     default=os.path.join(_REPO_DIR, "llm_config.json"))
    parser.add_argument("--no-llm-triage",  action="store_true", help="Disable LLM for triage (debug only)")
    parser.add_argument("--use-llm-report", action="store_true", help="Enable LLM for the report stage")
    # Rétrocompatibilité : --use-llm active le LLM sur TOUTES les étapes
    parser.add_argument("--use-llm",        action="store_true", help="Enable LLM for all stages (triage + report)")
    args = parser.parse_args()

    out_dir = args.out
    os.makedirs(out_dir, exist_ok=True)

    triage_path   = os.path.join(out_dir, "triage.json")
    pivot_path    = os.path.join(out_dir, "pivot.json")
    analyst_path  = os.path.join(out_dir, "analyst.json")
    report_path   = os.path.join(out_dir, "report.md")

    # --- Étape 1 : Triage (Agent 1, LLM) ---
    triage_cmd = [
        sys.executable,
        os.path.join(_SCRIPTS_DIR, "triage_agent.py"),
        "--collector", args.collector,
        "--out",        triage_path,
        "--llm-config", args.llm_config,
    ]
    if args.no_llm_triage:
        triage_cmd.append("--no-llm")
    subprocess.check_call(triage_cmd)

    # --- Étape 2 : Grep pivot (déterministe) ---
    subprocess.check_call([
        sys.executable,
        os.path.join(_SCRIPTS_DIR, "pivot_grep.py"),
        "--triage",        triage_path,
        "--artifact-root", args.artifact_root,
        "--out",           pivot_path,
    ])

    # --- Étape 3 : Pivot Analyst (Agent 2, LLM) ---
    subprocess.check_call([
        sys.executable,
        os.path.join(_SCRIPTS_DIR, "pivot_analyst.py"),
        "--triage",     triage_path,
        "--pivot",      pivot_path,
        "--out",        analyst_path,
        "--llm-config", args.llm_config,
    ])

    # --- Étape 4 : Report Writer (Agent 3, LLM) ---
    report_cmd = [
        sys.executable,
        os.path.join(_SCRIPTS_DIR, "report_agent.py"),
        "--analyst", analyst_path,
        "--pivot",   pivot_path,
        "--out",     report_path,
    ]
    if args.use_llm or args.use_llm_report:
        report_cmd.extend(["--use-llm", "--llm-config", args.llm_config])
    subprocess.check_call(report_cmd)

    print("\nPipeline complete (4 stages):")
    print(f"  1. Triage (Agent 1) -> {triage_path}")
    print(f"  2. Grep pivot       -> {pivot_path}")
    print(f"  3. Analyst (Agent 2)-> {analyst_path}")
    print(f"  4. Report (Agent 3) -> {report_path}")


if __name__ == "__main__":
    main()
