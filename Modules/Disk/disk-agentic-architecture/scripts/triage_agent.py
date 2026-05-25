#!/usr/bin/env python3
"""
Agent 1 — specialized disk forensics triage.

Reads one of three mode-specific TRIAGE_INPUT_*.txt files, calls Claude Sonnet
via the Anthropic API once, and writes the structured triage report.

Usage:
    python triage_agent.py --mode <persistence|events|mft>
                           [--base-dir <dir>] [--no-llm]

    --mode         REQUIRED. Which specialized agent to run:
                     persistence  → TRIAGE_INPUT_PERSISTENCE.txt + agent1_persistence.md
                     events       → TRIAGE_INPUT_EVENTS.txt       + agent1_events.md
                     mft          → TRIAGE_INPUT_MFT.txt           + agent1_mft.md
    --no-llm       Dry-run: print the prompt that would be sent without calling the LLM.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Mode configuration
# ---------------------------------------------------------------------------

MODE_CONFIG = {
    "persistence": {
        "input_key":   "triage_input_persistence",
        "input_default": "output/TRIAGE_INPUT_PERSISTENCE.txt",
        "prompt_file": "agent1_persistence.md",
        "output_key":  "triage_output_persistence",
        "output_default": "output/triage_persistence.txt",
        "finding_prefix": "P",
    },
    "events": {
        "input_key":   "triage_input_events",
        "input_default": "output/TRIAGE_INPUT_EVENTS.txt",
        "prompt_file": "agent1_events.md",
        "output_key":  "triage_output_events",
        "output_default": "output/triage_events.txt",
        "finding_prefix": "E",
    },
    "mft": {
        "input_key":   "triage_input_mft",
        "input_default": "output/TRIAGE_INPUT_MFT.txt",
        "prompt_file": "agent1_mft.md",
        "output_key":  "triage_output_mft",
        "output_default": "output/triage_mft.txt",
        "finding_prefix": "M",
    },
}

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent


def _resolve_base(override: str | None) -> Path:
    return Path(override).resolve() if override else BASE_DIR


def _load_text(path: Path) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


# ---------------------------------------------------------------------------
# LLM call
# ---------------------------------------------------------------------------

def _call_agent1(system_prompt: str, triage_input: str, llm_cfg: dict) -> str:
    sys.path.insert(0, str(SCRIPT_DIR))
    from llm_client import call_chat

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": triage_input},
    ]
    return call_chat(messages, llm_cfg)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Agent 1 — specialized disk forensics triage")
    ap.add_argument("--mode", required=True, choices=list(MODE_CONFIG.keys()),
                    help="Which specialized agent to run: persistence | events | mft")
    ap.add_argument("--base-dir", default=None, help="Root of disk-agentic-architecture/")
    ap.add_argument("--no-llm", action="store_true", help="Dry-run: print prompt only, no API call")
    args = ap.parse_args()

    base = _resolve_base(args.base_dir)
    mode_cfg = MODE_CONFIG[args.mode]

    # Load config to resolve paths
    config_path = base / "config.json"
    cfg: dict = {}
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)

    prompt_path  = base / "prompts" / mode_cfg["prompt_file"]
    input_path   = base / cfg.get(mode_cfg["input_key"], mode_cfg["input_default"])
    output_path  = base / cfg.get(mode_cfg["output_key"], mode_cfg["output_default"])
    llm_cfg_path = base / "llm_config.json"

    # Validate inputs
    for p in (prompt_path, input_path, llm_cfg_path):
        if not p.exists():
            sys.exit(f"[triage_agent/{args.mode}] Missing required file: {p}")

    system_prompt = _load_text(prompt_path)
    triage_input  = _load_text(input_path)
    prefix        = mode_cfg["finding_prefix"]

    print(f"[triage_agent/{args.mode}] System prompt: {len(system_prompt):,} chars", flush=True)
    print(f"[triage_agent/{args.mode}] Triage input:  {len(triage_input):,} chars", flush=True)
    print(f"[triage_agent/{args.mode}] Finding prefix: {prefix}NNN", flush=True)

    if args.no_llm:
        print(f"\n=== DRY RUN [{args.mode}] — SYSTEM PROMPT ===")
        print(system_prompt[:2000], "..." if len(system_prompt) > 2000 else "")
        print(f"\n=== DRY RUN [{args.mode}] — USER MESSAGE (first 2000 chars) ===")
        print(triage_input[:2000], "..." if len(triage_input) > 2000 else "")
        return

    with open(llm_cfg_path, "r", encoding="utf-8") as f:
        llm_cfg = json.load(f)

    (base / "logs").mkdir(parents=True, exist_ok=True)

    print(f"[triage_agent/{args.mode}] Calling {llm_cfg.get('model')} …", flush=True)
    t0 = datetime.now(timezone.utc)
    response = _call_agent1(system_prompt, triage_input, llm_cfg)
    elapsed = (datetime.now(timezone.utc) - t0).total_seconds()
    print(f"[triage_agent/{args.mode}] Response in {elapsed:.1f}s — {len(response):,} chars", flush=True)

    # Inject finding prefix into [FINDING] blocks so downstream can trace origin
    prefixed = response.replace("[FINDING]\n", f"[FINDING]\ntriage_source: {args.mode}\n")

    _write_text(output_path, prefixed)
    print(f"[triage_agent/{args.mode}] Written → {output_path}", flush=True)

    for line in prefixed.splitlines()[:6]:
        print(f"  {line}")


if __name__ == "__main__":
    main()
