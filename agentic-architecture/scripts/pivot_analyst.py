#!/usr/bin/env python3
"""
Pivot Analyst — Agent 2 of the forensic pipeline.

Reads triage.txt (Agent 1 key:value output) and pivot.txt (grep evidence),
builds a compact context, calls the LLM, and saves the raw TXT response
as analyst.txt. The output format is defined verbatim by agent2_pivot.md.
"""
import argparse
import os
import sys
from typing import Any, Dict, List, Tuple

from llm_client import call_chat, load_llm_config
from utils import now_iso

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_DIR = os.path.dirname(_SCRIPTS_DIR)


# ---------------------------------------------------------------------------
# Parsers for TXT intermediates
# ---------------------------------------------------------------------------

def parse_triage_txt(path: str) -> Dict[str, Dict[str, str]]:
    """
    Parse triage.txt into {pid: {pid, ppid, image, cmdline, severity, reasons}}.
    """
    result: Dict[str, Dict[str, str]] = {}
    current: Dict[str, str] = {}
    in_process = False

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.rstrip()

            if line == "[PROCESS]":
                in_process = True
                current = {}
            elif in_process:
                if line.startswith("pid: "):
                    current["pid"] = line[5:].strip()
                elif line.startswith("ppid: "):
                    current["ppid"] = line[6:].strip()
                elif line.startswith("image: "):
                    current["image"] = line[7:].strip()
                elif line.startswith("cmdline: "):
                    current["cmdline"] = line[9:].strip()
                elif line.startswith("severity: "):
                    current["severity"] = line[10:].strip()
                elif line.startswith("reasons: "):
                    current["reasons"] = line[9:].strip()
                elif line == "":
                    if current.get("pid"):
                        result[current["pid"]] = dict(current)
                    in_process = False
                    current = {}

    if in_process and current.get("pid"):
        result[current["pid"]] = dict(current)

    return result


def parse_pivot_txt(path: str) -> Dict[str, Dict[str, List[str]]]:
    """
    Parse pivot.txt into {pid: {filename: [evidence_lines]}}.
    """
    result: Dict[str, Dict[str, List[str]]] = {}
    current_pid: str = ""
    current_file: str = ""

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.rstrip()

            # PID section header: "=== PID 3412 (powershell.exe, ppid=...) ==="
            if line.startswith("=== PID ") and line.endswith(" ==="):
                inner = line[4:-4].strip()
                # Extract just the numeric PID
                pid_part = inner.split()[1] if len(inner.split()) > 1 else inner
                # Remove trailing parenthetical if present
                pid_part = pid_part.split("(")[0].strip()
                current_pid = pid_part
                result.setdefault(current_pid, {})
                current_file = ""
            elif line.startswith("--- ") and line.endswith(" ---"):
                if current_pid:
                    current_file = line[4:-4].strip()
                    result[current_pid].setdefault(current_file, [])
            elif line in ("(no matching lines in any artifact file)", ""):
                current_file = ""
            elif line.startswith("=== END") or line.startswith("=== PIVOT"):
                pass
            elif current_pid and current_file and line and not line.startswith("Cmdline:"):
                result[current_pid][current_file].append(line)

    return result


# ---------------------------------------------------------------------------
# Context builder for Agent 2
# ---------------------------------------------------------------------------

def _build_llm_context(
    triage_procs: Dict[str, Dict],
    pivot_evidence: Dict[str, Dict],
    max_lines_per_target: int = 40,
) -> str:
    lines: List[str] = []
    lines.append("=== TRIAGE FINDINGS TO VALIDATE ===")
    lines.append(
        "For each finding: WHY Agent 1 flagged it, then ACTUAL EVIDENCE from Volatility artifacts."
    )
    lines.append("Confirm, reject, or mark inconclusive each finding.\n")

    for pid, proc in triage_procs.items():
        image = proc.get("image", "unknown")
        ppid = proc.get("ppid", "?")
        severity = proc.get("severity", "?")
        cmdline = proc.get("cmdline", "")
        reasons = proc.get("reasons", "none given")

        lines.append(f"\n--- [PID {pid}] {image} (ppid={ppid}, Agent1 severity={severity}) ---")
        if cmdline:
            lines.append(f"  Cmdline: {cmdline}")
        lines.append(f"  Agent 1 reasons: {reasons}")

        evidence = pivot_evidence.get(pid, {})
        budget = max_lines_per_target
        if evidence:
            for fname, hits in evidence.items():
                if budget <= 0:
                    break
                alloc = min(len(hits), budget)
                lines.append(f"  [{fname}] ({len(hits)} hits, showing {alloc}):")
                for h in hits[:alloc]:
                    lines.append(f"    {h}")
                budget -= alloc
        else:
            lines.append("  Evidence: NO MATCH FOUND in any artifact file")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Fallback TXT output when LLM fails
# ---------------------------------------------------------------------------

def _build_fallback_analyst_txt(triage_procs: Dict[str, Dict]) -> str:
    """Generate a valid analyst.txt when the LLM is unavailable."""
    n = len(triage_procs)
    out_lines: List[str] = []
    out_lines.append("================================================================")
    out_lines.append("FIND_EVIL — PIVOT REPORT")
    out_lines.append(f"Generated: {now_iso()}")
    out_lines.append(
        "Summary: LLM validation failed — all findings are inconclusive. Manual review required."
    )
    out_lines.append(f"Counts: confirmed=0  inconclusive={n}  rejected=0")
    out_lines.append("================================================================")

    for pid, proc in triage_procs.items():
        image = proc.get("image", "unknown")
        ppid = proc.get("ppid", "?")
        cmdline = proc.get("cmdline", "")
        reasons = proc.get("reasons", "")

        out_lines.append("")
        out_lines.append("[INCONCLUSIVE]")
        out_lines.append("----------------------------------------------------------------")
        out_lines.append(f"PID:      {pid}")
        out_lines.append(f"PPID:     {ppid}")
        out_lines.append(f"Image:    {image}")
        if cmdline:
            out_lines.append(f"Cmdline:  {cmdline}")
        out_lines.append("")
        out_lines.append("Justification:")
        out_lines.append(
            f"  LLM unavailable — cannot validate. Agent 1 reasons: {reasons}"
        )
        out_lines.append("----------------------------------------------------------------")

    return "\n".join(out_lines) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Pivot Analyst — Agent 2 (LLM validation)")
    parser.add_argument("--triage",     required=True, help="Path to triage.txt (Agent 1 output)")
    parser.add_argument("--pivot",      required=True, help="Path to pivot.txt (grep output)")
    parser.add_argument("--out",        required=True, help="Output path for analyst.txt")
    parser.add_argument("--llm-config", default=os.path.join(_REPO_DIR, "llm_config.json"))
    parser.add_argument("--prompt",     default=os.path.join(_REPO_DIR, "prompts", "agent2_pivot.md"))
    parser.add_argument("--max-lines",  type=int, default=40,
                        help="Max evidence lines per PID in LLM context")
    parser.add_argument("--no-llm",    action="store_true", help="Skip LLM; write fallback analyst.txt")
    args = parser.parse_args()

    triage_procs = parse_triage_txt(args.triage)
    pivot_evidence = parse_pivot_txt(args.pivot)

    print(
        f"[pivot-analyst] {len(triage_procs)} findings to validate.",
        file=sys.stderr,
    )

    if args.no_llm:
        print("[pivot-analyst] --no-llm set; writing fallback analyst.txt.", file=sys.stderr)
        content = _build_fallback_analyst_txt(triage_procs)
    else:
        with open(args.prompt, "r", encoding="utf-8", errors="ignore") as f:
            system_prompt = f.read().strip()

        context = _build_llm_context(triage_procs, pivot_evidence, args.max_lines)

        llm_config = load_llm_config(args.llm_config)

        print("[pivot-analyst] Calling LLM for validation...", file=sys.stderr)
        try:
            raw_response = call_chat([
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": context},
            ], llm_config)

            # Agent 2 outputs TXT directly — save raw response as-is
            content = raw_response.strip()
            print("[pivot-analyst] LLM validation complete.", file=sys.stderr)

        except Exception as exc:
            print(
                f"[pivot-analyst] LLM failed ({exc}), writing fallback analyst.txt.",
                file=sys.stderr,
            )
            content = _build_fallback_analyst_txt(triage_procs)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(content + "\n")

    print(f"[pivot-analyst] Written: {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
