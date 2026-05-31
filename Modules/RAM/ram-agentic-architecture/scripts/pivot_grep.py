#!/usr/bin/env python3
"""
Grep Pivot — deterministic evidence extractor (no LLM).

Reads triage.txt (key:value format), extracts suspicious PIDs,
then greps each configured Volatility artifact file for those PIDs.
Writes pivot.txt with verbatim matching lines per PID.
"""
import argparse
import json
import os
import re
from typing import Dict, List, Tuple

from utils import grep_file_for_pattern, now_iso


def safe_compile_pid(pid: str) -> re.Pattern:
    return re.compile(r"\b" + re.escape(pid) + r"\b")


def parse_triage_txt(path: str) -> List[Tuple[str, str, str, str]]:
    """
    Parse triage.txt and return a list of (pid, ppid, image, cmdline) tuples
    for every [PROCESS] block.
    """
    results: List[Tuple[str, str, str, str]] = []
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
                elif line == "":
                    if current.get("pid"):
                        results.append((
                            current.get("pid", ""),
                            current.get("ppid", ""),
                            current.get("image", ""),
                            current.get("cmdline", ""),
                        ))
                    in_process = False
                    current = {}

    # Handle final block with no trailing blank line
    if in_process and current.get("pid"):
        results.append((
            current.get("pid", ""),
            current.get("ppid", ""),
            current.get("image", ""),
            current.get("cmdline", ""),
        ))

    return results


def write_pivot_txt(
    processes: List[Tuple[str, str, str, str]],
    by_pid: Dict[str, Dict[str, List[str]]],
    out_path: str,
) -> None:
    """Write evidence as structured TXT."""
    lines: List[str] = []
    lines.append("=== PIVOT EVIDENCE REPORT ===")
    lines.append(f"Generated: {now_iso()}")
    lines.append("")

    for pid, ppid, image, cmdline in processes:
        lines.append(f"=== PID {pid} ({image}, ppid={ppid}) ===")
        if cmdline:
            lines.append(f"Cmdline: {cmdline}")

        evidence = by_pid.get(pid, {})
        if evidence:
            for fname, hits in evidence.items():
                lines.append("")
                lines.append(f"--- {fname} ---")
                for h in hits:
                    lines.append(h)
        else:
            lines.append("(no matching lines in any artifact file)")

        lines.append("")

    lines.append("=== END OF PIVOT REPORT ===")

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_DIR = os.path.dirname(_SCRIPTS_DIR)


def main() -> None:
    parser = argparse.ArgumentParser(description="Grep Pivot — deterministic evidence extractor")
    parser.add_argument("--triage",       required=True, help="Path to triage.txt (Agent 1 output)")
    parser.add_argument("--config",       default=os.path.join(_REPO_DIR, "config.json"))
    parser.add_argument("--artifact-root", help="Override artifact directory (default: from config)")
    parser.add_argument("--out",          required=True, help="Output path for pivot.txt")
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8", errors="ignore") as f:
        config = json.load(f)

    # Resolve artifact root: CLI flag > config > fallback
    artifact_root = args.artifact_root
    if not artifact_root:
        raw = config.get("grep_input_dir", "../Grep_input")
        if os.path.isabs(raw):
            artifact_root = raw
        else:
            artifact_root = os.path.normpath(os.path.join(_REPO_DIR, raw))

    processes = parse_triage_txt(args.triage)
    print(f"[pivot-grep] {len(processes)} PIDs to search.", file=__import__("sys").stderr)

    max_per_file = config.get("max_lines_per_file", 120)
    max_total = config.get("max_total_lines_per_target", 400)

    by_pid: Dict[str, Dict[str, List[str]]] = {}

    for pid, _ppid, _image, _cmdline in processes:
        by_pid[pid] = {}
        pattern = safe_compile_pid(str(pid))
        total = 0
        for fname in config.get("pid_files", []):
            if total >= max_total:
                break
            fpath = os.path.join(artifact_root, fname)
            if not os.path.exists(fpath):
                continue
            remaining = max_total - total
            hits = grep_file_for_pattern(fpath, pattern, min(max_per_file, remaining))
            if hits:
                by_pid[pid][fname] = hits
                total += len(hits)

    write_pivot_txt(processes, by_pid, args.out)
    print(f"[pivot-grep] Written: {args.out}", file=__import__("sys").stderr)


if __name__ == "__main__":
    main()
