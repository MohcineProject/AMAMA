#!/usr/bin/env python3
"""
Agent 2 — disk forensics pivot analyst.

Reads output/triage.txt (Agent 1 findings) and output/pivot.txt (grep evidence),
calls Claude Sonnet once per finding, and writes output/analyst.txt.

Usage:
    python pivot_analyst.py [--base-dir <dir>] [--no-llm] [--finding N]

    --no-llm     Dry-run: print first finding prompt only.
    --finding N  Only analyse finding N (1-indexed).
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

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
# Parse Agent 1 triage.txt → list of (index, raw_block_str)
# ---------------------------------------------------------------------------

def parse_triage(text: str) -> list[tuple[int, str]]:
    """
    Returns [(1, block_text), (2, block_text), ...] for each [FINDING] block.
    """
    findings = []
    # Split on [FINDING] markers; keep the marker in the block
    parts = re.split(r"(?=\[FINDING\])", text)
    idx = 0
    for part in parts:
        part = part.strip()
        if part.startswith("[FINDING]"):
            idx += 1
            findings.append((idx, part))
    return findings


def _extract_field(block: str, field: str) -> str:
    """Extract a single field value from a [FINDING] block."""
    m = re.search(rf"^{field}\s*:\s*(.+)$", block, re.MULTILINE | re.IGNORECASE)
    return m.group(1).strip() if m else ""


# ---------------------------------------------------------------------------
# Parse output/pivot.txt → dict {finding_index: evidence_block_str}
# ---------------------------------------------------------------------------

def parse_pivot(text: str) -> dict[int, str]:
    """
    Returns {1: evidence_str, 2: evidence_str, ...} keyed by finding index.

    pivot.txt format (from pivot_search.py):
      ========================================================================
      === FINDING N: type=... severity=... ===
      === key: <key> ===
      ========================================================================
      reasons: ...
      ...
      --- artifact.txt (N hits) ---
      L<n>: <verbatim line>
    """
    result: dict[int, str] = {}
    # Find the opening separator of each finding block
    sep_re = re.compile(r"^={40,}$", re.MULTILINE)
    finding_re = re.compile(r"^=== FINDING (\d+):", re.MULTILINE)

    sep_positions = [m.start() for m in sep_re.finditer(text)]

    for i, sep_start in enumerate(sep_positions):
        # The line after this separator should contain "=== FINDING N:"
        after_sep = text[sep_start:]
        fm = finding_re.match(after_sep.lstrip("=\n"))
        if fm is None:
            # Try looking in the 3 lines after the separator
            lines_after = after_sep.split("\n", 4)
            for ln in lines_after[1:4]:
                fm2 = re.match(r"=== FINDING (\d+):", ln)
                if fm2:
                    idx = int(fm2.group(1))
                    # Block runs from sep_start to next separator (or EOF)
                    end = sep_positions[i + 1] if i + 1 < len(sep_positions) else len(text)
                    # But the closing separator is also part of the next block's opener
                    # Find the NEXT opening separator after this block's content
                    block = text[sep_start:end].strip()
                    result[idx] = block
                    break
    return result


# ---------------------------------------------------------------------------
# LLM call
# ---------------------------------------------------------------------------

def _call_agent2(system_prompt: str, user_content: str, llm_cfg: dict) -> str:
    sys.path.insert(0, str(SCRIPT_DIR))
    from llm_client import call_chat

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
    ]
    return call_chat(messages, llm_cfg)


# ---------------------------------------------------------------------------
# Build user message for one finding
# ---------------------------------------------------------------------------

def _build_user_message(idx: int, finding_block: str, evidence_block: str) -> str:
    return (
        f"=== Agent 1 Finding #{idx} ===\n"
        f"{finding_block}\n\n"
        f"=== Pivot Evidence for Finding #{idx} ===\n"
        f"{evidence_block if evidence_block else '(no matching lines in any artifact file)'}\n"
    )


# ---------------------------------------------------------------------------
# Assemble final report
# ---------------------------------------------------------------------------

def _assemble_report(
    per_finding_responses: list[tuple[int, str]],
    generated: str,
) -> str:
    """
    Concatenate individual Agent 2 responses into one analyst.txt.
    Each response already has its own [CONFIRMED]/[INCONCLUSIVE] block.
    Prepend a generation header.
    """
    lines = [
        "================================================================",
        "DISK FORENSICS — PIVOT REPORT",
        f"Generated: {generated}",
        "================================================================",
        "",
    ]
    for idx, resp in per_finding_responses:
        lines.append(f"--- Finding {idx} ---")
        lines.append(resp.strip())
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Agent 2 — disk forensics pivot analyst")
    ap.add_argument("--base-dir", default=None)
    ap.add_argument("--no-llm", action="store_true", help="Dry-run: print first finding prompt")
    ap.add_argument("--finding", type=int, default=None, help="Only analyse finding N")
    args = ap.parse_args()

    base = _resolve_base(args.base_dir)
    prompt_path  = base / "prompts" / "agent2_pivot.md"
    # session-7 multi-agent architecture produces triage_combined.txt; fall back to
    # the legacy triage.txt produced by the old single-agent flow.
    _combined = base / "output" / "triage_combined.txt"
    _legacy   = base / "output" / "triage.txt"
    triage_path = _combined if _combined.exists() else _legacy
    pivot_path   = base / "output"  / "pivot.txt"
    output_path  = base / "output"  / "analyst.txt"
    llm_cfg_path = base / "llm_config.json"

    for p in (prompt_path, triage_path, pivot_path, llm_cfg_path):
        if not p.exists():
            sys.exit(f"[pivot_analyst] Missing required file: {p}")

    system_prompt = _load_text(prompt_path)
    triage_text   = _load_text(triage_path)
    pivot_text    = _load_text(pivot_path)

    findings  = parse_triage(triage_text)
    evidence  = parse_pivot(pivot_text)

    if not findings:
        sys.exit(f"[pivot_analyst] No [FINDING] blocks found in {triage_path.name} — nothing to analyse.")

    print(f"[pivot_analyst] {len(findings)} findings in {triage_path.name}", flush=True)
    print(f"[pivot_analyst] {len(evidence)} evidence blocks in pivot.txt", flush=True)

    if args.finding:
        findings = [(i, b) for i, b in findings if i == args.finding]
        if not findings:
            sys.exit(f"[pivot_analyst] Finding {args.finding} not found.")

    if args.no_llm:
        idx, block = findings[0]
        ev = evidence.get(idx, "")
        print("\n=== DRY RUN — USER MESSAGE FOR FINDING 1 ===")
        print(_build_user_message(idx, block, ev))
        return

    with open(llm_cfg_path, "r", encoding="utf-8") as f:
        llm_cfg = json.load(f)

    (base / "logs").mkdir(parents=True, exist_ok=True)

    per_finding_responses: list[tuple[int, str]] = []
    for idx, finding_block in findings:
        ev = evidence.get(idx, "")
        user_msg = _build_user_message(idx, finding_block, ev)

        print(f"[pivot_analyst] Analysing finding {idx}/{findings[-1][0]} …", flush=True)
        t0 = datetime.now(timezone.utc)
        resp = _call_agent2(system_prompt, user_msg, llm_cfg)
        elapsed = (datetime.now(timezone.utc) - t0).total_seconds()
        print(f"[pivot_analyst]   → {len(resp):,} chars in {elapsed:.1f}s", flush=True)

        per_finding_responses.append((idx, resp))

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    report = _assemble_report(per_finding_responses, generated)

    _write_text(output_path, report)
    print(f"[pivot_analyst] Written → {output_path}", flush=True)


if __name__ == "__main__":
    main()
