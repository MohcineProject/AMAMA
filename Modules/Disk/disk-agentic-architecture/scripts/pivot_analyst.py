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

# How many Agent 1 findings to validate per LLM call. Each finding carries its
# full pivot evidence already, so batching costs little quality but cuts the
# number of calls (and the mandatory inter-call wait) ~3x. Overridable via the
# `agent2_batch_size` key in llm_config.json.
_BATCH_SIZE = 3


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

    Each finding uses two ==== separators (opening + closing header), so
    we split on the opening-separator+FINDING-header pattern to capture
    all evidence lines up to the next finding.
    """
    result: dict[int, str] = {}
    parts = re.split(r"(?=={40,}\n=== FINDING \d+:)", text)
    for part in parts:
        m = re.search(r"=== FINDING (\d+):", part)
        if m:
            result[int(m.group(1))] = part.strip()
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


def _chunked(seq: list, size: int) -> list[list]:
    """Split seq into consecutive sub-lists of at most `size` items."""
    size = max(1, size)
    return [seq[i:i + size] for i in range(0, len(seq), size)]


def _build_batch_user_message(batch: list[tuple[int, str, str]]) -> str:
    """Concatenate several (idx, finding_block, evidence_block) items into one
    user message. The prompt instructs the model to emit one verdict block per
    finding, in order."""
    n = len(batch)
    header = (
        f"You are given {n} Agent 1 finding(s) below. Emit one verdict block per "
        f"finding, in order. Each block's `Finding:` field must match its "
        f"`Agent 1 Finding #<N>` header.\n\n"
        if n > 1
        else ""
    )
    parts = [_build_user_message(idx, block, ev) for idx, block, ev in batch]
    return header + ("\n" + "-" * 72 + "\n\n").join(parts)


# ---------------------------------------------------------------------------
# Assemble final report
# ---------------------------------------------------------------------------

def _batch_label(first_idx: int, last_idx: int) -> str:
    """Human-readable section header for a batch response."""
    if first_idx == last_idx:
        return f"--- Finding {first_idx} ---"
    return f"--- Findings {first_idx}–{last_idx} ---"


def _assemble_report(
    batch_responses: list[tuple[int, int, str]],
    generated: str,
) -> str:
    """
    Concatenate batched Agent 2 responses into one analyst.txt.
    Each response already holds one or more [CONFIRMED]/[INCONCLUSIVE]/[REJECTED]
    blocks. Prepend a generation header.
    """
    lines = [
        "================================================================",
        "DISK FORENSICS — PIVOT REPORT",
        f"Generated: {generated}",
        "================================================================",
        "",
    ]
    for first_idx, last_idx, resp in batch_responses:
        lines.append(_batch_label(first_idx, last_idx))
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
    ap.add_argument("--from-finding", type=int, default=None,
                    help="Resume from finding N (append to existing analyst.txt)")
    ap.add_argument("--delay", type=float, default=None,
                    help="Seconds to sleep between API calls (overrides llm_config request_delay_seconds)")
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

    if args.from_finding:
        findings = [(i, b) for i, b in findings if i >= args.from_finding]
        if not findings:
            sys.exit(f"[pivot_analyst] No findings >= {args.from_finding}.")
        print(f"[pivot_analyst] Resuming from finding {args.from_finding} ({len(findings)} remaining)", flush=True)

    # Attach each finding's pivot evidence: (idx, finding_block, evidence_block)
    items: list[tuple[int, str, str]] = [
        (idx, block, evidence.get(idx, "")) for idx, block in findings
    ]

    with open(llm_cfg_path, "r", encoding="utf-8") as f:
        llm_cfg = json.load(f)

    batch_size = int(llm_cfg.get("agent2_batch_size", _BATCH_SIZE))
    batches = _chunked(items, batch_size)

    if args.no_llm:
        print(f"\n=== DRY RUN — USER MESSAGE FOR BATCH 1 ({len(batches[0])} finding(s)) ===")
        print(_build_batch_user_message(batches[0]))
        return

    # Inter-request delay: CLI --delay > llm_config request_delay_seconds > default 10s
    inter_delay: float = (
        args.delay
        if args.delay is not None
        else float(llm_cfg.get("request_delay_seconds", 10.0))
    )

    (base / "logs").mkdir(parents=True, exist_ok=True)

    last_idx_overall = items[-1][0]
    print(
        f"[pivot_analyst] {len(items)} finding(s) in {len(batches)} batch(es) "
        f"of up to {batch_size}", flush=True,
    )

    batch_responses: list[tuple[int, int, str]] = []
    for call_idx, batch in enumerate(batches):
        first_idx, last_idx = batch[0][0], batch[-1][0]
        user_msg = _build_batch_user_message(batch)

        if call_idx > 0 and inter_delay > 0:
            import time as _time
            print(f"[pivot_analyst] Waiting {inter_delay:.0f}s before next call …", flush=True)
            _time.sleep(inter_delay)

        rng = f"{first_idx}" if first_idx == last_idx else f"{first_idx}–{last_idx}"
        print(f"[pivot_analyst] Analysing finding(s) {rng}/{last_idx_overall} …", flush=True)
        t0 = datetime.now(timezone.utc)
        resp = _call_agent2(system_prompt, user_msg, llm_cfg)
        elapsed = (datetime.now(timezone.utc) - t0).total_seconds()
        print(f"[pivot_analyst]   → {len(resp):,} chars in {elapsed:.1f}s", flush=True)

        batch_responses.append((first_idx, last_idx, resp))

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Append mode: when resuming, append to existing analyst.txt content
    if args.from_finding and output_path.exists():
        existing = _load_text(output_path)
        new_section = "\n".join(
            f"{_batch_label(f, l)}\n{r.strip()}\n" for f, l, r in batch_responses
        )
        report = existing.rstrip() + "\n\n" + new_section
        _write_text(output_path, report)
    else:
        report = _assemble_report(batch_responses, generated)
        _write_text(output_path, report)

    print(f"[pivot_analyst] Written → {output_path}", flush=True)


if __name__ == "__main__":
    main()
