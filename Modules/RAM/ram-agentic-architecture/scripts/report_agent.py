#!/usr/bin/env python3
"""
Report Writer — Agent 3 of the forensic pipeline.

Reads aggregated_analyst.txt (all chunk analyst.txt files concatenated),
then either calls the LLM for a narrative report or generates a structured
Markdown report from the parsed TXT.
"""
import argparse
import os
import re
import sys
from typing import Any, Dict, List

from llm_client import call_chat, load_llm_config
from utils import now_iso

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_DIR = os.path.dirname(_SCRIPTS_DIR)


# ---------------------------------------------------------------------------
# TXT parser for analyst output
# ---------------------------------------------------------------------------

def _parse_analyst_txt(text: str) -> Dict[str, Any]:
    """
    Parse aggregated analyst TXT into a structured dict for the fallback report.
    Extracts confirmed/inconclusive blocks and header metadata.
    """
    result: Dict[str, Any] = {
        "summary": "",
        "rejected_count": 0,
        "confirmed": [],
        "inconclusive": [],
    }

    # Extract overall summary (first Summary: line found)
    m = re.search(r"^Summary:\s*(.+)$", text, re.MULTILINE)
    if m:
        result["summary"] = m.group(1).strip()

    # Sum up rejected counts across all chunks
    for m in re.finditer(r"rejected=(\d+)", text):
        result["rejected_count"] += int(m.group(1))

    # Extract CONFIRMED blocks
    for block_text in re.findall(
        r"\[CONFIRMED\]\s*-{3,}\s*(.*?)-{3,}", text, re.DOTALL
    ):
        block = _parse_finding_block(block_text)
        block["verdict"] = "confirmed"
        result["confirmed"].append(block)

    # Extract INCONCLUSIVE blocks
    for block_text in re.findall(
        r"\[INCONCLUSIVE\]\s*-{3,}\s*(.*?)-{3,}", text, re.DOTALL
    ):
        block = _parse_finding_block(block_text)
        block["verdict"] = "inconclusive"
        result["inconclusive"].append(block)

    return result


def _parse_finding_block(text: str) -> Dict[str, Any]:
    """Extract fields from a single CONFIRMED or INCONCLUSIVE block."""
    block: Dict[str, Any] = {}

    for field, prefix in [
        ("pid", r"^PID:\s*(.+)$"),
        ("ppid", r"^PPID:\s*(.+)$"),
        ("image", r"^Image:\s*(.+)$"),
        ("cmdline", r"^Cmdline:\s*(.+)$"),
        ("severity", r"^Severity:\s*(.+)$"),
        ("mitre", r"^MITRE:\s*(.+)$"),
    ]:
        m = re.search(prefix, text, re.MULTILINE)
        if m:
            block[field] = m.group(1).strip()

    # Justification block (indented lines after "Justification:")
    m = re.search(r"Justification:\n((?:  .+\n?)+)", text)
    if m:
        block["justification"] = " ".join(
            l.strip() for l in m.group(1).strip().splitlines()
        )

    # Key Evidence lines ("  - ...")
    block["key_evidence"] = re.findall(r"^  - (.+)$", text, re.MULTILINE)

    return block


# ---------------------------------------------------------------------------
# LLM mode
# ---------------------------------------------------------------------------

def _report_with_llm(
    analyst_path: str, prompt_path: str, llm_config_path: str
) -> str:
    with open(prompt_path, "r", encoding="utf-8", errors="ignore") as f:
        system_prompt = f.read().strip()

    with open(analyst_path, "r", encoding="utf-8", errors="ignore") as f:
        analyst_text = f.read()

    llm_config = load_llm_config(llm_config_path)
    content = call_chat(
        [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": "Pivot analyst report (all chunks):\n\n" + analyst_text,
            },
        ],
        llm_config,
    )
    return content


# ---------------------------------------------------------------------------
# Fallback structured report (no LLM)
# ---------------------------------------------------------------------------

def _generate_fallback_report(parsed: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# Incident Triage Report")
    lines.append(f"_Generated: {now_iso()}_")
    lines.append("")

    confirmed = parsed.get("confirmed", [])
    inconclusive = parsed.get("inconclusive", [])
    rejected_count = parsed.get("rejected_count", 0)
    summary = parsed.get("summary", "")

    # --- Executive Summary ---
    lines.append("## Executive Summary")
    if summary:
        lines.append(summary)
    else:
        lines.append(
            f"Agent 2 confirmed **{len(confirmed)}** finding(s), "
            f"marked **{len(inconclusive)}** inconclusive, "
            f"and rejected **{rejected_count}**."
        )
    lines.append("")

    # --- Attack Timeline (from confirmed) ---
    lines.append("## Attack Timeline")
    if confirmed:
        for f in confirmed:
            pid = f.get("pid", "?")
            image = f.get("image", "?")
            cmdline = f.get("cmdline", "")
            severity = f.get("severity", "")
            entry = f"- **[{severity}]** PID {pid} ({image})"
            if cmdline:
                entry += f": `{cmdline[:120]}`"
            lines.append(entry)
    else:
        lines.append("_No confirmed findings to build a timeline from._")
    lines.append("")

    # --- MITRE ATT&CK ---
    lines.append("## MITRE ATT&CK Mapping")
    mitre_rows = [
        f for f in confirmed
        if f.get("mitre") and f["mitre"].strip()
    ]
    if mitre_rows:
        lines.append("| Technique | Evidence (PID / Image) |")
        lines.append("|-----------|------------------------|")
        for f in mitre_rows:
            lines.append(
                f"| {f['mitre']} | PID {f.get('pid', '?')} ({f.get('image', '?')}) |"
            )
    else:
        lines.append("_No MITRE mappings provided by Agent 2._")
    lines.append("")

    # --- IOCs ---
    lines.append("## Indicators of Compromise (IOCs)")
    all_evidence: List[str] = []
    for f in confirmed:
        all_evidence.extend(f.get("key_evidence", []))
    if all_evidence:
        lines.append("| Evidence |")
        lines.append("|----------|")
        for e in all_evidence[:20]:
            lines.append(f"| `{e}` |")
    else:
        lines.append("_No verbatim IOCs extracted._")
    lines.append("")

    # --- Recommendations ---
    lines.append("## Recommendations")
    if confirmed:
        lines.append("1. **Immediate**: Isolate affected host from the network.")
        lines.append("2. **Investigation**: Collect full disk image; hunt fleet for extracted IOCs.")
        lines.append("3. **Remediation**: Rotate credentials of affected accounts; patch entry point.")
    else:
        lines.append("1. **Review inconclusive findings** — manual analysis required.")
        lines.append("2. **Collect additional artifacts** (disk image, EDR telemetry).")
    lines.append("")

    # --- Confidence Assessment ---
    lines.append("## Confidence Assessment")
    lines.append(
        f"**{len(confirmed)}** confirmed finding(s) with corroborating evidence. "
        f"**{len(inconclusive)}** inconclusive finding(s) requiring manual review. "
        f"**{rejected_count}** finding(s) rejected as benign."
    )
    if inconclusive:
        lines.append(
            "Inconclusive items may represent deleted artefacts or insufficient memory "
            "capture coverage."
        )
    lines.append("")
    lines.append("---")
    lines.append("_Source: `aggregated_analyst.txt` — see per-chunk analyst.txt for full evidence._")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Report Writer — Agent 3")
    parser.add_argument(
        "--analyst", required=True,
        help="Path to aggregated_analyst.txt (all chunks combined)"
    )
    parser.add_argument("--out",        required=True, help="Output path for report.md")
    parser.add_argument("--use-llm",    action="store_true", help="Use LLM for narrative report")
    parser.add_argument("--llm-config", default=os.path.join(_REPO_DIR, "llm_config.json"))
    parser.add_argument("--prompt",     default=os.path.join(_REPO_DIR, "prompts", "agent3_report.md"))
    args = parser.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)

    if args.use_llm:
        try:
            print("[report] Running LLM report generation...", file=sys.stderr)
            content = _report_with_llm(args.analyst, args.prompt, args.llm_config)
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(content.strip() + "\n")
            print(f"[report] LLM report written: {args.out}", file=sys.stderr)
            return
        except Exception as exc:
            print(
                f"[report] LLM failed ({exc}), falling back to structured report.",
                file=sys.stderr,
            )

    # Fallback: structured Markdown without LLM
    with open(args.analyst, "r", encoding="utf-8", errors="ignore") as f:
        analyst_text = f.read()

    parsed = _parse_analyst_txt(analyst_text)
    content = _generate_fallback_report(parsed)

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(content + "\n")
    print(f"[report] Structured report written: {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
