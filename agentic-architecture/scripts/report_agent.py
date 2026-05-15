#!/usr/bin/env python3
"""
Report Writer — Agent 3 du pipeline forensique.

Reçoit la sortie validée de l'Agent 2 (analyst.json) et génère un rapport
d'incident Markdown structuré selon les phases MITRE ATT&CK.

En mode LLM : génère un récit narratif de l'attaque.
En mode fallback : génère un rapport structuré à partir des données brutes.
"""
import argparse
import json
import os
import sys
from typing import Dict, List

from llm_client import call_chat, load_llm_config
from utils import load_json

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_DIR = os.path.dirname(_SCRIPTS_DIR)


# ---------------------------------------------------------------------------
# Mode LLM : rapport narratif
# ---------------------------------------------------------------------------

def _report_with_llm(analyst_path: str, pivot_path: str, prompt_path: str, llm_config_path: str) -> str:
    with open(prompt_path, "r", encoding="utf-8", errors="ignore") as f:
        system_prompt = f.read().strip()

    analyst = load_json(analyst_path)
    # On n'envoie que les findings validés + summary pour économiser les tokens
    context_data = {
        "analyst_summary": analyst.get("analyst_summary", ""),
        "validated_findings": analyst.get("validated_findings", []),
        "inconclusive_findings": analyst.get("inconclusive_findings", []),
        "rejected_count": len(analyst.get("rejected_findings", [])),
    }
    context_json = json.dumps(context_data, indent=2)

    config = load_llm_config(llm_config_path)
    content = call_chat([
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "Validated findings from Agent 2:\n\n" + context_json}
    ], config)

    return content


# ---------------------------------------------------------------------------
# Mode fallback : rapport structuré sans LLM
# ---------------------------------------------------------------------------

def _generate_fallback_report(analyst: Dict, pivot: Dict) -> str:
    lines: List[str] = []
    lines.append("# Incident Triage Report")
    lines.append(f"_Generated at: {analyst.get('generated_at', 'unknown')}_")
    lines.append("")

    # Summary
    summary = analyst.get("analyst_summary", "")
    validated = analyst.get("validated_findings", [])
    rejected  = analyst.get("rejected_findings", [])
    inconclusive = analyst.get("inconclusive_findings", [])

    lines.append("## Summary")
    if summary:
        lines.append(summary)
    else:
        lines.append(
            f"Agent 2 validated **{len(validated)}** finding(s), "
            f"rejected **{len(rejected)}**, "
            f"and marked **{len(inconclusive)}** as inconclusive."
        )
    lines.append("")

    # Confirmed findings (the core of the report)
    if validated:
        lines.append("## Confirmed Malicious Activity")
        for f in validated:
            target = f.get("target", "?")
            phase  = f.get("attack_phase", "unknown")
            conf   = f.get("confidence", "?")
            justif = f.get("justification", "")
            evidence = f.get("key_evidence", [])

            lines.append(f"### {target}")
            lines.append(f"- **MITRE Phase**: {phase}")
            lines.append(f"- **Confidence**: {conf}")
            lines.append(f"- **Justification**: {justif}")
            if evidence:
                lines.append("- **Key Evidence**:")
                lines.append("```")
                for e in evidence[:5]:
                    lines.append(f"  {e}")
                lines.append("```")
            lines.append("")
    else:
        lines.append("## Confirmed Malicious Activity")
        lines.append("_No findings were confirmed by Agent 2._")
        lines.append("")

    # Inconclusive
    if inconclusive:
        lines.append("## Inconclusive (Requires Manual Review)")
        for f in inconclusive:
            target = f.get("target", "?")
            justif = f.get("justification", "")
            lines.append(f"- **{target}**: {justif}")
        lines.append("")

    # Rejected (brief)
    if rejected:
        lines.append("## Rejected (Confirmed Benign)")
        for f in rejected:
            target = f.get("target", "?")
            justif = f.get("justification", "")
            lines.append(f"- ~~{target}~~: {justif}")
        lines.append("")

    # Evidence pointers
    lines.append("## Evidence Pointers")
    lines.append("- Full validated analysis: `analyst.json`")
    lines.append("- Raw grep results: `pivot.json`")
    lines.append("- Raw Volatility outputs: artifact root directory")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Report Writer — Agent 3")
    parser.add_argument("--analyst", required=True, help="Path to analyst.json (Agent 2 output)")
    parser.add_argument("--pivot",   required=True, help="Path to pivot.json (grep output)")
    parser.add_argument("--out",     required=True, help="Output report.md path")
    parser.add_argument("--use-llm", action="store_true", help="Use LLM to generate narrative report")
    parser.add_argument("--llm-config", default=os.path.join(_REPO_DIR, "llm_config.json"))
    parser.add_argument("--prompt",     default=os.path.join(_REPO_DIR, "prompts", "agent3_report.md"))
    args = parser.parse_args()

    if args.use_llm:
        try:
            print("[report] Running LLM report generation...", file=sys.stderr)
            content = _report_with_llm(args.analyst, args.pivot, args.prompt, args.llm_config)
            os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(content.strip() + "\n")
            print("[report] LLM report complete.", file=sys.stderr)
            return
        except Exception as exc:
            print(f"[report] LLM failed ({exc}), falling back to structured report.", file=sys.stderr)

    # Fallback : rapport structuré sans LLM
    analyst = load_json(args.analyst)
    pivot   = load_json(args.pivot)
    content = _generate_fallback_report(analyst, pivot)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(content + "\n")
    print("[report] Structured report generated (no LLM).", file=sys.stderr)


if __name__ == "__main__":
    main()
