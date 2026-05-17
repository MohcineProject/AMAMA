#!/usr/bin/env python3
"""
Pivot Analyst — Agent 2 du pipeline forensique.

Reçoit les preuves grepées (pivot.json) et les confronte au triage initial.
Pour chaque cible (PID ou path suspect identifié par Agent 1), l'Agent 2 :
  - Lit les lignes réelles extraites des artefacts Volatility
  - Valide ou rejette la suspicion avec justification
  - Classe le verdict : confirmed / rejected / inconclusive

Cela élimine les faux positifs de l'Agent 1 et empêche le rapport
de contenir des findings non corroborés par les preuves.
"""
import argparse
import json
import os
import sys
from typing import Any, Dict, List

from llm_client import call_chat, extract_json, load_llm_config
from utils import load_json, now_iso, write_json

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_DIR = os.path.dirname(_SCRIPTS_DIR)


# ---------------------------------------------------------------------------
# Pré-traitement : structurer le contexte pour le LLM
# ---------------------------------------------------------------------------

def _build_llm_context(
    triage: Dict[str, Any],
    pivot: Dict[str, Any],
    max_lines_per_target: int = 40,
) -> str:
    """
    Fusionne triage + pivot en un contexte compact pour l'Agent 2.
    Chaque cible est présentée avec :
      - Pourquoi Agent 1 l'a flaggée (reasons)
      - Les lignes de preuve grepées dans les artefacts
    """
    lines: List[str] = []

    lines.append("=== TRIAGE FINDINGS TO VALIDATE ===")
    lines.append("For each finding below, you will see WHY Agent 1 flagged it,")
    lines.append("followed by the ACTUAL EVIDENCE lines from Volatility artifacts.")
    lines.append("Your job: confirm, reject, or mark inconclusive each finding.\n")

    # --- Par PID ---
    by_pid = pivot.get("by_pid", {})
    triage_procs = {p.get("pid"): p for p in triage.get("suspicious_processes", []) if p.get("pid")}

    for pid, evidence_files in by_pid.items():
        triage_entry = triage_procs.get(pid, {})
        image   = triage_entry.get("image", "unknown")
        reasons = triage_entry.get("reasons", [])
        score   = triage_entry.get("score", "?")
        phase   = triage_entry.get("attack_phase", "unknown")

        lines.append(f"\n--- [PID {pid}] {image} (score={score}, phase={phase}) ---")
        lines.append(f"  Agent 1 reasons: {'; '.join(reasons) if reasons else 'none given'}")

        budget = max_lines_per_target
        if evidence_files:
            for fname, hits in evidence_files.items():
                alloc = min(len(hits), budget)
                if alloc <= 0:
                    break
                lines.append(f"  [{fname}] ({len(hits)} hits, showing {alloc}):")
                for h in hits[:alloc]:
                    lines.append(f"    {h}")
                budget -= alloc
        else:
            lines.append("  Evidence: NO MATCH FOUND in any artifact file")

    # --- Par Path ---
    by_path = pivot.get("by_path", {})
    triage_paths = {p.get("path"): p for p in triage.get("suspicious_paths", []) if p.get("path")}

    for path, evidence_files in by_path.items():
        triage_entry = triage_paths.get(path, {})
        reason = triage_entry.get("reason", "flagged by triage")
        pids   = triage_entry.get("related_pids", [])

        lines.append(f"\n--- [PATH] {path} (related PIDs: {pids}) ---")
        lines.append(f"  Agent 1 reason: {reason}")

        budget = max_lines_per_target
        if evidence_files:
            for fname, hits in evidence_files.items():
                alloc = min(len(hits), budget)
                if alloc <= 0:
                    break
                lines.append(f"  [{fname}] ({len(hits)} hits, showing {alloc}):")
                for h in hits[:alloc]:
                    lines.append(f"    {h}")
                budget -= alloc
        else:
            lines.append("  Evidence: NO MATCH FOUND in any artifact file")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Agent 2 : LLM pivot analysis
# ---------------------------------------------------------------------------

def _pivot_analyst_llm(
    triage: Dict[str, Any],
    pivot: Dict[str, Any],
    prompt_path: str,
    llm_config_path: str,
    max_lines_per_target: int = 40,
) -> Dict[str, Any]:

    with open(prompt_path, "r", encoding="utf-8", errors="ignore") as f:
        system_prompt = f.read().strip()

    context = _build_llm_context(triage, pivot, max_lines_per_target)

    config = load_llm_config(llm_config_path)
    raw = call_chat([
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": context},
    ], config)

    result = extract_json(raw)

    # Garantir structure attendue
    result.setdefault("generated_at", now_iso())
    result.setdefault("validated_findings", [])
    result.setdefault("rejected_findings", [])
    result.setdefault("inconclusive_findings", [])
    result.setdefault("analyst_summary", "")

    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Pivot Analyst — Agent 2 (LLM validation)")
    parser.add_argument("--triage",     required=True, help="Path to triage.json (Agent 1 output)")
    parser.add_argument("--pivot",      required=True, help="Path to pivot.json (grep output)")
    parser.add_argument("--out",        required=True, help="Output path for validated findings")
    parser.add_argument("--llm-config", default=os.path.join(_REPO_DIR, "llm_config.json"))
    parser.add_argument("--prompt",     default=os.path.join(_REPO_DIR, "prompts", "agent2_pivot.md"))
    parser.add_argument("--max-lines",  type=int, default=40, help="Max evidence lines per target")
    args = parser.parse_args()

    triage = load_json(args.triage)
    pivot  = load_json(args.pivot)

    print("[pivot-analyst] Running LLM validation of findings...", file=sys.stderr)
    try:
        output = _pivot_analyst_llm(
            triage, pivot, args.prompt, args.llm_config, args.max_lines
        )
        print("[pivot-analyst] LLM validation complete.", file=sys.stderr)
    except Exception as exc:
        # Si le LLM échoue, on passe tout en "inconclusive" pour ne pas bloquer le pipeline
        print(f"[pivot-analyst] LLM failed ({exc}), marking all as inconclusive.", file=sys.stderr)
        all_targets = []
        for proc in triage.get("suspicious_processes", []):
            all_targets.append({
                "target": f"PID {proc.get('pid')} ({proc.get('image', '?')})",
                "verdict": "inconclusive",
                "justification": f"LLM unavailable — cannot validate. Original reasons: {'; '.join(proc.get('reasons', []))}"
            })
        output = {
            "generated_at": now_iso(),
            "validated_findings": [],
            "rejected_findings": [],
            "inconclusive_findings": all_targets,
            "analyst_summary": "LLM validation failed — all findings are inconclusive.",
            "_fallback": True,
        }

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    write_json(args.out, output)


if __name__ == "__main__":
    main()
