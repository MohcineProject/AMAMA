#!/usr/bin/env python3
"""
Triage Agent — Agent 1 du pipeline forensique.

Approche : LLM en premier, avec pré-traitement déterministe pour enrichir
le contexte avant envoi (arbre de processus, anomalies de spawn, SIDs).
Les règles keyword ne servent que de filet de secours si le LLM échoue.
"""
import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

from llm_client import call_chat, extract_json, load_llm_config
from utils import (
    extract_processes,
    find_value_by_key_substring,
    is_whitelisted_path,
    load_json,
    load_whitelist,
    now_iso,
    pick_strings,
    write_json,
)

# Enfants inhabituels pour des parents spécifiques (anomalie de spawn)
_UNUSUAL_CHILDREN = {
    "winword.exe":   {"powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "rundll32.exe"},
    "excel.exe":     {"powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "rundll32.exe"},
    "outlook.exe":   {"powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe"},
    "acrord32.exe":  {"powershell.exe", "cmd.exe"},
    "chrome.exe":    {"powershell.exe", "cmd.exe", "wscript.exe"},
    "firefox.exe":   {"powershell.exe", "cmd.exe"},
}

_KNOWN_LEGIT_PARENTS = {
    "explorer.exe", "services.exe", "wininit.exe", "winlogon.exe",
    "smss.exe", "csrss.exe", "lsass.exe", "svchost.exe",
}


# ---------------------------------------------------------------------------
# Pré-traitement déterministe (enrichit le contexte AVANT le LLM)
# ---------------------------------------------------------------------------

def _build_process_tree(processes: Dict[str, Dict]) -> Dict[str, Any]:
    """Construit un index pid→proc et un index ppid→[child pids]."""
    by_pid: Dict[str, Dict] = {}
    children: Dict[str, List[str]] = {}
    for _, proc in processes.items():
        pid  = find_value_by_key_substring(proc, "PID")
        ppid = find_value_by_key_substring(proc, "PPID")
        if pid:
            by_pid[pid] = proc
            children.setdefault(ppid, []).append(pid)
    return {"by_pid": by_pid, "children": children}


def _extract_anomalies(processes: Dict[str, Dict], tree: Dict[str, Any]) -> List[str]:
    """
    Détecte des anomalies structurelles avant envoi au LLM :
    - spawn inhabituel (Office/browser → shell)
    - processus cumulant SID SYSTEM + SID utilisateur
    - shell spawning un volume anormal d'enfants
    """
    anomalies: List[str] = []
    by_pid   = tree["by_pid"]
    children = tree["children"]

    for pid, proc in by_pid.items():
        image        = (find_value_by_key_substring(proc, "ImageFileName") or "").lower()
        ppid         = find_value_by_key_substring(proc, "PPID")
        parent_proc  = by_pid.get(ppid, {})
        parent_image = (find_value_by_key_substring(parent_proc, "ImageFileName") or "").lower()

        # Spawn Office/browser → interpréteur shell
        for known_parent, bad_children in _UNUSUAL_CHILDREN.items():
            if known_parent in parent_image and image in bad_children:
                anomalies.append(
                    f"SPAWN ANOMALY: {parent_image} (PID {ppid}) -> {image} (PID {pid}) "
                    f"— document/browser process should not launch a shell interpreter"
                )

        # Processus portant à la fois SYSTEM et un SID utilisateur
        sids = pick_strings(proc.get("AssociatedSIDs(using windows.getsids)", {}) or {})
        has_system = any("system" in s.lower() or "s-1-5-18" in s.lower() for s in sids)
        has_user   = any("s-1-5-21" in s.lower() for s in sids)
        if has_system and has_user and image not in _KNOWN_LEGIT_PARENTS:
            anomalies.append(
                f"PRIVILEGE ANOMALY: {image} (PID {pid}) holds both SYSTEM and user SIDs "
                f"— possible token impersonation or privilege escalation"
            )

        # Shell avec trop d'enfants
        n_children = len(children.get(pid, []))
        if n_children > 5 and image in {"cmd.exe", "powershell.exe", "wscript.exe"}:
            anomalies.append(
                f"SPAWN VOLUME: {image} (PID {pid}) spawned {n_children} child processes "
                f"— unusual for an interactive shell"
            )

    return anomalies


def _build_llm_context(
    processes: Dict[str, Dict],
    tree: Dict[str, Any],
    anomalies: List[str],
    whitelist: List[str],
    top_n: int,
) -> str:
    """
    Construit un contexte synthétique compact à envoyer au LLM.
    On n'envoie PAS le JSON brut — on envoie une vue enrichie
    et pré-filtrée pour économiser les tokens.
    """
    lines: List[str] = ["=== PROCESS LIST ==="]

    for pid, proc in tree["by_pid"].items():
        image   = find_value_by_key_substring(proc, "ImageFileName") or "?"
        ppid    = find_value_by_key_substring(proc, "PPID") or "?"
        created = find_value_by_key_substring(proc, "CreateTime") or "?"
        exited  = find_value_by_key_substring(proc, "ExitTime") or ""

        commands_obj = {}
        for key in proc:
            if "AssociatedCommands" in str(key):
                commands_obj = proc.get(key, {})
                break
        cmds = [c for c in pick_strings(commands_obj) if c.strip()]

        # DLLs non-whitelistées seulement (évite le bruit ntdll/kernel32)
        dlls = [
            v for v in pick_strings(proc.get("DllsLoaded", {}))
            if v.lower().endswith(".dll") and not is_whitelisted_path(v, whitelist)
        ]

        # Adresses étrangères extraites proprement depuis les clés ForeignAddr
        net_foreign: List[str] = []
        for key in proc:
            if "NetworkEvents" in str(key):
                net_obj = proc.get(key, {})
                if isinstance(net_obj, dict):
                    for k, v in net_obj.items():
                        if "ForeignAddr" in str(k) and isinstance(v, str) and v.strip():
                            net_foreign.append(v)
                break

        sids = [s for s in pick_strings(
            proc.get("AssociatedSIDs(using windows.getsids)", {}) or {}
        ) if s.strip() and not s.upper().startswith("SID")]

        parent_proc  = tree["by_pid"].get(ppid, {})
        parent_image = find_value_by_key_substring(parent_proc, "ImageFileName") or "unknown"

        lines.append(f"\n[PID {pid}] {image}")
        lines.append(f"  Parent : PID {ppid} ({parent_image})")
        lines.append(f"  Start  : {created}" + (f"  |  Exit: {exited}" if exited else ""))
        if cmds:
            lines.append("  Commands:")
            for c in cmds[:4]:
                lines.append(f"    > {c}")
        if dlls:
            lines.append(f"  Non-whitelisted DLLs: {', '.join(dlls[:6])}")
        if net_foreign:
            lines.append(f"  Foreign connections: {', '.join(net_foreign[:4])}")
        if sids:
            lines.append(f"  SIDs/Users: {', '.join(sids[:4])}")

    lines.append("\n=== PRE-COMPUTED STRUCTURAL ANOMALIES ===")
    if anomalies:
        for a in anomalies:
            lines.append(f"  [!] {a}")
    else:
        lines.append("  None detected by pre-processor.")

    lines.append(f"\n=== TASK ===")
    lines.append(f"Identify the top {top_n} most suspicious processes.")
    lines.append("Prioritize spawn chain reasoning over individual keyword matching.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Chemin LLM (principal)
# ---------------------------------------------------------------------------

def _triage_with_llm(
    data: Dict[str, Any],
    processes: Dict[str, Dict],
    tree: Dict[str, Any],
    anomalies: List[str],
    whitelist: List[str],
    prompt_path: str,
    llm_config_path: str,
    top_n: int,
) -> Dict[str, Any]:

    with open(prompt_path, "r", encoding="utf-8", errors="ignore") as f:
        system_prompt = f.read().strip()

    context = _build_llm_context(processes, tree, anomalies, whitelist, top_n)

    llm_config = load_llm_config(llm_config_path)
    raw = call_chat([
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": context}
    ], llm_config)

    result = extract_json(raw)

    # Garantir les clés attendues par le pivot en aval
    result.setdefault("generated_at", now_iso())
    result.setdefault("top_n", top_n)
    result.setdefault("suspicious_processes", [])
    result.setdefault("suspicious_paths", [])
    result.setdefault("suspicious_services", [])
    result.setdefault("suspicious_tasks", [])

    return result


# ---------------------------------------------------------------------------
# Filet de secours (règles — uniquement si LLM indisponible)
# ---------------------------------------------------------------------------

def _rule_based_fallback(
    data: Dict[str, Any],
    processes: Dict[str, Dict],
    config: Dict[str, Any],
    whitelist: List[str],
) -> Dict[str, Any]:
    """Scoring par règles simples. Utilisé UNIQUEMENT si le LLM échoue."""
    keywords        = [k.lower() for k in config.get("suspicious_keywords", [])]
    suspicious_dirs = [d.lower() for d in config.get("suspicious_dirs", [])]
    top_n           = config.get("top_n", 10)

    _LEGIT_NAMES = {
        "svchost.exe", "services.exe", "explorer.exe", "lsass.exe", "csrss.exe",
        "wininit.exe", "winlogon.exe", "smss.exe", "taskhost.exe", "taskhostw.exe",
        "spoolsv.exe", "searchindexer.exe", "conhost.exe", "dllhost.exe",
        "msiexec.exe", "wermgr.exe", "fontdrvhost.exe", "dwm.exe", "sihost.exe",
        "runtimebroker.exe", "securityhealthservice.exe", "logonui.exe",
    }

    scored: List[Dict[str, Any]] = []
    for _, proc in processes.items():
        reasons: List[str] = []
        score = 0
        image = find_value_by_key_substring(proc, "ImageFileName")
        pid   = find_value_by_key_substring(proc, "PID")
        ppid  = find_value_by_key_substring(proc, "PPID")

        commands_obj = {}
        for key in proc:
            if "AssociatedCommands" in str(key):
                commands_obj = proc.get(key, {})
                break
        cmds = pick_strings(commands_obj)
        dlls = pick_strings(proc.get("DllsLoaded", {}))

        for cmd in cmds:
            if any(k in cmd.lower() for k in keywords):
                score += 3
                reasons.append(f"Keyword match in command: {cmd}")
                break

        for val in [image] + dlls:
            low = val.lower() if val else ""
            if low and not is_whitelisted_path(low, whitelist):
                if any(d in low for d in suspicious_dirs):
                    score += 2
                    reasons.append(f"Unusual path: {val}")
                    break

        img_lower = image.lower() if image else ""
        if img_lower not in _LEGIT_NAMES and re.search(r"[a-f0-9]{8,}\.exe$", img_lower):
            score += 2
            reasons.append(f"Randomized hex name: {image}")

        scored.append({
            "pid": pid, "ppid": ppid, "image": image,
            "score": score, "reasons": reasons,
            "evidence": {"commands": cmds[:5], "dlls": dlls[:5], "network": []}
        })

    scored.sort(key=lambda x: x.get("score", 0), reverse=True)
    suspicious = [s for s in scored if s.get("score", 0) > 0][:top_n]

    paths: List[Dict] = []
    seen: set = set()
    for item in suspicious:
        img = item.get("image") or ""
        if img and img.lower() not in seen and not is_whitelisted_path(img, whitelist):
            paths.append({"path": img, "related_pids": [item.get("pid")], "reason": "Unusual image path"})
            seen.add(img.lower())

    return {
        "generated_at": now_iso(),
        "top_n": top_n,
        "suspicious_processes": suspicious,
        "suspicious_paths": paths,
        "suspicious_services": [],
        "suspicious_tasks": [],
        "_fallback": True,
        "_fallback_reason": "LLM unavailable — rule-based scoring used"
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_DIR    = os.path.dirname(_SCRIPTS_DIR)


def main() -> None:
    parser = argparse.ArgumentParser(description="Forensic Triage Agent — LLM-first")
    parser.add_argument("--collector",  required=True)
    parser.add_argument("--config",     default=os.path.join(_REPO_DIR, "config.json"))
    parser.add_argument("--whitelist",  default=os.path.join(_SCRIPTS_DIR, "whitelist.txt"))
    parser.add_argument("--out",        required=True)
    parser.add_argument("--llm-config", default=os.path.join(_REPO_DIR, "llm_config.json"))
    parser.add_argument("--prompt",     default=os.path.join(_REPO_DIR, "prompts", "agent1_triage.md"))
    parser.add_argument("--no-llm",     action="store_true", help="Force rule-based fallback (debug only)")
    # Rétrocompatibilité : --use-llm accepté mais ignoré (LLM est toujours actif)
    parser.add_argument("--use-llm",    action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    data = load_json(args.collector)
    with open(args.config, "r", encoding="utf-8", errors="ignore") as f:
        config = json.load(f)
    whitelist = load_whitelist(args.whitelist)
    top_n     = config.get("top_n", 10)

    # Pré-traitement déterministe (toujours exécuté)
    processes = extract_processes(data)
    tree      = _build_process_tree(processes)
    anomalies = _extract_anomalies(processes, tree)

    output: Optional[Dict[str, Any]] = None

    if not args.no_llm:
        try:
            print("[triage] Running LLM analysis...", file=sys.stderr)
            output = _triage_with_llm(
                data, processes, tree, anomalies,
                whitelist, args.prompt, args.llm_config, top_n
            )
            print("[triage] LLM analysis complete.", file=sys.stderr)
        except Exception as exc:
            print(f"[triage] LLM failed ({exc}), falling back to rules.", file=sys.stderr)

    if output is None:
        print("[triage] Using rule-based fallback.", file=sys.stderr)
        output = _rule_based_fallback(data, processes, config, whitelist)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    write_json(args.out, output)


if __name__ == "__main__":
    main()

    reasons: List[str] = []
    score = 0

if __name__ == "__main__":
    main()
