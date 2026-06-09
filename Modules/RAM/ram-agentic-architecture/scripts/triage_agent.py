#!/usr/bin/env python3
"""
Triage Agent — Agent 1 of the forensic pipeline.

Reads a FIND_EVIL collector chunk (custom key=value text format),
flags suspicious processes with the LLM, and writes triage.txt.

Approach: LLM-first with deterministic pre-processing for anomaly
detection. Rule-based scoring is a fallback if the LLM is unavailable.
"""
import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

from llm_client import call_chat, extract_json, load_llm_config, get_last_call_meta, get_last_usage, write_agent_call
from utils import is_whitelisted_path, load_json, load_whitelist, now_iso

# Unusual parent→child spawn pairs
_UNUSUAL_CHILDREN = {
    "winword.exe":   {"powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "rundll32.exe"},
    "excel.exe":     {"powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "rundll32.exe"},
    "outlook.exe":   {"powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe"},
    "acrord32.exe":  {"powershell.exe", "cmd.exe"},
    "chrome.exe":    {"powershell.exe", "cmd.exe", "wscript.exe"},
    "firefox.exe":   {"powershell.exe", "cmd.exe"},
    "powerpnt.exe":  {"powershell.exe", "cmd.exe", "wscript.exe"},
}

_KNOWN_LEGIT_PARENTS = {
    "explorer.exe", "services.exe", "wininit.exe", "winlogon.exe",
    "smss.exe", "csrss.exe", "lsass.exe", "svchost.exe",
}

# Known field names for the chunk parser
_KNOWN_FIELDS = ["pid", "ppid", "name", "path", "cmd", "start", "end",
                 "dlls", "nets", "sids", "privs", "handles"]


# ---------------------------------------------------------------------------
# Input parser — custom FIND_EVIL text format
# ---------------------------------------------------------------------------

def parse_input_chunk(text: str) -> List[Dict[str, str]]:
    """
    Parse a FIND_EVIL collector chunk into a list of process dicts.

    Each non-comment, non-empty line is one process:
      pid=136 ppid=4 name=Registry path= cmd="" start=... dlls=... privs=... handles=

    Fields are space-separated key=value pairs where values may contain
    spaces (e.g. timestamps). Known field names act as delimiters.
    """
    processes: List[Dict[str, str]] = []

    # Build regex that matches the start of any known field: e.g. " pid="
    # We use a lookahead pattern to find field boundaries.
    field_start_re = re.compile(
        r'(?<!\w)(' + '|'.join(re.escape(f) for f in _KNOWN_FIELDS) + r')='
    )

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue

        # Find positions of all field markers
        positions: List[Tuple[int, str, int]] = []
        for m in field_start_re.finditer(line):
            positions.append((m.start(), m.group(1), m.end()))

        if not positions:
            continue

        positions.sort(key=lambda x: x[0])
        proc: Dict[str, str] = {}

        for i, (start, field, val_start) in enumerate(positions):
            if i + 1 < len(positions):
                val_end = positions[i + 1][0]
                value = line[val_start:val_end].strip()
            else:
                value = line[val_start:].strip()
            proc[field] = value

        if proc.get("pid"):
            # Strip outer double quotes from cmd
            cmd = proc.get("cmd", "")
            if cmd.startswith('"') and cmd.endswith('"') and len(cmd) > 1:
                cmd = cmd[1:-1]
            proc["cmd"] = cmd
            processes.append(proc)

    return processes


# ---------------------------------------------------------------------------
# Deterministic pre-processing (runs before LLM)
# ---------------------------------------------------------------------------

def _build_process_tree(processes: List[Dict]) -> Dict[str, Any]:
    """Index by PID and build parent→children map."""
    by_pid: Dict[str, Dict] = {}
    children: Dict[str, List[str]] = {}
    for proc in processes:
        pid = proc.get("pid", "")
        ppid = proc.get("ppid", "")
        if pid:
            by_pid[pid] = proc
            children.setdefault(ppid, []).append(pid)
    return {"by_pid": by_pid, "children": children}


def _extract_anomalies(processes: List[Dict], tree: Dict) -> List[str]:
    """Detect structural anomalies before sending to the LLM."""
    anomalies: List[str] = []
    by_pid = tree["by_pid"]
    children = tree["children"]

    for proc in processes:
        pid = proc.get("pid", "")
        ppid = proc.get("ppid", "")
        image = proc.get("name", "").lower()
        parent_proc = by_pid.get(ppid, {})
        parent_image = parent_proc.get("name", "").lower()

        # Office/browser → shell interpreter
        for known_parent, bad_children in _UNUSUAL_CHILDREN.items():
            if known_parent in parent_image and image in bad_children:
                anomalies.append(
                    f"SPAWN ANOMALY: {parent_image} (PID {ppid}) -> {image} (PID {pid})"
                    f" — document/browser should not launch a shell interpreter"
                )

        # SYSTEM SID + user SID on same process
        sids = proc.get("sids", "").lower()
        if sids:
            has_system = "s-1-5-18" in sids or "system" in sids
            has_user = "s-1-5-21" in sids
            if has_system and has_user and image not in _KNOWN_LEGIT_PARENTS:
                anomalies.append(
                    f"PRIVILEGE ANOMALY: {image} (PID {pid}) holds both SYSTEM and user SIDs"
                    f" — possible token impersonation"
                )

        # Shell spawning excessive children
        n_children = len(children.get(pid, []))
        if n_children > 5 and image in {"cmd.exe", "powershell.exe", "wscript.exe"}:
            anomalies.append(
                f"SPAWN VOLUME: {image} (PID {pid}) spawned {n_children} child processes"
                f" — unusual for an interactive shell"
            )

    return anomalies


def _parse_enabled_privs(privs_field: str) -> List[str]:
    """Extract privilege names that are Enabled from the privs= field."""
    enabled = []
    for entry in privs_field.split(";"):
        entry = entry.strip()
        if not entry:
            continue
        if "|" in entry:
            name, attrs = entry.split("|", 1)
            if "Enabled" in attrs:
                enabled.append(name.strip())
    return enabled


def _build_llm_context(
    processes: List[Dict],
    tree: Dict,
    anomalies: List[str],
    whitelist: List[str],
) -> str:
    """
    Build a compact, human-readable context block for the LLM.
    Sends a filtered view — not raw text — to save tokens.
    """
    lines: List[str] = ["=== PROCESS LIST ==="]

    for proc in processes:
        pid = proc.get("pid", "?")
        ppid = proc.get("ppid", "?")
        name = proc.get("name", "?")
        path = proc.get("path", "")
        cmd = proc.get("cmd", "")
        start = proc.get("start", "")
        end = proc.get("end", "")

        # Non-whitelisted DLLs only
        dlls_raw = [d for d in proc.get("dlls", "").split(";") if d.strip()]
        dlls = [d for d in dlls_raw if not is_whitelisted_path(d, whitelist)]

        # Network connections (non-empty entries)
        nets = [n for n in proc.get("nets", "").split(";") if n.strip()]

        # Enabled privileges worth noting
        enabled_privs = _parse_enabled_privs(proc.get("privs", ""))
        notable_privs = [p for p in enabled_privs if p in {
            "SeDebugPrivilege", "SeTcbPrivilege", "SeImpersonatePrivilege",
            "SeLoadDriverPrivilege", "SeTakeOwnershipPrivilege",
            "SeAssignPrimaryTokenPrivilege", "SeCreateTokenPrivilege",
        }]

        parent_name = tree["by_pid"].get(ppid, {}).get("name", "unknown")

        lines.append(f"\n[PID {pid}] {name}")
        lines.append(f"  Parent: PID {ppid} ({parent_name})")
        if path:
            lines.append(f"  Path: {path}")
        lines.append(
            f"  Start: {start}" + (f"  |  Exit: {end}" if end else "")
        )
        if cmd:
            lines.append(f"  Cmd: {cmd}")
        if dlls:
            lines.append(f"  Non-whitelisted DLLs: {', '.join(dlls[:8])}")
        if nets:
            lines.append(f"  Network connections: {', '.join(nets[:6])}")
        if notable_privs:
            lines.append(f"  Notable enabled privileges: {', '.join(notable_privs)}")

    lines.append("\n=== PRE-COMPUTED STRUCTURAL ANOMALIES ===")
    if anomalies:
        for a in anomalies:
            lines.append(f"  [!] {a}")
    else:
        lines.append("  None detected by pre-processor.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# LLM path (primary)
# ---------------------------------------------------------------------------

def _triage_with_llm(
    processes: List[Dict],
    tree: Dict,
    anomalies: List[str],
    whitelist: List[str],
    prompt_path: str,
    llm_config_path: str,
) -> Dict[str, Any]:
    with open(prompt_path, "r", encoding="utf-8", errors="ignore") as f:
        system_prompt = f.read().strip()

    context = _build_llm_context(processes, tree, anomalies, whitelist)

    llm_config = load_llm_config(llm_config_path)
    raw = call_chat([
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": context},
    ], llm_config)

    result = extract_json(raw)

    # Normalize required keys
    result.setdefault("generated_at", now_iso())
    result.setdefault("top_n", len(result.get("suspicious_processes", [])))
    result.setdefault("reasoning_summary", "")
    result.setdefault("suspicious_processes", [])

    # Remove buckets the prompt explicitly forbids
    for key in ("suspicious_paths", "suspicious_services", "suspicious_tasks"):
        result.pop(key, None)

    return result


# ---------------------------------------------------------------------------
# Rule-based fallback (only when LLM is unavailable)
# ---------------------------------------------------------------------------

_LEGIT_NAMES = {
    "svchost.exe", "services.exe", "explorer.exe", "lsass.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "smss.exe", "taskhost.exe", "taskhostw.exe",
    "spoolsv.exe", "searchindexer.exe", "conhost.exe", "dllhost.exe",
    "msiexec.exe", "wermgr.exe", "fontdrvhost.exe", "dwm.exe", "sihost.exe",
    "runtimebroker.exe", "securityhealthservice.exe", "logonui.exe",
    "registry", "system", "idle",
}


def _rule_based_fallback(
    processes: List[Dict],
    config: Dict[str, Any],
    whitelist: List[str],
) -> Dict[str, Any]:
    """Keyword/path scoring — used only if the LLM fails."""
    keywords = [k.lower() for k in config.get("suspicious_keywords", [])]
    suspicious_dirs = [d.lower() for d in config.get("suspicious_dirs", [])]

    scored: List[Dict[str, Any]] = []
    for proc in processes:
        reasons: List[str] = []
        score = 0
        name = proc.get("name", "")
        pid = proc.get("pid", "")
        ppid = proc.get("ppid", "")
        cmd = proc.get("cmd", "")
        path = proc.get("path", "")

        # Keyword match in command line
        cmd_lower = cmd.lower()
        for k in keywords:
            if k in cmd_lower:
                score += 3
                reasons.append(f"Keyword in cmdline: {k}")
                break

        # Suspicious directory
        for val in [path, name]:
            if val and not is_whitelisted_path(val, whitelist):
                if any(d in val.lower() for d in suspicious_dirs):
                    score += 2
                    reasons.append(f"Unusual path: {val}")
                    break

        # Hex-like executable name
        name_lower = name.lower()
        if name_lower not in _LEGIT_NAMES and re.search(r"[a-f0-9]{8,}\.exe$", name_lower):
            score += 2
            reasons.append(f"Hex-like executable name: {name}")

        if score > 0:
            severity = "HIGH" if score >= 5 else ("MEDIUM" if score >= 3 else "LOW")
            scored.append({
                "pid": pid,
                "ppid": ppid,
                "image": name,
                "command_line": cmd,
                "severity": severity,
                "reasons": reasons,
            })

    scored.sort(key=lambda x: len(x["reasons"]), reverse=True)

    return {
        "generated_at": now_iso(),
        "top_n": len(scored),
        "reasoning_summary": "Rule-based fallback — LLM unavailable",
        "suspicious_processes": scored,
        "_fallback": True,
    }


# ---------------------------------------------------------------------------
# Output writer — key:value TXT format
# ---------------------------------------------------------------------------

def write_triage_txt(result: Dict[str, Any], chunk_name: str, out_path: str) -> None:
    """Write the triage result as human-readable key:value TXT."""
    lines: List[str] = []
    lines.append("=== TRIAGE REPORT ===")
    lines.append(f"Generated: {result.get('generated_at', now_iso())}")
    lines.append(f"Chunk: {chunk_name}")
    summary = result.get("reasoning_summary", "")
    if summary:
        lines.append(f"Summary: {summary}")
    lines.append("")

    for proc in result.get("suspicious_processes", []):
        lines.append("[PROCESS]")
        lines.append(f"pid: {proc.get('pid', '')}")
        lines.append(f"ppid: {proc.get('ppid', '')}")
        lines.append(f"image: {proc.get('image', '')}")
        lines.append(f"cmdline: {proc.get('command_line', '')}")
        lines.append(f"severity: {proc.get('severity', '')}")
        reasons = proc.get("reasons", [])
        lines.append(f"reasons: {' | '.join(reasons) if reasons else 'none'}")
        lines.append("")

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_DIR = os.path.dirname(_SCRIPTS_DIR)


def main() -> None:
    parser = argparse.ArgumentParser(description="Forensic Triage Agent — Agent 1")
    parser.add_argument("--input",     required=True, help="Path to input chunk_*.txt")
    parser.add_argument("--config",    default=os.path.join(_REPO_DIR, "config.json"))
    parser.add_argument("--whitelist", default=os.path.join(_SCRIPTS_DIR, "whitelist.txt"))
    parser.add_argument("--out",       required=True, help="Output path for triage.txt")
    parser.add_argument("--llm-config", default=os.path.join(_REPO_DIR, "llm_config.json"))
    parser.add_argument("--prompt",    default=os.path.join(_REPO_DIR, "prompts", "agent1_triage.md"))
    parser.add_argument("--no-llm",   action="store_true", help="Force rule-based fallback")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        chunk_text = f.read()

    chunk_name = os.path.basename(args.input)
    processes = parse_input_chunk(chunk_text)
    print(f"[triage] Parsed {len(processes)} processes from {chunk_name}", file=sys.stderr)

    with open(args.config, "r", encoding="utf-8", errors="ignore") as f:
        config = json.load(f)
    whitelist = load_whitelist(args.whitelist)

    tree = _build_process_tree(processes)
    anomalies = _extract_anomalies(processes, tree)

    result: Optional[Dict[str, Any]] = None

    if not args.no_llm:
        try:
            print("[triage] Running LLM analysis...", file=sys.stderr)
            result = _triage_with_llm(
                processes, tree, anomalies, whitelist, args.prompt, args.llm_config
            )
            n = len(result.get("suspicious_processes", []))
            print(f"[triage] LLM complete — {n} suspicious processes flagged.", file=sys.stderr)
            _meta = get_last_call_meta()
            _usage = get_last_usage()
            _chunk_stem = os.path.splitext(chunk_name)[0]
            try:
                _model = load_llm_config(args.llm_config).get("model", "unknown")
            except Exception:
                _model = "unknown"
            write_agent_call("ram", {
                "call_id": _meta["call_id"], "timestamp": _meta["timestamp"],
                "agent_name": "ram/triage_agent", "model": _model,
                "tokens_in": _usage["tokens_in"], "tokens_out": _usage["tokens_out"],
                "latency_ms": _meta["latency_ms"],
                "input_files": [f"01_chunks/{_chunk_stem}.txt"],
                "output_files": [f"02_per_chunk_analysis/{_chunk_stem}/triage.txt"],
                "query_id": None, "entity": None, "verdict": None, "error": None,
            })
        except Exception as exc:
            print(f"[triage] LLM failed ({exc}), falling back to rules.", file=sys.stderr)

    if result is None:
        print("[triage] Using rule-based fallback.", file=sys.stderr)
        result = _rule_based_fallback(processes, config, whitelist)

    write_triage_txt(result, chunk_name, args.out)
    print(f"[triage] Written: {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
