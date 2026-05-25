#!/usr/bin/env python3
"""
preprocess.py — deterministic noise-reduction pass.

Reads Disk_Artifacts/*.txt and produces THREE separate input files:
  - TRIAGE_INPUT_PERSISTENCE.txt  (publisher-whitelisted persistence/execution/browser)
  - TRIAGE_INPUT_EVENTS.txt       (event-log deduped authentication summary)
  - TRIAGE_INPUT_MFT.txt          (tiered anomaly-scored MFT records + stats block)

Each file feeds its own specialized triage agent. No LLM. No classification.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from collections import defaultdict
from typing import Any, Dict, Iterator, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Record parser — handles the type=key value=val line format from _common.py
# ---------------------------------------------------------------------------

def parse_record(line: str) -> Optional[Dict[str, str]]:
    """Parse a FIND_EVIL_DISK record line into a dict. Returns None on blank/comment lines."""
    line = line.strip()
    if not line or not line.startswith("type="):
        return None

    result: Dict[str, str] = {}
    pos = 0
    n = len(line)

    while pos < n:
        while pos < n and line[pos] == " ":
            pos += 1
        if pos >= n:
            break

        eq = line.find("=", pos)
        if eq == -1:
            break
        key = line[pos:eq]
        pos = eq + 1

        if pos < n and line[pos] == '"':
            pos += 1
            chars: List[str] = []
            while pos < n:
                c = line[pos]
                if c == "\\" and pos + 1 < n:
                    nc = line[pos + 1]
                    chars.append("\\" if nc == "\\" else nc if nc == '"' else c)
                    pos += 2
                elif c == '"':
                    pos += 1
                    break
                else:
                    chars.append(c)
                    pos += 1
            result[key] = "".join(chars)
        else:
            start = pos
            while pos < n and line[pos] != " ":
                pos += 1
            result[key] = line[start:pos]

    return result if result else None


def parse_iso(s: str) -> Optional[datetime.datetime]:
    """Parse ISO8601 UTC string to aware datetime, or None."""
    if not s:
        return None
    s = s.strip().rstrip("Z").replace(" ", "T")
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(s, fmt).replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
    return None


def read_records(path: str) -> Iterator[Dict[str, str]]:
    """Yield parsed records from a file, skipping blank lines and comment lines."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            r = parse_record(line)
            if r:
                yield r


def emit_line(r: Dict[str, str]) -> str:
    """Re-serialize a record dict back to a type=key value=val line (minimal quoting)."""
    parts = []
    for k, v in r.items():
        if v is None or v == "":
            continue
        if any(c in str(v) for c in (" ", "\t", "=", '"')):
            v = str(v).replace("\\", "\\\\").replace('"', '\\"')
            parts.append(f'{k}="{v}"')
        else:
            parts.append(f"{k}={v}")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Suspicious-path check
# ---------------------------------------------------------------------------

def is_in_suspicious_path(value: str, suspicious_paths: List[str]) -> bool:
    if not value:
        return False
    v_lower = value.lower()
    return any(sp.lower() in v_lower for sp in suspicious_paths)


# ---------------------------------------------------------------------------
# Section 1: PERSISTENCE + EXECUTION (publisher-whitelisted)
# ---------------------------------------------------------------------------

def _action_path(r: Dict[str, str]) -> str:
    """Extract the primary path/action field from a record."""
    return r.get("action") or r.get("path") or r.get("data") or r.get("url") or ""


def _is_publisher_whitelisted(r: Dict[str, str], cfg: Dict[str, Any]) -> bool:
    """Return True if this record is from a known-good vendor in a canonical path.

    Whitelist policy (aggressive — drop noise, keep suspicious-path entries):
      1. Suspicious-path override always wins: NEVER whitelist.
      2. WMI placeholder stubs (needs_full_parser=true): always drop (no useful data).
      3. Canonical path match: whitelist regardless of author (enough signal of benign).
      4. Known vendor author + boring task name: whitelist even without canonical path.
      5. Everything else: keep (send to Agent 1).
    """
    wl = cfg.get("publisher_whitelist", {})
    suspicious_paths = cfg.get("suspicious_paths", [])

    action = _action_path(r)
    author = r.get("author", "").strip()
    name = r.get("name", "").strip()
    run_as = r.get("run_as", "").strip()

    # Rule 1: Suspicious-path override — never whitelist regardless of anything else
    if is_in_suspicious_path(action, suspicious_paths):
        return False

    # Rule 2: WMI placeholder stubs carry zero information — drop them
    if r.get("type") == "persistence" and r.get("mechanism") == "wmi":
        return r.get("needs_full_parser") == "true"

    path_prefixes = wl.get("path_prefixes", [])
    boring_prefixes = wl.get("boring_task_name_prefixes", [])
    author_names = wl.get("author_names", [])

    # Rule 1b: Empty action with no data — nothing to investigate, drop silently
    if not action:
        return True

    # Normalise action for prefix comparison; expand common env vars
    action_lower = action.replace("/", "\\").lower()
    action_lower = (
        action_lower
        .replace("%programfiles(x86)%", "c:\\program files (x86)")
        .replace("%programfiles%", "c:\\program files")
        .replace("%systemroot%", "c:\\windows")
        .replace("%windir%", "c:\\windows")
    )
    # Strip leading quote or space that may appear before the path
    action_lower = action_lower.lstrip('" ')
    # Collapse any double backslashes introduced by env-var expansion
    while "\\\\" in action_lower:
        action_lower = action_lower.replace("\\\\", "\\")

    # Rule 3: Canonical path is sufficient (covers shimcache/amcache system32 etc.)
    if action_lower and any(action_lower.startswith(pp.lower()) for pp in path_prefixes):
        return True

    # Rule 3b: Bare filename (no path separator) run by SYSTEM — Windows built-in implicit System32 lookup
    is_bare_filename = ("\\" not in action_lower and ":" not in action_lower)
    if is_bare_filename and run_as in ("S-1-5-18", "S-1-5-19", "S-1-5-20", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
        return True

    # Rule 4a: Known vendor author + boring task name → whitelist
    known_vendor = bool(author) and any(an.lower() in author.lower() for an in author_names if an)
    boring_name = any(name.lower().startswith(p.lower()) for p in boring_prefixes)
    if known_vendor and boring_name:
        return True

    # Rule 4b: SYSTEM-run task with boring name → treat as benign
    if run_as in ("S-1-5-18", "SYSTEM") and boring_name:
        return True

    return False


def section_persistence_execution(artifact_dir: str, cfg: Dict[str, Any]) -> Tuple[List[str], int, int]:
    """Build the PERSISTENCE + EXECUTION section. Returns (lines, total_read, dropped)."""
    sources = (
        cfg.get("artifact_files", {}).get("persistence_sources", [])
        + cfg.get("artifact_files", {}).get("execution_sources", [])
        + cfg.get("artifact_files", {}).get("browser_sources", [])
    )

    lines: List[str] = []
    total_read = 0
    dropped = 0

    # Categories in registry_autoruns.txt that carry no useful triage signal.
    drop_categories: set = {c.lower() for c in cfg.get("registry_drop_categories", [])}

    for filename in sources:
        path = os.path.join(artifact_dir, filename)
        source_lines: List[str] = []
        for r in read_records(path):
            total_read += 1
            # Drop entire category classes before the whitelist pass
            cat = r.get("category", "").strip().lower()
            if cat and cat in drop_categories:
                dropped += 1
                continue
            if _is_publisher_whitelisted(r, cfg):
                dropped += 1
                continue
            source_lines.append(emit_line(r))
        if source_lines:
            lines.append(f"# source: {filename} ({len(source_lines)} rows after whitelist)")
            lines.extend(source_lines)

    return lines, total_read, dropped


# ---------------------------------------------------------------------------
# Section 2: AUTHENTICATION + LOGON SUMMARY (event-log dedup)
# ---------------------------------------------------------------------------

def _dedup_key(r: Dict[str, str]) -> Optional[Tuple]:
    """Return the dedup key tuple for an event record, or None to always emit verbatim."""
    try:
        eid = int(r.get("id", "0"))
    except ValueError:
        eid = 0

    if eid in {4624, 4625, 4634, 4647, 4672}:
        return (eid, r.get("user", ""), r.get("src_ip", ""), r.get("logon_type", ""))
    elif eid == 4648:
        return None  # always emit — explicit credential use
    elif eid == 4688:
        return (eid, r.get("process", ""), r.get("parent_process", ""), r.get("user", ""))
    elif eid == 7045:
        return (eid, r.get("service_name", ""))
    elif eid in {4697, 4720, 4732}:
        return (eid, r.get("user", ""), r.get("target", ""))
    elif eid == 5140:
        return (eid, r.get("user", ""), r.get("share_name", ""))
    elif eid in {1, 3, 11, 13}:  # Sysmon
        return (eid, r.get("process", ""), r.get("user", ""))
    else:
        return None  # unknown/always emit verbatim


def section_auth_summary(
    artifact_dir: str,
    cfg: Dict[str, Any],
    recency_cutoff: Optional[datetime.datetime],
) -> Tuple[List[str], int, int]:
    """Build AUTH + LOGON SUMMARY section. Returns (lines, total_read, collapsed)."""
    sources = cfg.get("artifact_files", {}).get("eventlog_sources", [])
    always_emit_ids = set(cfg.get("always_emit_event_ids", [1102, 104]))

    groups: Dict[Tuple, Dict[str, Any]] = {}
    verbatim_lines: List[str] = []
    total_read = 0
    collapsed = 0

    for filename in sources:
        path = os.path.join(artifact_dir, filename)
        for r in read_records(path):
            total_read += 1
            try:
                eid = int(r.get("id", "0"))
            except ValueError:
                eid = 0

            if eid in always_emit_ids:
                verbatim_lines.append(f"# always-emit id={eid}")
                verbatim_lines.append(emit_line(r))
                continue

            key = _dedup_key(r)
            if key is None:
                verbatim_lines.append(emit_line(r))
                continue

            t = parse_iso(r.get("time", ""))
            if recency_cutoff and t and t < recency_cutoff:
                collapsed += 1
                continue

            if key not in groups:
                groups[key] = {"count": 1, "first": t, "last": t, "rep": dict(r)}
            else:
                g = groups[key]
                g["count"] += 1
                if t:
                    if g["first"] is None or t < g["first"]:
                        g["first"] = t
                    if g["last"] is None or t > g["last"]:
                        g["last"] = t

    # Format output
    lines: List[str] = []
    if verbatim_lines:
        lines.append(f"# always-emit / non-deduped events: {len(verbatim_lines)} rows")
        lines.extend(verbatim_lines)

    if groups:
        lines.append(f"# deduped event groups: {len(groups)} unique patterns")
        for key, g in sorted(groups.items(), key=lambda x: -x[1]["count"]):
            rep = g["rep"]
            rep_copy = dict(rep)
            rep_copy["type"] = "event_summary"
            rep_copy["count"] = str(g["count"])
            first_str = g["first"].strftime("%Y-%m-%dT%H:%M:%SZ") if g["first"] else ""
            last_str = g["last"].strftime("%Y-%m-%dT%H:%M:%SZ") if g["last"] else ""
            rep_copy["first"] = first_str
            rep_copy["last"] = last_str
            rep_copy.pop("time", None)
            lines.append(emit_line(rep_copy))

    return lines, total_read, collapsed


# ---------------------------------------------------------------------------
# Section 3: STRUCTURAL ANOMALIES (MFT) with tiered anomaly scoring
# ---------------------------------------------------------------------------

def _is_in_mft_whitelist(path: str, wl_prefixes: List[str]) -> bool:
    """Return True if path starts with a canonical system prefix."""
    p = path.lower().replace("/", "\\").lstrip("c:\\").lstrip("\\")
    return any(p.startswith(wp.lower()) for wp in wl_prefixes)


def _get_install_date(artifact_dir: str) -> Optional[datetime.datetime]:
    """Try to read OS install date from registry_misc.txt."""
    path = os.path.join(artifact_dir, "registry_misc.txt")
    if not os.path.exists(path):
        return None
    for r in read_records(path):
        if r.get("value", "").lower() == "installdate":
            data = r.get("data", "")
            try:
                ts = int(data)
                if ts > 1_000_000_000:  # Unix timestamp (seconds since 1970)
                    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
            except ValueError:
                pass
            t = parse_iso(data)
            if t:
                return t
    return None


def _has_pe_extension(path: str, pe_extensions: List[str]) -> bool:
    _, ext = os.path.splitext(path.lower())
    return ext in pe_extensions


def _detect_mft_anomalies(
    r: Dict[str, str],
    wl_prefixes: List[str],
    system_binary_prefixes: List[str],
    always_escalate: set,
    suspicious_paths: List[str],
    pe_extensions: List[str],
    entropy_threshold: float,
    mismatch_threshold: float,
    install_date: Optional[datetime.datetime],
) -> List[str]:
    """Return list of named anomaly tags for an MFT record (used for labeling, not gating)."""
    path = r.get("path", "")
    anomalies: List[str] = []

    # 1. extension_magic_mismatch — already flagged by mft_collector
    if r.get("magic_mismatch", ""):
        anomalies.append(f"extension_magic_mismatch:{r['magic_mismatch']}")

    # 2. recycle_bin_executable
    if "$recycle.bin" in path.lower() and _has_pe_extension(path, pe_extensions):
        anomalies.append("recycle_bin_executable")

    # 3. high_entropy — only in user-accessible paths or unknown paths
    try:
        entropy = float(r.get("entropy", "0") or "0")
    except ValueError:
        entropy = 0.0
    if entropy > entropy_threshold and not _is_in_mft_whitelist(path, wl_prefixes):
        anomalies.append(f"high_entropy:entropy={entropy:.2f}")

    # 4. missing_zone_identifier — PE in suspicious path with no Zone.Identifier
    ads = r.get("ads", "")
    if (
        _has_pe_extension(path, pe_extensions)
        and is_in_suspicious_path(path, suspicious_paths)
        and "zone.identifier" not in ads.lower()
    ):
        anomalies.append("missing_zone_identifier")

    # 5. si_fn_mismatch — only in user-writable paths
    si_created = parse_iso(r.get("created", "") or r.get("si_created", ""))
    fn_created = parse_iso(r.get("fn_created", ""))
    if si_created and fn_created and is_in_suspicious_path(path, suspicious_paths):
        delta = abs((si_created - fn_created).total_seconds())
        if delta > mismatch_threshold:
            anomalies.append(f"si_fn_mismatch:{delta:.0f}s")

    # 5b. system_path_timestomp — PE in System32/SysWOW64 with SI backdated vs FN
    if (
        si_created and fn_created
        and _is_in_mft_whitelist(path, system_binary_prefixes)
        and _has_pe_extension(path, pe_extensions)
    ):
        delta_sys = (fn_created - si_created).total_seconds()
        if delta_sys > mismatch_threshold:
            anomalies.append(f"system_path_timestomp:{delta_sys:.0f}s")

    # 6. pre_install_date — created before OS install, in user-writable path
    if install_date and si_created and is_in_suspicious_path(path, suspicious_paths):
        if si_created < install_date:
            anomalies.append(f"pre_install_date:si={si_created.strftime('%Y-%m-%dT%H:%M:%SZ')}")

    # Apply whitelist for non-always-escalate anomalies
    if anomalies and _is_in_mft_whitelist(path, wl_prefixes):
        escalate_set = set(a.split(":")[0] for a in anomalies)
        if not escalate_set.intersection(always_escalate):
            return []  # suppressed by whitelist

    return anomalies


_EXEC_EXTS = frozenset({".exe", ".dll", ".ps1", ".vbs", ".js", ".bat", ".scr", ".com", ".sys"})


def _score_mft_record(
    r: Dict[str, str],
    cfg: Dict[str, Any],
    attack_window_start: Optional[datetime.datetime],
    attack_window_end: Optional[datetime.datetime],
    suspicious_paths: List[str],
    wl_prefixes: List[str],
) -> int:
    """
    Compute a numeric anomaly score for an MFT record.

    Scoring table:
      +4  execution-capable extension (.exe/.dll/.ps1 etc.) in a suspicious path
      +3  entropy > threshold outside Program Files
      +3  SI/FN timestamp delta > 60s (timestomping indicator)
      +2  created within configured attack window
      +2  parent path is known-bad ($Recycle.Bin or non-whitelisted ProgramData subdir)
      +2  Zone.Identifier ADS absent on an executable
      -5  NSRL hash match (known-good OS file)
      +1  path depth > 8 levels inside system directories
    """
    score = 0
    path = r.get("path", "").lower()
    _, ext = os.path.splitext(path)

    scoring_cfg = cfg.get("mft_scoring", {})
    entropy_score_threshold = float(scoring_cfg.get("entropy_score_threshold", 7.0))

    # Whitelist check: suppress path-context signals for trusted system directories.
    # Files in known-good vendor paths (Program Files\Microsoft, ProgramData\Microsoft, etc.)
    # should not score +4 or +2 Zone.Id just because the path contains "ProgramData".
    is_whitelisted = _is_in_mft_whitelist(path, wl_prefixes)

    # +4: execution-capable extension in suspicious path (only for non-whitelisted paths)
    if ext in _EXEC_EXTS and is_in_suspicious_path(path, suspicious_paths) and not is_whitelisted:
        score += 4

    # +3: high entropy outside Program Files
    try:
        entropy = float(r.get("entropy", "0") or "0")
    except ValueError:
        entropy = 0.0
    if entropy > entropy_score_threshold and "program files" not in path:
        score += 3

    # +3: SI/FN timestamp delta > 60s — only meaningful in user-writable paths.
    # System files legitimately have SI/FN mismatches from Windows Update, SFC, etc.
    si_created = parse_iso(r.get("created", "") or r.get("si_created", ""))
    fn_created = parse_iso(r.get("fn_created", ""))
    if si_created and fn_created and is_in_suspicious_path(path, suspicious_paths):
        if abs((si_created - fn_created).total_seconds()) > 60:
            score += 3

    # +2: created within attack window
    if attack_window_start and attack_window_end and si_created:
        if attack_window_start <= si_created <= attack_window_end:
            score += 2

    # +2: parent path is known-bad indicator
    if "\\$recycle.bin" in path:
        score += 2
    elif "\\programdata\\" in path and not is_whitelisted:
        score += 2

    # +2: Zone.Identifier ADS absent on executable (only meaningful for non-trusted files)
    if ext in _EXEC_EXTS and not is_whitelisted:
        ads = r.get("ads", "")
        if "zone.identifier" not in ads.lower():
            score += 2

    # -5: NSRL hash match (known-good file)
    if r.get("nsrl_match", "").lower() == "true":
        score -= 5

    # +1: path depth > 8 in system directories
    if path.count("\\") > 8 and ("windows\\" in path or "program files" in path):
        score += 1

    return score


def _build_mft_stats_block(
    total_read: int,
    total_above_threshold: int,
    filtered_in: int,
    score_ge6: int,
    score_4_5: int,
    score_3: int,
    stats: Dict[str, int],
    attack_window_start: Optional[datetime.datetime],
    attack_window_end: Optional[datetime.datetime],
    threshold: int,
    top_n: int,
) -> List[str]:
    """Generate the stats block that always precedes scored records in TRIAGE_INPUT_MFT.txt."""
    lines = [
        "=== MFT SUMMARY ===",
        f"# total_records={total_read}  threshold={threshold}  top_n={top_n}",
        f"# filtered_in={filtered_in}  (from {total_above_threshold} records scoring >= {threshold})",
        f"# filtered_out={total_read - total_above_threshold}  (score < {threshold})",
        f"# score_ge6={score_ge6}  score_4_5={score_4_5}  score_3={score_3}",
        f"# entropy_anomalies={stats['entropy_anomalies']}  (entropy > 7.5 outside Program Files)",
        f"# timestomping_candidates={stats['timestomping_candidates']}  (SI/FN delta > 60s)",
        f"# missing_zone_id={stats['missing_zone_id']}  (executables in suspicious paths without Zone.Identifier)",
    ]
    if attack_window_start and attack_window_end:
        lines.append(
            f"# attack_window_hits={stats['attack_window_hits']}"
            f"  window={attack_window_start.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            f"–{attack_window_end.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
    else:
        lines.append("# attack_window=not_configured  (set mft_scoring.attack_window_start/end to enable +2 bonus)")
    lines.append("=== TOP SCORED MFT RECORDS ===")
    return lines


def section_mft_anomalies(
    artifact_dir: str,
    cfg: Dict[str, Any],
    audit_dir: Optional[str] = None,
) -> Tuple[List[str], int, int, int]:
    """
    Walk mft_records.txt, score each record via tiered anomaly scoring,
    and emit the top-N records (by score) that pass the scoring threshold.

    Also writes filtered-out records to audit_dir/mft_filtered.jsonl for traceability.

    Returns (lines, total_read, filtered_in, filtered_out_below_threshold).
    """
    mft_path = os.path.join(artifact_dir, cfg.get("artifact_files", {}).get("mft_source", "mft_records.txt"))
    if not os.path.exists(mft_path):
        return ["# mft_records.txt not found — skipping MFT scoring pass"], 0, 0, 0

    scoring_cfg = cfg.get("mft_scoring", {})
    threshold = int(scoring_cfg.get("threshold", 3))
    top_n = int(scoring_cfg.get("top_n", 200))
    attack_window_start = parse_iso(scoring_cfg.get("attack_window_start") or "")
    attack_window_end = parse_iso(scoring_cfg.get("attack_window_end") or "")

    wl_prefixes = cfg.get("mft_whitelist_path_prefixes", [])
    system_binary_prefixes = cfg.get("mft_system_binary_prefixes", ["windows\\system32", "windows\\syswow64"])
    always_escalate = set(cfg.get("mft_always_escalate_anomalies", []))
    suspicious_paths = cfg.get("suspicious_paths", [])
    pe_extensions = cfg.get("pe_extensions", [".exe", ".dll", ".scr", ".sys", ".com", ".bat", ".ps1"])
    entropy_threshold = float(cfg.get("entropy_threshold", 7.2))
    mismatch_threshold = float(cfg.get("si_fn_mismatch_threshold_seconds", 2))
    install_date = _get_install_date(artifact_dir)

    # Collect all records, score them, detect anomaly labels
    all_scored: List[Tuple[int, List[str], Dict[str, str]]] = []
    total_read = 0

    # Global stats counters (across ALL records, not just passing ones)
    stats = {
        "entropy_anomalies": 0,
        "timestomping_candidates": 0,
        "missing_zone_id": 0,
        "attack_window_hits": 0,
    }

    for r in read_records(mft_path):
        total_read += 1
        path = r.get("path", "")
        if not path:
            continue

        # Named anomaly labels (for output tagging)
        anomalies = _detect_mft_anomalies(
            r, wl_prefixes, system_binary_prefixes, always_escalate,
            suspicious_paths, pe_extensions, entropy_threshold, mismatch_threshold, install_date,
        )

        # Numeric score (determines ranking and filtering)
        score = _score_mft_record(r, cfg, attack_window_start, attack_window_end, suspicious_paths, wl_prefixes)

        # Accumulate whole-dataset stats for the summary block
        try:
            entropy = float(r.get("entropy", "0") or "0")
        except ValueError:
            entropy = 0.0
        if entropy > 7.5 and "program files" not in path.lower():
            stats["entropy_anomalies"] += 1

        si_created = parse_iso(r.get("created", "") or r.get("si_created", ""))
        fn_created = parse_iso(r.get("fn_created", ""))
        if si_created and fn_created and abs((si_created - fn_created).total_seconds()) > 60:
            stats["timestomping_candidates"] += 1

        _, ext = os.path.splitext(path.lower())
        if ext in _EXEC_EXTS and "zone.identifier" not in r.get("ads", "").lower() \
                and is_in_suspicious_path(path, suspicious_paths):
            stats["missing_zone_id"] += 1

        if attack_window_start and attack_window_end and si_created:
            if attack_window_start <= si_created <= attack_window_end:
                stats["attack_window_hits"] += 1

        # Keep any record with non-trivial score or a named anomaly
        if score > 0 or anomalies:
            all_scored.append((score, anomalies, r))

    # Sort by score descending
    all_scored.sort(key=lambda x: -x[0])

    # Split into passing (>= threshold, capped at top_n) and rejected (< threshold)
    above = [(s, a, r) for s, a, r in all_scored if s >= threshold]
    below = [(s, a, r) for s, a, r in all_scored if s < threshold]
    passing = above[:top_n]

    # Write rejected records to audit file for forensic traceability.
    # Always create the file when audit_dir is set (even if below=[] so existence
    # can be asserted by tests and analysts without extra checks).
    if audit_dir:
        os.makedirs(audit_dir, exist_ok=True)
        audit_path = os.path.join(audit_dir, "mft_filtered.jsonl")
        with open(audit_path, "w", encoding="utf-8") as af:
            for score, anomalies, r in below:
                entry = dict(r)
                entry["_score"] = score
                entry["_anomalies"] = anomalies
                af.write(json.dumps(entry) + "\n")
        print(f"[preprocess] audit: {len(below)} low-score MFT records → {audit_path}", file=sys.stderr)

    # Score distribution for stats block
    score_ge6 = sum(1 for s, _, _ in all_scored if s >= 6)
    score_4_5 = sum(1 for s, _, _ in all_scored if 4 <= s <= 5)
    score_3 = sum(1 for s, _, _ in all_scored if s == 3)

    # Build output: stats block + scored records
    lines = _build_mft_stats_block(
        total_read=total_read,
        total_above_threshold=len(above),
        filtered_in=len(passing),
        score_ge6=score_ge6,
        score_4_5=score_4_5,
        score_3=score_3,
        stats=stats,
        attack_window_start=attack_window_start,
        attack_window_end=attack_window_end,
        threshold=threshold,
        top_n=top_n,
    )

    for score, anomalies, r in passing:
        row = dict(r)
        row["type"] = "mft_anomaly"
        row["score"] = str(score)
        if anomalies:
            row["anomalies"] = " | ".join(anomalies)
        lines.append(emit_line(row))

    return lines, total_read, len(passing), len(below)


# ---------------------------------------------------------------------------
# File writers for the three output files
# ---------------------------------------------------------------------------

def _write_section_file(path: str, header_comment: str, section_header: str, lines: List[str], empty_msg: str) -> None:
    """Write a single TRIAGE_INPUT_*.txt file."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    now = datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# {os.path.basename(path)} — generated {now}\n")
        f.write(f"# {header_comment}\n\n")
        f.write("=" * 72 + "\n")
        f.write(f"=== {section_header} ===\n")
        f.write("=" * 72 + "\n")
        if lines:
            f.write("\n".join(lines) + "\n")
        else:
            f.write(f"# {empty_msg}\n")
        f.write("\n")


# ---------------------------------------------------------------------------
# Main pipeline function
# ---------------------------------------------------------------------------

def run(artifact_dir: str, cfg: Dict[str, Any], base_dir: str) -> None:
    now = datetime.datetime.now(tz=datetime.timezone.utc)

    recency_cap_days = cfg.get("recency_cap_days", 365)
    recency_cutoff = now - datetime.timedelta(days=recency_cap_days) if recency_cap_days else None

    output_dir = os.path.normpath(os.path.join(base_dir, cfg.get("output_dir", "output")))
    audit_dir = os.path.join(base_dir, "audit")
    os.makedirs(output_dir, exist_ok=True)

    persist_out = os.path.join(output_dir, "TRIAGE_INPUT_PERSISTENCE.txt")
    events_out  = os.path.join(output_dir, "TRIAGE_INPUT_EVENTS.txt")
    mft_out     = os.path.join(output_dir, "TRIAGE_INPUT_MFT.txt")

    print(f"[preprocess] artifact_dir : {artifact_dir}", file=sys.stderr)
    print(f"[preprocess] output_dir   : {output_dir}", file=sys.stderr)
    print(f"[preprocess] recency_cap  : {recency_cap_days} days (cutoff: {recency_cutoff})", file=sys.stderr)

    # Build sections
    pe_lines, pe_total, pe_dropped = section_persistence_execution(artifact_dir, cfg)
    auth_lines, auth_total, auth_collapsed = section_auth_summary(artifact_dir, cfg, recency_cutoff)
    mft_lines, mft_total, mft_in, mft_out_count = section_mft_anomalies(artifact_dir, cfg, audit_dir)

    print(
        f"[preprocess] persistence+execution: {pe_total} read, {pe_dropped} whitelisted, "
        f"{sum(1 for l in pe_lines if not l.startswith('#'))} output rows",
        file=sys.stderr,
    )
    print(
        f"[preprocess] auth+logon:            {auth_total} read, {auth_collapsed} recency-dropped, "
        f"{sum(1 for l in auth_lines if l.startswith('type='))} output rows",
        file=sys.stderr,
    )
    print(
        f"[preprocess] mft scoring:           {mft_total} records scanned, "
        f"{mft_in} passed (score >= threshold), {mft_out_count} written to audit",
        file=sys.stderr,
    )

    # Write three separate triage input files
    _write_section_file(
        persist_out,
        "Source: registry autoruns, scheduled tasks, WMI, shimcache, amcache, prefetch, browser history. Already whitelisted.",
        "PERSISTENCE + EXECUTION",
        pe_lines,
        "no persistence/execution records after whitelist",
    )

    _write_section_file(
        events_out,
        "Source: event logs (security, system, application, other). Deduplicated by (event_id, user, src_ip, logon_type).",
        "AUTHENTICATION + LOGON SUMMARY",
        auth_lines,
        "no event log records found",
    )

    _write_section_file(
        mft_out,
        "Source: mft_records.txt. Tiered anomaly scoring applied — only top-N records by score included.",
        "MFT ANOMALY SCORING",
        mft_lines,
        "no MFT records processed",
    )

    for fname, path in [("PERSISTENCE", persist_out), ("EVENTS", events_out), ("MFT", mft_out)]:
        size_kb = os.path.getsize(path) // 1024
        print(f"[preprocess] TRIAGE_INPUT_{fname}: {size_kb} KB → {path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Unit tests (run with --test)
# ---------------------------------------------------------------------------

def _run_tests() -> None:
    import tempfile

    failures = 0

    def assert_eq(desc, got, expected):
        nonlocal failures
        if got != expected:
            print(f"  FAIL [{desc}]: got {got!r}, expected {expected!r}")
            failures += 1
        else:
            print(f"  PASS [{desc}]")

    def assert_true(desc, cond):
        nonlocal failures
        if not cond:
            print(f"  FAIL [{desc}]")
            failures += 1
        else:
            print(f"  PASS [{desc}]")

    print("\n--- parse_record ---")
    r = parse_record('type=execution path="C:\\\\Users\\\\nfury\\\\AppData\\\\Roaming\\\\x.exe" entropy=7.83 artifact_source=mft')
    assert_true("parse type=execution", r is not None and r.get("type") == "execution")
    assert_true("parse path with backslashes", r and "\\" in r.get("path", ""))
    assert_eq("parse entropy", r and r.get("entropy"), "7.83")

    r2 = parse_record('type=persistence mechanism=scheduled_task name="Adobe Acrobat Update Task" action="C:\\\\Program Files (x86)\\\\Common Files\\\\Adobe\\\\ARM\\\\1.0\\\\AdobeARM.exe" author="Adobe Systems Incorporated"')
    assert_true("parse scheduled_task", r2 is not None)
    assert_eq("parse author", r2 and r2.get("author"), "Adobe Systems Incorporated")

    assert_eq("parse blank line", parse_record(""), None)
    assert_eq("parse comment", parse_record("# comment"), None)

    print("\n--- publisher whitelist ---")
    cfg = {
        "publisher_whitelist": {
            "path_prefixes": ["c:\\program files (x86)\\google"],
            "author_names": ["Google LLC"],
            "boring_task_name_prefixes": ["GoogleUpdateTask"],
        },
        "suspicious_paths": ["AppData\\Roaming"],
    }

    r_good = {"type": "persistence", "mechanism": "scheduled_task", "name": "GoogleUpdateTaskMachineCore",
              "action": "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe",
              "author": "Google LLC", "run_as": "S-1-5-18"}
    assert_true("whitelist Google canonical path", _is_publisher_whitelisted(r_good, cfg))

    r_bad = {"type": "execution", "path": "C:\\Users\\nfury\\AppData\\Roaming\\GoogleUpdate.exe",
             "author": "Google LLC"}
    assert_true("suspicious path NOT whitelisted", not _is_publisher_whitelisted(r_bad, cfg))

    r_unknown = {"type": "execution", "path": "C:\\MyTools\\thing.exe", "author": "Unknown Corp"}
    assert_true("unknown author NOT whitelisted", not _is_publisher_whitelisted(r_unknown, cfg))

    print("\n--- eventlog dedup ---")
    with tempfile.TemporaryDirectory() as tmp:
        evtx_path = os.path.join(tmp, "eventlog_security.txt")
        with open(evtx_path, "w") as f:
            for i in range(100):
                f.write(f'type=event id=4625 time=2020-11-15T23:53:{i:02d}Z user=patrick logon_type=3 src_ip=213.202.233.104\n')
            for i in range(5):
                f.write(f'type=event id=4625 time=2020-11-15T23:54:{i:02d}Z user=admin logon_type=3 src_ip=10.0.0.1\n')
            f.write('type=event id=1102 time=2020-11-16T03:01:22Z user=admin\n')

        test_cfg = {
            "artifact_files": {"eventlog_sources": ["eventlog_security.txt"]},
            "always_emit_event_ids": [1102, 104],
            "recency_cap_days": None,
        }
        auth_lines, total, collapsed = section_auth_summary(tmp, test_cfg, recency_cutoff=None)

        summary_lines = [l for l in auth_lines if l.startswith("type=event_summary")]
        assert_eq("dedup 100 identical 4625 → 1 group", len([l for l in summary_lines if "213.202.233.104" in l]), 1)
        assert_eq("separate group for different IP", len([l for l in summary_lines if "10.0.0.1" in l]), 1)
        always_lines = [l for l in auth_lines if "id=1102" in l and not l.startswith("#")]
        assert_true("always-emit 1102 present", len(always_lines) > 0)
        count_line = next((l for l in summary_lines if "213.202.233.104" in l), "")
        assert_true("count=100 in dedup line", "count=100" in count_line)

    print("\n--- MFT anomaly detection (_detect_mft_anomalies) ---")
    base_cfg = {
        "mft_whitelist_path_prefixes": ["windows\\system32"],
        "mft_always_escalate_anomalies": ["extension_magic_mismatch", "recycle_bin_executable", "pre_install_date"],
        "mft_system_binary_prefixes": ["windows\\system32", "windows\\syswow64"],
        "suspicious_paths": ["AppData\\Roaming", "\\Downloads\\"],
        "pe_extensions": [".exe", ".dll", ".scr", ".bat", ".ps1"],
        "entropy_threshold": 7.2,
        "si_fn_mismatch_threshold_seconds": 2,
    }
    wl = base_cfg["mft_whitelist_path_prefixes"]
    sys_bin = base_cfg["mft_system_binary_prefixes"]
    always_esc = set(base_cfg["mft_always_escalate_anomalies"])
    susp = base_cfg["suspicious_paths"]
    pe_ext = base_cfg["pe_extensions"]

    # Should flag high_entropy in AppData\Roaming
    r_he = {"type": "file", "path": "C:\\Users\\nfury\\AppData\\Roaming\\x.exe",
             "entropy": "7.85", "signature": "PE32+", "ads": "", "artifact_source": "mft"}
    a1 = _detect_mft_anomalies(r_he, wl, sys_bin, always_esc, susp, pe_ext, 7.2, 2.0, None)
    assert_true("AppData/Roaming high_entropy flagged", any("high_entropy" in a for a in a1))

    # Should flag missing_zone_identifier
    assert_true("missing_zone_identifier flagged in AppData", any("missing_zone_identifier" in a for a in a1))

    # Should flag magic mismatch
    r_mm = {"type": "file", "path": "C:\\Users\\nfury\\Downloads\\photo.jpg",
            "magic_mismatch": "mismatch:claimed_jpg_is_PE", "artifact_source": "mft"}
    a2 = _detect_mft_anomalies(r_mm, wl, sys_bin, always_esc, susp, pe_ext, 7.2, 2.0, None)
    assert_true("magic_mismatch flagged", any("extension_magic_mismatch" in a for a in a2))

    # System32 high entropy should be suppressed (whitelisted, not always-escalate)
    r_s32 = {"type": "file", "path": "C:\\Windows\\System32\\ntdll.dll",
             "entropy": "7.85", "artifact_source": "mft"}
    a3 = _detect_mft_anomalies(r_s32, wl, sys_bin, always_esc, susp, pe_ext, 7.2, 2.0, None)
    assert_true("System32 high entropy NOT flagged (whitelisted)", a3 == [])

    print("\n--- MFT scorer (_score_mft_record) ---")
    score_cfg = {
        "mft_scoring": {"threshold": 3, "top_n": 200, "entropy_score_threshold": 7.0},
        "mft_whitelist_path_prefixes": ["windows\\system32", "program files\\"],
        "suspicious_paths": ["AppData\\Local", "AppData\\Local\\Temp", "\\Downloads\\", "AppData\\Roaming"],
    }
    sp = score_cfg["suspicious_paths"]
    wl2 = score_cfg["mft_whitelist_path_prefixes"]

    # +4 exec ext in suspicious path
    r_p4 = {"type": "file", "path": "C:\\Users\\nfury\\AppData\\Local\\Temp\\evil.exe",
            "entropy": "0", "ads": "Zone.Identifier", "fn_created": ""}
    s_p4 = _score_mft_record(r_p4, score_cfg, None, None, sp, wl2)
    assert_true("+4 for exec ext in Temp (got %d)" % s_p4, s_p4 >= 4)

    # +4 exec in Downloads
    r_dl = {"type": "file", "path": "C:\\Users\\nfury\\Downloads\\tool.ps1",
            "entropy": "0", "ads": "Zone.Identifier", "fn_created": ""}
    s_dl = _score_mft_record(r_dl, score_cfg, None, None, sp, wl2)
    assert_true("+4 for ps1 in Downloads (got %d)" % s_dl, s_dl >= 4)

    # +4 should NOT apply to .txt in temp
    r_txt = {"type": "file", "path": "C:\\Temp\\readme.txt",
             "entropy": "0", "ads": "", "fn_created": ""}
    s_txt = _score_mft_record(r_txt, score_cfg, None, None, sp, wl2)
    assert_true("+4 does NOT apply to .txt in temp (got %d)" % s_txt, s_txt < 4)

    # +3 high entropy outside Program Files
    r_he2 = {"type": "file", "path": "C:\\Users\\nfury\\AppData\\Roaming\\svc.exe",
             "entropy": "7.5", "ads": "Zone.Identifier", "fn_created": ""}
    s_he2 = _score_mft_record(r_he2, score_cfg, None, None, sp, wl2)
    assert_true("+3 for high entropy in AppData (total score %d)" % s_he2, s_he2 >= 3)

    # +3 high entropy suppressed inside Program Files
    r_pf = {"type": "file", "path": "C:\\Program Files\\App\\lib.dll",
            "entropy": "7.5", "ads": "", "fn_created": ""}
    s_pf = _score_mft_record(r_pf, score_cfg, None, None, sp, wl2)
    # No +3 (inside program files), no +4 (program files not suspicious), +2 for no zone.id
    assert_true("+3 NOT applied for Program Files high entropy (got %d)" % s_pf, s_pf < 5)

    # +3 SI/FN delta > 60s
    r_ts = {"type": "file", "path": "C:\\Users\\nfury\\AppData\\Roaming\\x.exe",
            "created": "2020-11-15T23:00:00Z", "fn_created": "2020-11-10T00:00:00Z",
            "entropy": "0", "ads": "Zone.Identifier"}
    s_ts = _score_mft_record(r_ts, score_cfg, None, None, sp, wl2)
    assert_true("+3 for SI/FN delta >60s (total %d)" % s_ts, s_ts >= 3)

    # +3 SI/FN delta ≤ 60s should NOT score +3
    r_ts2 = {"type": "file", "path": "C:\\Users\\nfury\\AppData\\Roaming\\x.exe",
             "created": "2020-11-15T23:00:00Z", "fn_created": "2020-11-15T23:00:30Z",
             "entropy": "0", "ads": "Zone.Identifier"}
    s_ts2 = _score_mft_record(r_ts2, score_cfg, None, None, sp, wl2)
    assert_true("+3 NOT applied for 30s delta (got %d)" % s_ts2, s_ts2 < (4 + 3))

    # +2 attack window bonus
    aw_start = parse_iso("2020-11-15T23:45:00Z")
    aw_end   = parse_iso("2020-11-16T00:15:00Z")
    r_aw = {"type": "file", "path": "C:\\Users\\nfury\\Downloads\\evil.exe",
            "created": "2020-11-15T23:55:00Z", "fn_created": "",
            "entropy": "0", "ads": ""}
    s_aw = _score_mft_record(r_aw, score_cfg, aw_start, aw_end, sp, wl2)
    r_aw_no = {"type": "file", "path": "C:\\Users\\nfury\\Downloads\\old.exe",
               "created": "2020-01-01T00:00:00Z", "fn_created": "",
               "entropy": "0", "ads": ""}
    s_aw_no = _score_mft_record(r_aw_no, score_cfg, aw_start, aw_end, sp, wl2)
    assert_true("+2 attack window bonus applied (got %d)" % s_aw, s_aw > s_aw_no)
    assert_true("+2 NOT applied outside window (got %d)" % s_aw_no, s_aw_no < s_aw)

    # +2 Zone.Identifier absent on executable
    r_nozi = {"type": "file", "path": "C:\\Users\\nfury\\AppData\\Roaming\\x.exe",
              "entropy": "0", "ads": "", "fn_created": ""}
    r_zi = {"type": "file", "path": "C:\\Users\\nfury\\AppData\\Roaming\\x.exe",
            "entropy": "0", "ads": "Zone.Identifier", "fn_created": ""}
    s_nozi = _score_mft_record(r_nozi, score_cfg, None, None, sp, wl2)
    s_zi   = _score_mft_record(r_zi, score_cfg, None, None, sp, wl2)
    assert_true("+2 for missing Zone.Identifier", s_nozi > s_zi)

    # -5 NSRL match
    r_nsrl = {"type": "file", "path": "C:\\Users\\nfury\\AppData\\Roaming\\malware.exe",
              "entropy": "0", "ads": "", "fn_created": "", "nsrl_match": "true"}
    s_nsrl = _score_mft_record(r_nsrl, score_cfg, None, None, sp, wl2)
    r_no_nsrl = dict(r_nsrl)
    r_no_nsrl["nsrl_match"] = "false"
    s_no_nsrl = _score_mft_record(r_no_nsrl, score_cfg, None, None, sp, wl2)
    assert_true("-5 NSRL match reduces score (nsrl=%d vs no_nsrl=%d)" % (s_nsrl, s_no_nsrl), s_nsrl < s_no_nsrl)
    assert_true("-5 NSRL can produce negative total", s_nsrl <= s_no_nsrl - 5)

    print("\n--- MFT section integration (scoring + filtering) ---")
    with tempfile.TemporaryDirectory() as tmp:
        with tempfile.TemporaryDirectory() as audit_tmp:
            mft_path = os.path.join(tmp, "mft_records.txt")
            with open(mft_path, "w") as f:
                # Score >= threshold: exec ext in suspicious path (+4) + no Zone.Id (+2) = 6
                f.write('type=file path="C:\\\\Users\\\\nfury\\\\AppData\\\\Roaming\\\\x.exe" entropy=0 ads="" artifact_source=mft\n')
                # Score = 0: clean system file
                f.write('type=file path="C:\\\\Windows\\\\System32\\\\calc.exe" entropy=3.2 artifact_source=mft\n')
                # Score < threshold (0): no anomaly
                f.write('type=file path="C:\\\\Some\\\\Normal\\\\file.txt" entropy=1.0 artifact_source=mft\n')

            test_cfg = {
                "artifact_files": {"mft_source": "mft_records.txt"},
                "mft_whitelist_path_prefixes": ["windows\\system32"],
                "mft_always_escalate_anomalies": ["extension_magic_mismatch"],
                "mft_system_binary_prefixes": ["windows\\system32"],
                "suspicious_paths": ["AppData\\Roaming"],
                "pe_extensions": [".exe", ".dll"],
                "entropy_threshold": 7.2,
                "si_fn_mismatch_threshold_seconds": 2,
                "mft_scoring": {"threshold": 3, "top_n": 200, "entropy_score_threshold": 7.0},
            }
            mft_lines, total, filtered_in, filtered_out = section_mft_anomalies(tmp, test_cfg, audit_tmp)

            assert_true("stats block present", any("MFT SUMMARY" in l for l in mft_lines))
            passing_records = [l for l in mft_lines if l.startswith("type=mft_anomaly")]
            assert_true("AppData/.exe passes threshold", any("AppData" in l for l in passing_records))
            assert_true("clean file NOT in passing", not any("calc.exe" in l for l in passing_records))

            # Audit file should exist (there are records with score=0 that are < threshold)
            audit_file = os.path.join(audit_tmp, "mft_filtered.jsonl")
            assert_true("audit file written when records filtered out", os.path.exists(audit_file))

    print(f"\n{'PASSED' if failures == 0 else f'FAILED ({failures} failures)'} — {failures} failures")
    sys.exit(0 if failures == 0 else 1)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic triage-input preprocessor (multi-file output)")
    parser.add_argument("--base-dir", default=None,
                        help="Root of disk-agentic-architecture/ (config.json is at base_dir/config.json)")
    parser.add_argument("--config", required=False, default=None,
                        help="Explicit path to config.json (overrides --base-dir)")
    parser.add_argument("--artifact-dir", default=None,
                        help="Override artifact_dir from config")
    parser.add_argument("--test", action="store_true",
                        help="Run unit tests and exit")
    args = parser.parse_args()

    if args.test:
        _run_tests()
        return

    # Resolve config path: explicit --config > --base-dir/config.json > default sibling config.json
    if args.config:
        config_path = args.config
    elif args.base_dir:
        config_path = os.path.join(args.base_dir, "config.json")
    else:
        config_path = os.path.join(os.path.dirname(__file__), "..", "config.json")

    config_path = os.path.normpath(config_path)
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    base_dir = args.base_dir or os.path.dirname(config_path)
    artifact_dir = args.artifact_dir or os.path.normpath(
        os.path.join(base_dir, cfg.get("artifact_dir", "../Disk_Artifacts"))
    )

    run(artifact_dir, cfg, base_dir)


if __name__ == "__main__":
    main()
