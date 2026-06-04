#!/usr/bin/env python3
"""
scan_result_emitter — internal pipeline step (not a standalone CLI).

Called by run_pipeline.py immediately after aggregated_analyst.txt is written.
Parses the aggregated TXT and emits output/scan_result.json matching
module_scan_result.schema.json.

Public API:
    emit_scan_result(aggregated_path, case_id, out_path, per_chunk_paths=None)
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_SCRIPTS_DIR = Path(__file__).resolve().parent
_REPO_DIR = _SCRIPTS_DIR.parent    # ram-agentic-architecture/
_MODULE_DIR = _REPO_DIR.parent     # Modules/RAM/
_MODULES_DIR = _MODULE_DIR.parent  # Modules/
_PROJECT_DIR = _MODULES_DIR.parent # project root
_SCHEMA_DIR = _PROJECT_DIR / "Backbone" / "schemas"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Parsers for analyst TXT blocks
# ---------------------------------------------------------------------------

_BLOCK_HEADER_RE = re.compile(r"^\[(CONFIRMED|INCONCLUSIVE|REJECTED)\]\s*$")
_KV_RE = re.compile(r"^(\w[\w\s]*):\s+(.+)$")
_CHUNK_HEADER_RE = re.compile(r"^=== CHUNK \d+: (\S+) ===")

# Evidence lines look like: "  - L42: <content>" or "- L42: <content>"
_EVIDENCE_LINE_RE = re.compile(r"^\s*-\s+L(\d+):\s+(.+)$")

# Entity extractors
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_PATH_RE = re.compile(r"(?i)([a-z]:\\[^\s\|>\"]+|/(?:usr|tmp|var|home|opt)/[^\s\|>\"]+)", re.IGNORECASE)
_SID_RE = re.compile(r"\b(S-\d-\d+(?:-\d+)+)\b")


def _parse_blocks(text: str) -> List[Dict[str, Any]]:
    """
    Parse all [CONFIRMED] and [INCONCLUSIVE] finding blocks from analyst TXT.
    Returns a list of dicts with keys: verdict, pid, ppid, image, cmdline,
    severity, mitre, justification, key_evidence, chunk_label.
    """
    blocks = []
    current_chunk = "unknown"
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]

        # Track which chunk we're in (for finding_id generation)
        m = _CHUNK_HEADER_RE.match(line)
        if m:
            current_chunk = os.path.splitext(m.group(1))[0]  # e.g. chunk_001
            i += 1
            continue

        # Detect block header
        m = _BLOCK_HEADER_RE.match(line)
        if not m:
            i += 1
            continue

        verdict = m.group(1)
        block: Dict[str, Any] = {
            "verdict": verdict,
            "pid": None,
            "ppid": None,
            "image": None,
            "cmdline": None,
            "severity": None,
            "mitre": [],
            "justification": "",
            "key_evidence": [],
            "chunk_label": current_chunk,
        }

        i += 1
        in_justification = False
        in_evidence = False

        while i < len(lines):
            l = lines[i]

            # End of block: separator line or next block header or chunk header
            if l.startswith("================================================================") or \
               _BLOCK_HEADER_RE.match(l) or _CHUNK_HEADER_RE.match(l):
                break

            # Separator dashes (between blocks)
            if l.startswith("----------------------------------------------------------------"):
                i += 1
                continue

            # Key-value fields
            if l.startswith("PID:"):
                block["pid"] = l.split(":", 1)[1].strip()
                in_justification = False
                in_evidence = False
            elif l.startswith("PPID:"):
                block["ppid"] = l.split(":", 1)[1].strip()
            elif l.startswith("Image:"):
                block["image"] = l.split(":", 1)[1].strip()
            elif l.startswith("Cmdline:"):
                block["cmdline"] = l.split(":", 1)[1].strip()
            elif l.startswith("Severity:"):
                block["severity"] = l.split(":", 1)[1].strip()
            elif l.startswith("MITRE:"):
                raw_mitre = l.split(":", 1)[1].strip()
                # Parse "T1059.001 — PowerShell" → extract Txxxx codes
                codes = re.findall(r"T\d{4}(?:\.\d{3})?", raw_mitre)
                block["mitre"] = codes
            elif l.startswith("Justification:"):
                in_justification = True
                in_evidence = False
                rest = l.split(":", 1)[1].strip()
                if rest:
                    block["justification"] = rest
            elif l.startswith("Key Evidence:"):
                in_evidence = True
                in_justification = False
            elif in_justification and l.startswith("  "):
                block["justification"] = (block["justification"] + " " + l.strip()).strip()
            elif in_evidence:
                em = _EVIDENCE_LINE_RE.match(l)
                if em:
                    block["key_evidence"].append({
                        "line_number": int(em.group(1)),
                        "content": em.group(2).strip(),
                    })

            i += 1

        if block["pid"] is not None:
            blocks.append(block)
        # Don't advance i here — the while loop at the top will re-check the
        # break-triggering line (block header / separator / chunk header).

    return blocks


def _extract_related_entities(block: Dict[str, Any]) -> List[Dict[str, str]]:
    """Build related_entities from image, ppid, cmdline and evidence content."""
    entities = []
    seen = set()

    def add(etype: str, value: str, relationship: str) -> None:
        key = (etype, value.strip())
        if key not in seen and value.strip():
            seen.add(key)
            entities.append({"type": etype, "value": value.strip(),
                             "relationship": relationship})

    if block.get("image"):
        add("image_name", block["image"], "process_image")
    if block.get("ppid"):
        add("pid", block["ppid"], "parent_pid")

    # Scan cmdline + key evidence for IPs, paths, SIDs
    texts = []
    if block.get("cmdline"):
        texts.append(block["cmdline"])
    for ev in block.get("key_evidence", []):
        texts.append(ev["content"])

    for t in texts:
        for ip in _IP_RE.findall(t):
            # Skip private RFC1918 ranges that are common false positives
            if not (ip.startswith("127.") or ip.startswith("10.")
                    or ip.startswith("192.168.") or ip == "0.0.0.0"):
                add("ip", ip, "outbound_or_listening")
        for path in _PATH_RE.findall(t):
            if len(path) > 3:
                add("file_path", path, "referenced_path")
        for sid in _SID_RE.findall(t):
            add("user_sid", sid, "process_owner")

    return entities


def _build_pivot_index(pivot_path: str) -> Dict[tuple, str]:
    """
    Parse pivot.txt and return {(line_number, content): source_filename} for
    one PID section. Called once per chunk; the caller selects the right PID
    slice before looking up evidence items.

    Returns a flat dict covering all PIDs in the file — key collisions across
    PIDs are unlikely given that line numbers differ per artifact file.
    """
    index: Dict[tuple, str] = {}
    if not os.path.exists(pivot_path):
        return index

    current_file = ""
    with open(pivot_path, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.rstrip()
            if line.startswith("--- ") and line.endswith(" ---"):
                current_file = line[4:-4].strip()
            elif current_file and line and not line.startswith("===") \
                    and not line.startswith("Cmdline:"):
                m = re.match(r"^L(\d+):\s+(.+)$", line)
                if m:
                    key = (int(m.group(1)), m.group(2).strip())
                    index.setdefault(key, current_file)
    return index


def _build_evidence_items(
    block: Dict[str, Any],
    pivot_index: Optional[Dict[tuple, str]] = None,
) -> List[Dict[str, Any]]:
    """Convert key_evidence entries to schema-compatible evidence dicts.

    pivot_index (built from the chunk's pivot.txt) is used to back-populate
    source_file. Falls back to an empty string when the lookup misses.
    """
    items = []
    for ev in block.get("key_evidence", []):
        key = (ev["line_number"], ev["content"].strip())
        source_file = (pivot_index or {}).get(key, "")
        items.append({
            "source_file": source_file,
            "line": ev["line_number"],
            "content": ev["content"],
            "verbatim": True,
            "timestamp": None,
        })
    return items


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def emit_scan_result(
    aggregated_path: str,
    case_id: str,
    out_path: str,
    per_chunk_paths: Optional[List[str]] = None,
    started_at: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Parse aggregated_analyst.txt and write scan_result.json.

    Returns the result dict (also written to out_path).
    """
    completed_at = _now_iso()
    if started_at is None:
        started_at = completed_at

    with open(aggregated_path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    blocks = _parse_blocks(text)

    # Build pivot indexes keyed by chunk_label for source_file resolution
    pivot_indexes: Dict[str, Dict[tuple, str]] = {}
    if per_chunk_paths:
        for analyst_path in per_chunk_paths:
            chunk_label = Path(analyst_path).parent.name  # e.g. "chunk_001"
            pivot_path = str(Path(analyst_path).parent / "pivot.txt")
            pivot_indexes[chunk_label] = _build_pivot_index(pivot_path)

    # Count by verdict
    counts: Dict[str, int] = {"confirmed": 0, "inconclusive": 0, "rejected": 0}
    for b in blocks:
        key = b["verdict"].lower()
        if key in counts:
            counts[key] += 1

    # Count rejected from header lines like "Counts: confirmed=2 inconclusive=1 rejected=3"
    # (the aggregated TXT may include blocks that were rejected and not repeated verbatim)
    rejected_from_header = 0
    for line in text.splitlines():
        m = re.search(r"rejected=(\d+)", line, re.IGNORECASE)
        if m:
            rejected_from_header = max(rejected_from_header, int(m.group(1)))
    if rejected_from_header > counts["rejected"]:
        counts["rejected"] = rejected_from_header

    # Number of chunks processed (count unique chunk headers)
    chunk_count = len(re.findall(r"^=== CHUNK \d+:", text, re.MULTILINE))

    # Build findings list (only CONFIRMED and INCONCLUSIVE have full blocks)
    findings = []
    chunk_counters: Dict[str, int] = {}
    for block in blocks:
        if block["verdict"] not in ("CONFIRMED", "INCONCLUSIVE"):
            continue
        chunk_label = block["chunk_label"]
        chunk_counters[chunk_label] = chunk_counters.get(chunk_label, 0) + 1
        finding_id = f"ram-{chunk_label}-f{chunk_counters[chunk_label]:03d}"

        pivot_index = pivot_indexes.get(chunk_label, {})
        finding: Dict[str, Any] = {
            "finding_id": finding_id,
            "verdict": block["verdict"],
            "severity": block["severity"] if block["verdict"] == "CONFIRMED" else None,
            "mitre": block["mitre"],
            "primary_entity": {"type": "pid", "value": block["pid"] or "unknown"},
            "related_entities": _extract_related_entities(block),
            "justification": block["justification"] or f"{block['verdict']} — see analyst.txt",
            "evidence": _build_evidence_items(block, pivot_index),
        }
        findings.append(finding)

    # Artifacts section
    artifacts: Dict[str, Any] = {
        "human_report": str(aggregated_path),
    }
    if per_chunk_paths:
        artifacts["per_chunk"] = [str(p) for p in per_chunk_paths]

    result: Dict[str, Any] = {
        "contract_version": "1.0",
        "case_id": case_id,
        "module": "ram",
        "scan_started_at": started_at,
        "scan_completed_at": completed_at,
        "summary": (
            f"{chunk_count} chunk(s) processed. "
            f"{counts['confirmed']} CONFIRMED, "
            f"{counts['inconclusive']} INCONCLUSIVE, "
            f"{counts['rejected']} REJECTED."
        ),
        "counts": counts,
        "findings": findings,
        "artifacts": artifacts,
    }

    # Validate against schema (best-effort)
    _validate(result, "module_scan_result.schema.json")

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    confirmed = counts["confirmed"]
    inconclusive = counts["inconclusive"]
    print(
        f"[emitter] scan_result.json written → {out_path} "
        f"(confirmed={confirmed}, inconclusive={inconclusive})",
        flush=True,
    )
    return result


def _validate(data: Dict[str, Any], schema_name: str) -> None:
    try:
        import jsonschema
    except ImportError:
        return
    schema_path = _SCHEMA_DIR / schema_name
    if not schema_path.exists():
        return
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)
    errors = list(jsonschema.Draft7Validator(schema).iter_errors(data))
    if errors:
        print(f"[emitter] WARN: {len(errors)} schema validation error(s):", flush=True)
        for e in errors[:5]:
            print(f"  - {e.message}", flush=True)
