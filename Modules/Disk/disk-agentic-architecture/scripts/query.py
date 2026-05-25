#!/usr/bin/env python3
"""
Entry point 2 — QUERY mode (pivot-back).

Answers a single EntityQuery from the orchestrator using the 4-stage flow:
  Stage 1: type dispatch
  Stage 2: deterministic retrieval (grep across Disk_Artifacts/)
  Stage 3: triviality / whitelist check
  Stage 4: scoped LLM interpreter (agentQ_focused.md)

Usage:
    python scripts/query.py --query <entity_query.json>
                            --out   <entity_findings.json>
                            [--base-dir <dir>] [--artifact-dir <dir>]
                            [--no-llm]
"""

import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
SCHEMA_DIR = BASE_DIR / "schemas"

# ---------------------------------------------------------------------------
# Entity types this module handles (Stage 1 dispatch)
# ---------------------------------------------------------------------------

# Types we search across all artifacts (greedy)
_GREEDY_TYPES = {"file_path", "image_name", "hash_md5", "hash_sha1", "hash_sha256",
                 "registry_key", "user_sid"}

# Types with best-effort support (limited artifact coverage)
_BEST_EFFORT_TYPES = {"ip", "domain", "url"}

SUPPORTED_TYPES = _GREEDY_TYPES | _BEST_EFFORT_TYPES

# Types that get NOT_APPLICABLE immediately
NOT_APPLICABLE_TYPES = {"pid", "mutex"}

# ---------------------------------------------------------------------------
# Retrieval: which artifact files to search per entity type
# ---------------------------------------------------------------------------

_PERSISTENCE_FILES = [
    "registry_autoruns.txt",
    "registry_misc.txt",
    "scheduled_tasks.txt",
    "wmi_subscriptions.txt",
]
_EXECUTION_FILES = [
    "registry_shimcache.txt",
    "amcache_records.txt",
    "prefetch_records.txt",
]
_EVENTLOG_FILES = [
    "eventlog_security.txt",
    "eventlog_system.txt",
    "eventlog_application.txt",
    "eventlog_sysmon.txt",
    "eventlog_other.txt",
]
_MFT_FILES = ["mft_records.txt"]
_BROWSER_FILES = ["browser_history.txt"]
_ALL_FILES = (
    _MFT_FILES + _PERSISTENCE_FILES + _EXECUTION_FILES + _BROWSER_FILES + _EVENTLOG_FILES
)

# Per entity-type → list of artifact files to search
_TYPE_FILES: dict[str, list[str]] = {
    "file_path":    _ALL_FILES,
    "image_name":   _MFT_FILES + _EXECUTION_FILES + _PERSISTENCE_FILES + _BROWSER_FILES,
    "hash_md5":     _MFT_FILES + _EXECUTION_FILES,
    "hash_sha1":    _MFT_FILES + _EXECUTION_FILES,
    "hash_sha256":  _MFT_FILES + _EXECUTION_FILES,
    "registry_key": _PERSISTENCE_FILES,
    "user_sid":     _ALL_FILES,
    "ip":           _BROWSER_FILES + _PERSISTENCE_FILES + _EVENTLOG_FILES,
    "domain":       _BROWSER_FILES + _PERSISTENCE_FILES + _EVENTLOG_FILES,
    "url":          _BROWSER_FILES + _PERSISTENCE_FILES,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_config(base: Path) -> dict:
    cfg_path = base / "config.json"
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _load_whitelist(cfg: dict) -> list[str]:
    return [p.lower() for p in cfg.get("mft_whitelist_path_prefixes", [])]


# ---------------------------------------------------------------------------
# Stage 2: Deterministic retrieval
# ---------------------------------------------------------------------------

def _make_pattern(entity_type: str, value: str) -> re.Pattern:
    """Build a search regex for the given entity type and value."""
    escaped = re.escape(value)
    if entity_type == "image_name":
        # Match basename (case-insensitive, with common delimiters around it)
        basename = os.path.basename(value.replace("\\", "/"))
        escaped_base = re.escape(basename)
        return re.compile(rf"(?i)(^|[\s=\"'/\\]){escaped_base}($|[\s=\"'/\\])")
    if entity_type in ("hash_md5", "hash_sha1", "hash_sha256"):
        # Word-boundary match for hashes to avoid partial collisions
        return re.compile(rf"(?i)\b{escaped}\b")
    if entity_type == "file_path":
        # Match exact path OR just the filename component
        basename = os.path.basename(value.replace("\\", "/"))
        escaped_base = re.escape(basename)
        return re.compile(
            rf"(?i)({escaped}|{escaped_base})"
        )
    # Default: case-insensitive substring match
    return re.compile(rf"(?i){escaped}")


def _retrieve_evidence(
    artifact_dir: Path,
    entity_type: str,
    value: str,
    max_lines: int = 50,
) -> list[dict]:
    """Grep the relevant artifact files; return evidence dicts."""
    files = _TYPE_FILES.get(entity_type, [])
    pattern = _make_pattern(entity_type, value)
    hits: list[dict] = []

    for fname in files:
        fpath = artifact_dir / fname
        if not fpath.exists():
            continue
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                for lineno, line in enumerate(f, start=1):
                    if pattern.search(line):
                        ts = _extract_timestamp(line)
                        hits.append({
                            "source_file": fname,
                            "line": lineno,
                            "content": line.rstrip("\n"),
                            "verbatim": True,
                            "timestamp": ts,
                        })
                        if len(hits) >= max_lines:
                            return hits
        except OSError:
            continue

    return hits


def _extract_timestamp(line: str) -> str | None:
    """Try to pull an ISO-8601 timestamp from a FIND_EVIL record line."""
    m = re.search(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\b", line)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Stage 3: Triviality / whitelist check
# ---------------------------------------------------------------------------

def _is_trivially_benign(entity_type: str, value: str, evidence: list[dict],
                          whitelist: list[str]) -> bool:
    """
    Return True only when the entity is unambiguously benign.

    Conservative: if ANY evidence line contains a suspicious indicator
    (high entropy, suspicious path, known-bad field), skip to Stage 4.
    """
    if entity_type not in ("file_path", "image_name"):
        return False  # only apply whitelist to file-based entities

    norm = value.strip().replace("/", "\\").lower()
    # Strip leading drive letter (e.g. "c:\") so whitelist prefixes like
    # "windows\system32" match both "c:\windows\..." and bare paths.
    norm_no_drive = re.sub(r"^[a-z]:[/\\]", "", norm)
    matched = any(norm.startswith(p) or norm_no_drive.startswith(p) for p in whitelist)
    if not matched:
        return False

    # Escape hatch: look for suspicious indicators in evidence
    suspicious_indicators = re.compile(
        r"entropy=[7-9]\.\d|suspicious=true|malware|deleted=true|"
        r"appdata.{0,10}temp|recycle\.bin",
        re.IGNORECASE
    )
    for ev in evidence:
        if suspicious_indicators.search(ev["content"]):
            return False  # whitelist match but suspicious signal → go to LLM

    return True


# ---------------------------------------------------------------------------
# Stage 4: LLM interpreter
# ---------------------------------------------------------------------------

def _call_llm(query: dict, evidence: list[dict], base: Path, llm_cfg: dict) -> dict:
    """Call the scoped LLM interpreter and return an EntityFindings dict."""
    sys.path.insert(0, str(SCRIPT_DIR))
    from llm_client import call_chat

    prompt_path = base / "prompts" / "agentQ_focused.md"
    if not prompt_path.exists():
        return _fallback_inconclusive(query, evidence,
                                      "agentQ_focused.md prompt not found")

    system_prompt = prompt_path.read_text(encoding="utf-8", errors="ignore")

    entity = query["entity"]
    context = query.get("context", {})
    evidence_block = "\n".join(
        f"[{e['source_file']} L{e['line']}] {e['content']}"
        for e in evidence
    )

    user_msg = (
        f"Entity type: {entity['type']}\n"
        f"Entity value: {entity['value']}\n\n"
        f"Reason for this query (from orchestrator):\n"
        f"{context.get('reason', '(no reason provided)')}\n\n"
        f"Retrieved evidence ({len(evidence)} lines):\n"
        f"{'='*60}\n"
        f"{evidence_block}\n"
        f"{'='*60}\n\n"
        f"Respond with a JSON block matching EntityFindings. "
        f"query_id must be: {query['query_id']}"
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_msg},
    ]

    try:
        raw = call_chat(messages, llm_cfg)
    except Exception as exc:
        return _fallback_inconclusive(query, evidence,
                                      f"LLM call failed: {exc}")

    # Try to extract JSON from LLM response
    try:
        from llm_client import extract_json
        findings = extract_json(raw)
    except Exception:
        findings = None

    if not isinstance(findings, dict):
        return _fallback_inconclusive(query, evidence,
                                      f"LLM response was not valid JSON: {raw[:200]}")

    # Ensure mandatory envelope fields are correct
    findings["contract_version"] = "1.0"
    findings["query_id"] = query["query_id"]
    findings["responding_module"] = "disk"
    findings.setdefault("entity", entity)
    findings.setdefault("evidence", evidence)
    findings.setdefault("related_entities", [])
    findings.setdefault("cost", {"llm_calls": 1, "tokens_in": 0, "tokens_out": 0})
    findings.setdefault("mitre", [])
    # severity must be null for non-CONFIRMED
    if findings.get("verdict") != "CONFIRMED":
        findings["severity"] = None
    return findings


# ---------------------------------------------------------------------------
# Helpers: build EntityFindings envelopes
# ---------------------------------------------------------------------------

_ZERO_COST = {"llm_calls": 0, "tokens_in": 0, "tokens_out": 0}


def _make_findings(query: dict, verdict: str, justification: str,
                   evidence: list, related_entities: list,
                   cost: dict, severity: str | None = None,
                   mitre: list | None = None) -> dict:
    result = {
        "contract_version": "1.0",
        "query_id": query["query_id"],
        "responding_module": "disk",
        "entity": query["entity"],
        "verdict": verdict,
        "severity": severity if verdict == "CONFIRMED" else None,
        "mitre": mitre or [],
        "justification": justification,
        "evidence": evidence,
        "related_entities": related_entities,
        "cost": cost,
    }
    return result


def _fallback_inconclusive(query: dict, evidence: list, reason: str) -> dict:
    return _make_findings(
        query,
        verdict="INCONCLUSIVE",
        justification=f"LLM unavailable — manual review required. ({reason})",
        evidence=evidence,
        related_entities=[],
        cost=_ZERO_COST,
    )


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

def _validate(data: dict, schema_name: str) -> list[str]:
    try:
        import jsonschema
    except ImportError:
        return []
    schema_path = SCHEMA_DIR / schema_name
    if not schema_path.exists():
        return [f"Schema not found: {schema_path}"]
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)
    return [e.message for e in jsonschema.Draft7Validator(schema).iter_errors(data)]


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------

def _write_audit(base: Path, query_id: str, query: dict, evidence: list,
                 llm_prompt: str | None, llm_raw: str | None, findings: dict) -> None:
    audit_dir = base / "output" / "queries"
    audit_dir.mkdir(parents=True, exist_ok=True)
    audit_path = audit_dir / f"{query_id}.txt"
    with open(audit_path, "w", encoding="utf-8") as f:
        f.write(f"=== EntityQuery ===\n{json.dumps(query, indent=2)}\n\n")
        f.write(f"=== Retrieved Evidence ({len(evidence)} lines) ===\n")
        for ev in evidence:
            f.write(f"[{ev['source_file']} L{ev['line']}] {ev['content']}\n")
        f.write("\n")
        if llm_prompt:
            f.write(f"=== LLM Prompt ===\n{llm_prompt}\n\n")
        if llm_raw:
            f.write(f"=== LLM Raw Response ===\n{llm_raw}\n\n")
        f.write(f"=== EntityFindings ===\n{json.dumps(findings, indent=2)}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Disk module — QUERY mode (pivot-back)")
    ap.add_argument("--query", required=True, help="Path to EntityQuery JSON file")
    ap.add_argument("--out",   required=True, help="Path to write EntityFindings JSON")
    ap.add_argument("--base-dir", default=str(BASE_DIR))
    ap.add_argument("--artifact-dir", default=None)
    ap.add_argument("--no-llm", action="store_true",
                    help="Skip LLM stage (return INCONCLUSIVE with raw evidence)")
    args = ap.parse_args()

    base = Path(args.base_dir).resolve()
    cfg = _load_config(base)
    artifact_dir_str = args.artifact_dir or cfg.get("artifact_dir") or str(BASE_DIR.parent / "Disk_Artifacts")
    artifact_dir = Path(artifact_dir_str).resolve()
    whitelist = _load_whitelist(cfg)

    # Load and validate the EntityQuery
    with open(args.query, "r", encoding="utf-8") as f:
        query = json.load(f)

    errs = _validate(query, "entity_query.schema.json")
    if errs:
        # Invalid query → NOT_APPLICABLE per spec
        query.setdefault("query_id", str(uuid.uuid4()))
        query.setdefault("entity", {"type": "image_name", "value": "unknown"})
        findings = _make_findings(
            query, verdict="NOT_APPLICABLE",
            justification=f"Invalid EntityQuery: {'; '.join(errs[:3])}",
            evidence=[], related_entities=[], cost=_ZERO_COST,
        )
        _write_output(args.out, findings, query["query_id"], base, query, [], None, None)
        return

    entity = query["entity"]
    entity_type = entity["type"]
    value = entity["value"]

    # Reject unknown target_module
    if query.get("target_module", "disk") != "disk":
        findings = _make_findings(
            query, verdict="NOT_APPLICABLE",
            justification=f"Query is for module '{query.get('target_module')}', not 'disk'.",
            evidence=[], related_entities=[], cost=_ZERO_COST,
        )
        _write_output(args.out, findings, query["query_id"], base, query, [], None, None)
        return

    # --- Stage 1: type dispatch ---
    if entity_type in NOT_APPLICABLE_TYPES or entity_type not in SUPPORTED_TYPES:
        findings = _make_findings(
            query, verdict="NOT_APPLICABLE",
            justification=(
                f"Disk module does not handle entity type '{entity_type}'. "
                f"Supported: {', '.join(sorted(SUPPORTED_TYPES))}."
            ),
            evidence=[], related_entities=[], cost=_ZERO_COST,
        )
        _write_output(args.out, findings, query["query_id"], base, query, [], None, None)
        return

    # --- Stage 2: deterministic retrieval ---
    max_ev = int(query.get("scope", {}).get("max_evidence_lines") or 50)
    evidence = _retrieve_evidence(artifact_dir, entity_type, value, max_lines=max_ev)

    if not evidence:
        findings = _make_findings(
            query, verdict="NOT_FOUND",
            justification=(
                f"No matching lines found for {entity_type}='{value}' "
                f"in any disk artifact file."
            ),
            evidence=[], related_entities=[], cost=_ZERO_COST,
        )
        _write_output(args.out, findings, query["query_id"], base, query, [], None, None)
        return

    # --- Stage 3: triviality check ---
    if _is_trivially_benign(entity_type, value, evidence, whitelist):
        match_evidence = evidence[:5]
        findings = _make_findings(
            query, verdict="REJECTED",
            justification=(
                f"'{value}' matches the trusted-path whitelist and no suspicious "
                f"indicators were found in the retrieved evidence."
            ),
            evidence=match_evidence, related_entities=[], cost=_ZERO_COST,
        )
        _write_output(args.out, findings, query["query_id"], base, query, evidence, None, None)
        return

    # --- Stage 4: LLM interpreter ---
    if args.no_llm:
        findings = _fallback_inconclusive(
            query, evidence,
            "no-llm mode — manual review required"
        )
        _write_output(args.out, findings, query["query_id"], base, query, evidence, None, None)
        return

    llm_cfg_path = base / "llm_config.json"
    if not llm_cfg_path.exists():
        findings = _fallback_inconclusive(
            query, evidence,
            f"llm_config.json not found at {llm_cfg_path}"
        )
        _write_output(args.out, findings, query["query_id"], base, query, evidence, None, None)
        return

    with open(llm_cfg_path, "r", encoding="utf-8") as f:
        llm_cfg = json.load(f)

    findings = _call_llm(query, evidence, base, llm_cfg)

    errs = _validate(findings, "entity_findings.schema.json")
    if errs:
        print(f"[query] WARN: EntityFindings validation errors ({len(errs)}):", flush=True)
        for e in errs[:5]:
            print(f"  - {e}", flush=True)

    _write_output(args.out, findings, query["query_id"], base, query, evidence, None, None)


def _write_output(out_path: str, findings: dict, query_id: str, base: Path,
                  query: dict, evidence: list,
                  llm_prompt: str | None, llm_raw: str | None) -> None:
    """Validate, write findings JSON, and write audit block."""
    errs = _validate(findings, "entity_findings.schema.json")
    if errs:
        print(f"[query] WARN: schema validation errors: {errs[:3]}", flush=True)

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
    print(f"[query] Written → {out_path} (verdict={findings.get('verdict')})", flush=True)

    _write_audit(base, query_id, query, evidence, llm_prompt, llm_raw, findings)


if __name__ == "__main__":
    main()
