#!/usr/bin/env python3
"""
entity_query — RAM module QUERY mode (pivot-back).

Answers a single EntityQuery from the orchestrator using the 4-stage flow:
  Stage 1: type dispatch
  Stage 2: deterministic retrieval (grep across RAM_Artifacts/)
  Stage 3: triviality / whitelist check
  Stage 4: scoped LLM interpreter (agentQ_focused.md)

Usage:
    python scripts/entity_query.py --query <entity_query.json>
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
BASE_DIR = SCRIPT_DIR.parent       # ram-agentic-architecture/
_MODULE_DIR = BASE_DIR.parent      # Modules/RAM/
_MODULES_DIR = _MODULE_DIR.parent  # Modules/
_PROJECT_DIR = _MODULES_DIR.parent # project root
SCHEMA_DIR = _PROJECT_DIR / "Backbone" / "schemas"

# ---------------------------------------------------------------------------
# Entity type sets (Stage 1 dispatch)
# ---------------------------------------------------------------------------

# RAM natively handles these
SUPPORTED_TYPES = {
    "pid", "image_name", "file_path", "ip", "domain", "url",
    "registry_key", "user_sid",
}

# mutex is supported only if handles.txt exists — checked at runtime
CONDITIONAL_TYPES = {"mutex"}

# These types require file hashes which RAM artifacts don't carry
NOT_APPLICABLE_TYPES = {"hash_md5", "hash_sha1", "hash_sha256"}

# ---------------------------------------------------------------------------
# Retrieval: which artifact files to search per entity type
# These are supplemented by pid_files / path_files from config.json
# ---------------------------------------------------------------------------

_IMAGE_FILES = ["pslist.txt", "pstree.txt", "cmdline.txt", "psscan.txt"]
_NETWORK_FILES = ["netscan.txt", "netstat.txt", "cmdline.txt", "envars.txt"]
_SID_FILES = ["getsids.txt", "privileges.txt", "sessions.txt"]
_REGISTRY_FILES = ["registry_printkey.txt"]
_URL_FILES = ["cmdline.txt", "envars.txt"]
_MUTEX_FILES = ["handles.txt"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_config(base: Path) -> dict:
    cfg_path = base / "config.json"
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _load_whitelist(base: Path) -> list[str]:
    wl_path = base / "scripts" / "whitelist.txt"
    if not wl_path.exists():
        wl_path = base / "whitelist.txt"
    if not wl_path.exists():
        return []
    with open(wl_path, "r", encoding="utf-8", errors="ignore") as f:
        return [ln.strip().lower() for ln in f if ln.strip() and not ln.startswith("#")]


# ---------------------------------------------------------------------------
# Stage 2: Deterministic retrieval
# ---------------------------------------------------------------------------

def _make_pattern(entity_type: str, value: str) -> re.Pattern:
    escaped = re.escape(value)
    if entity_type == "pid":
        return re.compile(rf"\b{escaped}\b")
    if entity_type == "image_name":
        basename = os.path.basename(value.replace("\\", "/"))
        escaped_base = re.escape(basename)
        return re.compile(rf"(?i)(^|[\s=\"'/\\]){escaped_base}($|[\s=\"'/\\])")
    if entity_type == "file_path":
        basename = os.path.basename(value.replace("\\", "/"))
        escaped_base = re.escape(basename)
        return re.compile(rf"(?i)({escaped}|{escaped_base})")
    # Default: case-insensitive substring
    return re.compile(rf"(?i){escaped}")


def _get_file_list(entity_type: str, cfg: dict) -> list[str]:
    if entity_type == "pid":
        return cfg.get("pid_files", [])
    if entity_type == "image_name":
        return _IMAGE_FILES
    if entity_type == "file_path":
        return cfg.get("path_files", [])
    if entity_type in ("ip", "domain"):
        return cfg.get("network_files", _NETWORK_FILES)
    if entity_type == "url":
        return cfg.get("url_files", _URL_FILES)
    if entity_type == "registry_key":
        return cfg.get("registry_files", _REGISTRY_FILES)
    if entity_type == "user_sid":
        return cfg.get("sid_files", _SID_FILES)
    if entity_type == "mutex":
        return _MUTEX_FILES
    return []


def _retrieve_evidence(
    artifact_dir: Path,
    entity_type: str,
    value: str,
    cfg: dict,
    max_lines: int = 50,
) -> list[dict]:
    files = _get_file_list(entity_type, cfg)
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
    m = re.search(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\b", line)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Stage 3: Triviality / whitelist check
# ---------------------------------------------------------------------------

def _is_trivially_benign(
    entity_type: str,
    value: str,
    evidence: list[dict],
    whitelist: list[str],
) -> bool:
    if entity_type not in ("file_path", "image_name"):
        return False

    norm = value.strip().replace("/", "\\").lower()
    norm_no_drive = re.sub(r"^[a-z]:[/\\]", "", norm)
    matched = any(norm.startswith(p) or norm_no_drive.startswith(p) for p in whitelist)
    if not matched:
        return False

    suspicious_indicators = re.compile(
        r"rwx|shellcode|injected|malfind|entropy=[7-9]\.|"
        r"suspicious|malware|deleted=true|"
        r"appdata.{0,10}temp|recycle\.bin",
        re.IGNORECASE,
    )
    for ev in evidence:
        if suspicious_indicators.search(ev["content"]):
            return False  # whitelist match but suspicious signal → go to LLM

    return True


# ---------------------------------------------------------------------------
# Stage 4: LLM interpreter
# ---------------------------------------------------------------------------

def _call_llm(query: dict, evidence: list[dict], base: Path, llm_cfg: dict) -> dict:
    sys.path.insert(0, str(SCRIPT_DIR))
    from llm_client import call_chat

    prompt_path = base / "prompts" / "agentQ_focused.md"
    if not prompt_path.exists():
        return _fallback_inconclusive(query, evidence, "agentQ_focused.md prompt not found")

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
        return _fallback_inconclusive(query, evidence, f"LLM call failed: {exc}")

    try:
        from llm_client import extract_json
        findings = extract_json(raw)
    except Exception:
        findings = None

    if not isinstance(findings, dict):
        return _fallback_inconclusive(
            query, evidence,
            f"LLM response was not valid JSON: {raw[:200]}"
        )

    # Enforce mandatory envelope fields
    findings["contract_version"] = "1.0"
    findings["query_id"] = query["query_id"]
    findings["responding_module"] = "ram"
    findings.setdefault("entity", entity)
    findings.setdefault("evidence", evidence)
    findings.setdefault("related_entities", [])
    findings.setdefault("cost", {"llm_calls": 1, "tokens_in": 0, "tokens_out": 0})
    findings.setdefault("mitre", [])
    if findings.get("verdict") != "CONFIRMED":
        findings["severity"] = None
    # Normalise entity type strings to lowercase (LLMs sometimes capitalise them)
    for rel in findings.get("related_entities", []):
        if isinstance(rel.get("type"), str):
            rel["type"] = rel["type"].lower()
    return findings


# ---------------------------------------------------------------------------
# Helpers: EntityFindings envelopes
# ---------------------------------------------------------------------------

_ZERO_COST = {"llm_calls": 0, "tokens_in": 0, "tokens_out": 0}


def _make_findings(
    query: dict,
    verdict: str,
    justification: str,
    evidence: list,
    related_entities: list,
    cost: dict,
    severity: str | None = None,
    mitre: list | None = None,
) -> dict:
    return {
        "contract_version": "1.0",
        "query_id": query["query_id"],
        "responding_module": "ram",
        "entity": query["entity"],
        "verdict": verdict,
        "severity": severity if verdict == "CONFIRMED" else None,
        "mitre": mitre or [],
        "justification": justification,
        "evidence": evidence,
        "related_entities": related_entities,
        "cost": cost,
    }


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

def _write_audit(
    base: Path,
    query_id: str,
    query: dict,
    evidence: list,
    findings: dict,
) -> None:
    audit_dir = base / "output" / "queries"
    audit_dir.mkdir(parents=True, exist_ok=True)
    audit_path = audit_dir / f"{query_id}.txt"
    with open(audit_path, "w", encoding="utf-8") as f:
        f.write(f"=== EntityQuery ===\n{json.dumps(query, indent=2)}\n\n")
        f.write(f"=== Retrieved Evidence ({len(evidence)} lines) ===\n")
        for ev in evidence:
            f.write(f"[{ev['source_file']} L{ev['line']}] {ev['content']}\n")
        f.write("\n")
        f.write(f"=== EntityFindings ===\n{json.dumps(findings, indent=2)}\n")


# ---------------------------------------------------------------------------
# Output helper
# ---------------------------------------------------------------------------

def _write_output(
    out_path: str,
    findings: dict,
    query_id: str,
    base: Path,
    query: dict,
    evidence: list,
) -> None:
    errs = _validate(findings, "entity_findings.schema.json")
    if errs:
        print(f"[entity_query] WARN: schema validation errors: {errs[:3]}", flush=True)

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
    print(
        f"[entity_query] Written → {out_path} (verdict={findings.get('verdict')})",
        flush=True,
    )
    _write_audit(base, query_id, query, evidence, findings)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="RAM module — QUERY mode (pivot-back)")
    ap.add_argument("--query", required=True, help="Path to EntityQuery JSON file")
    ap.add_argument("--out",   required=True, help="Path to write EntityFindings JSON")
    ap.add_argument("--base-dir", default=str(BASE_DIR))
    ap.add_argument("--artifact-dir", default=None)
    ap.add_argument("--no-llm", action="store_true",
                    help="Skip LLM stage (return INCONCLUSIVE with raw evidence)")
    args = ap.parse_args()

    base = Path(args.base_dir).resolve()
    cfg = _load_config(base)

    artifact_dir_str = (
        args.artifact_dir
        or cfg.get("grep_input_dir")
        or str(BASE_DIR.parent / "RAM_Artifacts")
    )
    # Resolve relative paths relative to base
    artifact_dir = Path(artifact_dir_str)
    if not artifact_dir.is_absolute():
        artifact_dir = (base / artifact_dir_str).resolve()

    whitelist = _load_whitelist(base)

    # Load and validate the EntityQuery
    with open(args.query, "r", encoding="utf-8") as f:
        query = json.load(f)

    errs = _validate(query, "entity_query.schema.json")
    if errs:
        query.setdefault("query_id", str(uuid.uuid4()))
        query.setdefault("entity", {"type": "image_name", "value": "unknown"})
        findings = _make_findings(
            query, verdict="NOT_APPLICABLE",
            justification=f"Invalid EntityQuery: {'; '.join(errs[:3])}",
            evidence=[], related_entities=[], cost=_ZERO_COST,
        )
        _write_output(args.out, findings, query["query_id"], base, query, [])
        return

    entity = query["entity"]
    entity_type = entity["type"]
    value = entity["value"]

    # Reject queries not targeting this module
    if query.get("target_module", "ram") != "ram":
        findings = _make_findings(
            query, verdict="NOT_APPLICABLE",
            justification=f"Query is for module '{query.get('target_module')}', not 'ram'.",
            evidence=[], related_entities=[], cost=_ZERO_COST,
        )
        _write_output(args.out, findings, query["query_id"], base, query, [])
        return

    # --- Stage 1: type dispatch ---
    if entity_type in NOT_APPLICABLE_TYPES:
        findings = _make_findings(
            query, verdict="NOT_APPLICABLE",
            justification=(
                f"RAM module does not handle entity type '{entity_type}'. "
                f"File hashes are not present in memory artifacts."
            ),
            evidence=[], related_entities=[], cost=_ZERO_COST,
        )
        _write_output(args.out, findings, query["query_id"], base, query, [])
        return

    if entity_type not in SUPPORTED_TYPES and entity_type not in CONDITIONAL_TYPES:
        findings = _make_findings(
            query, verdict="NOT_APPLICABLE",
            justification=(
                f"RAM module does not handle entity type '{entity_type}'. "
                f"Supported: {', '.join(sorted(SUPPORTED_TYPES))}."
            ),
            evidence=[], related_entities=[], cost=_ZERO_COST,
        )
        _write_output(args.out, findings, query["query_id"], base, query, [])
        return

    # mutex is only supported if handles.txt exists
    if entity_type == "mutex":
        handles_file = artifact_dir / "handles.txt"
        if not handles_file.exists():
            findings = _make_findings(
                query, verdict="NOT_APPLICABLE",
                justification="handles.txt not found in RAM artifacts — mutex lookup unavailable.",
                evidence=[], related_entities=[], cost=_ZERO_COST,
            )
            _write_output(args.out, findings, query["query_id"], base, query, [])
            return

    # --- Stage 2: deterministic retrieval ---
    max_ev = int(query.get("scope", {}).get("max_evidence_lines") or 50)
    evidence = _retrieve_evidence(artifact_dir, entity_type, value, cfg, max_lines=max_ev)

    if not evidence:
        findings = _make_findings(
            query, verdict="NOT_FOUND",
            justification=(
                f"No matching lines found for {entity_type}='{value}' "
                f"in any RAM artifact file."
            ),
            evidence=[], related_entities=[], cost=_ZERO_COST,
        )
        _write_output(args.out, findings, query["query_id"], base, query, [])
        return

    # --- Stage 3: triviality check ---
    if _is_trivially_benign(entity_type, value, evidence, whitelist):
        findings = _make_findings(
            query, verdict="REJECTED",
            justification=(
                f"'{value}' matches the trusted-path whitelist and no suspicious "
                f"indicators were found in the retrieved evidence."
            ),
            evidence=evidence[:5], related_entities=[], cost=_ZERO_COST,
        )
        _write_output(args.out, findings, query["query_id"], base, query, evidence)
        return

    # --- Stage 4: LLM interpreter ---
    if args.no_llm:
        findings = _fallback_inconclusive(
            query, evidence, "no-llm mode — manual review required"
        )
        _write_output(args.out, findings, query["query_id"], base, query, evidence)
        return

    llm_cfg_path = base / "llm_config.json"
    if not llm_cfg_path.exists():
        findings = _fallback_inconclusive(
            query, evidence,
            f"llm_config.json not found at {llm_cfg_path}"
        )
        _write_output(args.out, findings, query["query_id"], base, query, evidence)
        return

    sys.path.insert(0, str(SCRIPT_DIR))
    from llm_client import load_llm_config
    llm_cfg = load_llm_config(str(llm_cfg_path))

    findings = _call_llm(query, evidence, base, llm_cfg)

    errs = _validate(findings, "entity_findings.schema.json")
    if errs:
        print(f"[entity_query] WARN: EntityFindings validation errors ({len(errs)}):", flush=True)
        for e in errs[:5]:
            print(f"  - {e}", flush=True)

    _write_output(args.out, findings, query["query_id"], base, query, evidence)


if __name__ == "__main__":
    main()
