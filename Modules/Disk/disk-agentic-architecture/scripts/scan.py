#!/usr/bin/env python3
"""
Entry point 1 — INITIAL scan mode.

Wraps the existing disk DFIR pipeline and emits a ModuleScanResult JSON
so the orchestrator can consume disk findings in the typed-envelope format.

Usage:
    python scripts/scan.py --case-id <id> --out <output_dir>
                           [--base-dir <dir>] [--artifact-dir <dir>]
                           [--run-pipeline] [--no-llm]

    --case-id         Required. Identifies the investigation.
    --out             Directory where scan_result.json will be written.
    --run-pipeline    If set, run_pipeline.py is invoked first before parsing.
    --no-llm          Pass through to run_pipeline.py to skip LLM stages.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
SCHEMA_DIR = BASE_DIR / "schemas"

_ENTITY_TYPE_REGISTRY = re.compile(
    r"^hk(lm|cu|u|cr|cc)\\", re.IGNORECASE
)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")

# Supported severity values for the schema enum
_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _infer_entity_type(key: str) -> str:
    """Infer entity.type from the finding's Key field."""
    k = key.strip()
    if _ENTITY_TYPE_REGISTRY.match(k):
        return "registry_key"
    if _URL_RE.match(k):
        return "url"
    if _IP_RE.match(k):
        return "ip"
    if _DOMAIN_RE.match(k) and "." in k:
        return "domain"
    if _HASH_RE.match(k):
        n = len(k)
        if n == 32:
            return "hash_md5"
        if n == 40:
            return "hash_sha1"
        if n == 64:
            return "hash_sha256"
    if "\\" in k or "/" in k:
        return "file_path"
    _, ext = os.path.splitext(k.lower())
    if ext in {".exe", ".dll", ".bat", ".ps1", ".vbs", ".scr", ".sys"}:
        return "image_name"
    return "image_name"


def _parse_evidence_lines(evidence_text: str) -> list[dict]:
    """
    Parse `Key Evidence:` lines into evidence dicts.

    Lines look like:
        - L1234: type=file path=...
        - L5678: type=eventlog ...
    """
    items = []
    for raw in evidence_text.splitlines():
        raw = raw.strip().lstrip("- ").strip()
        if not raw:
            continue
        # Try to extract line number from leading L<N>: prefix
        m = re.match(r"^L(\d+):\s*(.*)", raw)
        if m:
            line_no = int(m.group(1))
            content = m.group(2)
        else:
            line_no = 1
            content = raw
        items.append({
            "source_file": "analyst.txt",
            "line": line_no,
            "content": content,
            "verbatim": True,
            "timestamp": None,
        })
    return items[:50]  # cap per contract default


def _extract_mitre(mitre_raw: str) -> list[str]:
    """Extract MITRE technique IDs like T1059 or T1059.001 from a raw string."""
    return re.findall(r"T\d{4}(?:\.\d{3})?", mitre_raw)


def _parse_analyst(text: str, finding_offset: int = 0) -> list[dict]:
    """
    Parse [CONFIRMED] and [INCONCLUSIVE] blocks from analyst.txt.
    Returns a list of finding dicts ready for ModuleScanResult.
    """
    findings = []
    # Split text on block start markers
    chunks = re.split(r"(?=\[(?:CONFIRMED|INCONCLUSIVE)\])", text)

    idx = finding_offset
    for chunk in chunks:
        chunk = chunk.strip()
        verdict = None
        if chunk.startswith("[CONFIRMED]"):
            verdict = "CONFIRMED"
        elif chunk.startswith("[INCONCLUSIVE]"):
            verdict = "INCONCLUSIVE"
        else:
            continue

        idx += 1

        def _field(name: str) -> str:
            m = re.search(rf"^{name}:\s*(.+)$", chunk, re.MULTILINE | re.IGNORECASE)
            return m.group(1).strip() if m else ""

        key = _field("Key")
        if not key:
            continue

        entity_type = _infer_entity_type(key)
        severity_raw = _field("Severity").lower()
        severity = _SEVERITY_MAP.get(severity_raw)
        if verdict == "CONFIRMED" and severity is None:
            severity = "MEDIUM"  # safe fallback
        mitre = _extract_mitre(_field("MITRE"))

        # Extract justification block
        just_m = re.search(r"Justification:\s*\n(.*?)(?:\n\s*Key Evidence:|\n-{40}|\Z)",
                            chunk, re.DOTALL | re.IGNORECASE)
        justification = just_m.group(1).strip() if just_m else f"Disk finding: {key}"
        if not justification:
            justification = f"Disk finding: {key}"

        # Extract Key Evidence block
        ev_m = re.search(r"Key Evidence:\s*\n(.*?)(?:\n-{40}|\Z)", chunk,
                          re.DOTALL | re.IGNORECASE)
        evidence_text = ev_m.group(1) if ev_m else ""
        evidence = _parse_evidence_lines(evidence_text)

        finding = {
            "finding_id": f"disk-scan-f{idx:03d}",
            "verdict": verdict,
            "severity": severity if verdict == "CONFIRMED" else None,
            "mitre": mitre,
            "primary_entity": {"type": entity_type, "value": key},
            "related_entities": [],
            "justification": justification,
            "evidence": evidence,
        }
        findings.append(finding)

    return findings


def _parse_triage_combined(text: str) -> list[dict]:
    """
    Fallback parser when analyst.txt is not available.
    Parses [FINDING] blocks from triage_combined.txt and maps them to
    ModuleScanResult findings with verdict=INCONCLUSIVE (no Agent 2 validation).
    """
    findings = []
    chunks = re.split(r"(?=\[FINDING\])", text)
    idx = 0
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk.startswith("[FINDING]"):
            continue
        idx += 1

        def _field(name: str) -> str:
            m = re.search(rf"^{name}\s*:\s*(.+)$", chunk, re.MULTILINE | re.IGNORECASE)
            return m.group(1).strip() if m else ""

        key = _field("key")
        if not key:
            continue
        severity_raw = _field("severity").lower()
        severity = _SEVERITY_MAP.get(severity_raw)
        justification = f"Agent 1 triage finding (pivot analyst not yet run): {_field('reasons')}"

        finding = {
            "finding_id": f"disk-triage-f{idx:03d}",
            "verdict": "INCONCLUSIVE",
            "severity": None,
            "mitre": [],
            "primary_entity": {"type": _infer_entity_type(key), "value": key},
            "related_entities": [],
            "justification": justification,
            "evidence": [],
        }
        findings.append(finding)
    return findings


def _validate(data: dict, schema_name: str) -> list[str]:
    """Validate data against a local schema. Returns list of error strings."""
    try:
        import jsonschema
    except ImportError:
        return ["jsonschema not installed — skipping validation"]
    schema_path = SCHEMA_DIR / schema_name
    if not schema_path.exists():
        return [f"Schema not found: {schema_path}"]
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)
    errors = list(jsonschema.Draft7Validator(schema).iter_errors(data))
    return [e.message for e in errors]


def main() -> None:
    ap = argparse.ArgumentParser(description="Disk module — INITIAL scan entry point")
    ap.add_argument("--case-id", required=True, help="Case identifier")
    ap.add_argument("--out", required=True, help="Output directory for scan_result.json")
    ap.add_argument("--base-dir", default=str(BASE_DIR))
    ap.add_argument("--artifact-dir", default=None)
    ap.add_argument("--run-pipeline", action="store_true",
                    help="Invoke run_pipeline.py before parsing analyst.txt")
    ap.add_argument("--no-llm", action="store_true",
                    help="Pass to run_pipeline.py to skip LLM stages")
    args = ap.parse_args()

    base = Path(args.base_dir).resolve()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    started_at = _now_iso()

    if args.run_pipeline:
        py = sys.executable
        cmd = [py, str(SCRIPT_DIR / "run_pipeline.py"), "--base-dir", str(base)]
        if args.artifact_dir:
            cmd += ["--artifact-dir", args.artifact_dir]
        if args.no_llm:
            cmd.append("--no-llm")
        print(f"[scan] Running pipeline: {' '.join(cmd)}", flush=True)
        result = subprocess.run(cmd, check=False)
        if result.returncode != 0:
            print(f"[scan] WARN: run_pipeline.py exited {result.returncode}", flush=True)

    completed_at = _now_iso()

    # Prefer analyst.txt (Agent 2 validated); fall back to triage_combined.txt
    analyst_path = base / "output" / "analyst.txt"
    combined_path = base / "output" / "triage_combined.txt"
    legacy_triage = base / "output" / "triage.txt"

    findings: list[dict] = []
    used_source = "none"

    if analyst_path.exists():
        text = analyst_path.read_text(encoding="utf-8", errors="ignore")
        findings = _parse_analyst(text)
        used_source = "analyst.txt"
    elif combined_path.exists():
        text = combined_path.read_text(encoding="utf-8", errors="ignore")
        findings = _parse_triage_combined(text)
        used_source = "triage_combined.txt"
    elif legacy_triage.exists():
        text = legacy_triage.read_text(encoding="utf-8", errors="ignore")
        findings = _parse_triage_combined(text)
        used_source = "triage.txt (legacy)"

    print(f"[scan] Parsed {len(findings)} finding(s) from {used_source}", flush=True)

    confirmed   = sum(1 for f in findings if f["verdict"] == "CONFIRMED")
    inconclusive = sum(1 for f in findings if f["verdict"] == "INCONCLUSIVE")
    rejected    = sum(1 for f in findings if f["verdict"] == "REJECTED")

    scan_result = {
        "contract_version": "1.0",
        "case_id": args.case_id,
        "module": "disk",
        "scan_started_at": started_at,
        "scan_completed_at": completed_at,
        "summary": (
            f"{len(findings)} finding(s) from disk artifacts "
            f"(source: {used_source}). "
            f"{confirmed} CONFIRMED, {inconclusive} INCONCLUSIVE, {rejected} REJECTED."
        ),
        "counts": {
            "confirmed": confirmed,
            "inconclusive": inconclusive,
            "rejected": rejected,
        },
        "findings": findings,
        "artifacts": {
            "human_report": str(analyst_path.relative_to(base) if analyst_path.exists()
                                else (combined_path.relative_to(base) if combined_path.exists()
                                      else "output/analyst.txt")),
        },
    }

    errors = _validate(scan_result, "module_scan_result.schema.json")
    if errors:
        print(f"[scan] WARN: schema validation errors ({len(errors)}):", flush=True)
        for e in errors[:5]:
            print(f"  - {e}", flush=True)

    out_path = out_dir / "scan_result.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(scan_result, f, indent=2)

    print(f"[scan] Written → {out_path} ({out_path.stat().st_size:,} bytes)", flush=True)
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
