#!/usr/bin/env python3
"""
Entry point 1 — INITIAL scan mode.

Wraps the existing disk DFIR pipeline and emits a ModuleScanResult JSON
so the orchestrator can consume disk findings in the typed-envelope format.


TODO: CLI to be cleaned afterwards, only exist for test purposes
Usage:
    python scripts/scan.py --case-id <id> --out <output_dir>
                           [--base-dir <dir>] [--artifact-dir <dir>]
                           [--run-pipeline] [--no-llm]

    --case-id         Required. Identifies the investigation.
    --out             Directory where scan_result.json will be written.
    --run-pipeline    If set, run_pipeline.py is invoked first before parsing.
    --no-llm          Pass through to run_pipeline.py to skip LLM stages.

Library entry points:
  - ``build_scan_result()`` — sync
  - ``build_scan_result_async()`` — async wrapper (used by ``DiskModule.scan()``)
"""

import argparse
import json
import asyncio
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR   = Path(__file__).resolve().parent
BASE_DIR     = SCRIPT_DIR.parent
_DISK_DIR    = BASE_DIR.parent
_MODULES_DIR = _DISK_DIR.parent
_PROJECT_DIR = _MODULES_DIR.parent
SCHEMA_DIR   = _PROJECT_DIR / "Backbone" / "schemas"

# Mounter/collector live under Modules/Disk/ (a.k.a. _DISK_DIR). The MOUNT
# config.json written by mount_image.py is a DIFFERENT file from the analysis
# config.json inside disk-agentic-architecture/ — do not conflate the two.
_MOUNT_SCRIPT     = _DISK_DIR / "disk-image-mounter" / "mount_image.py"
_COLLECT_SCRIPT   = _DISK_DIR / "disk-collector" / "disk_collector.py"
_MOUNT_CONFIG     = _DISK_DIR / "config.json"
_DEFAULT_ARTIFACTS = _DISK_DIR / "Disk_Artifacts"

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

    Preferred format (emitted by agent2_pivot.md):
        - [artifact_filename.txt L1234]: type=file path=...

    Legacy format (older analyst.txt files without source prefix):
        - L1234: type=file path=...
        - type=eventlog ...
    """
    # Matches [filename L<N>]: content
    _PREFIXED = re.compile(r"^\[([^\]]+)\s+L(\d+)\]:\s*(.*)", re.IGNORECASE)
    # Matches legacy L<N>: content
    _LEGACY_LINENO = re.compile(r"^L(\d+):\s*(.*)")

    items = []
    for raw in evidence_text.splitlines():
        raw = raw.strip().lstrip("- ").strip()
        if not raw:
            continue
        m = _PREFIXED.match(raw)
        if m:
            source_file = m.group(1).strip()
            line_no = int(m.group(2))
            content = m.group(3)
        else:
            m2 = _LEGACY_LINENO.match(raw)
            if m2:
                line_no = int(m2.group(1))
                content = m2.group(2)
            else:
                line_no = 1
                content = raw
            source_file = "analyst.txt"
        items.append({
            "source_file": source_file,
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
    chunks = re.split(r"(?=\[(?:CONFIRMED|INCONCLUSIVE|REJECTED)\])", text)

    idx = finding_offset
    for chunk in chunks:
        chunk = chunk.strip()
        verdict = None
        if chunk.startswith("[CONFIRMED]"):
            verdict = "CONFIRMED"
        elif chunk.startswith("[INCONCLUSIVE]"):
            verdict = "INCONCLUSIVE"
        elif chunk.startswith("[REJECTED]"):
            verdict = "REJECTED"
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
        elif verdict != "CONFIRMED":
            severity = None  # Backbone schema enforces null for non-CONFIRMED
        mitre = _extract_mitre(_field("MITRE"))

        if verdict == "REJECTED":
            finding = {
                "finding_id": f"disk-scan-f{idx:03d}",
                "verdict": "REJECTED",
                "severity": None,
                "mitre": [],
                "primary_entity": {"type": _infer_entity_type(key), "value": key},
                "related_entities": [],
                "justification": _field("Legitimate explanation") or _field("Justification") or f"Rejected: {key}",
                "evidence": [],
            }
            findings.append(finding)
            continue

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
            "severity": severity,  # preserved for CONFIRMED and INCONCLUSIVE (from Agent 1 via prompt)
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

# Lines worth surfacing on the orchestrator's (interleaved) stream; everything
# else goes only to disk.log. Keeps the parallel run.log readable (REMARKS #9).
# Matched by line prefix so we relay the high-level pipeline/analyst progress but
# NOT pivot_search's verbose per-finding lines (which start with "[pivot] ").
_DISK_RELAY_PREFIXES = ("[pipeline", "[pivot_analyst]")


def _disk_relay(line: str) -> bool:
    if any(kw in line for kw in ("ERROR", "WARN", "Traceback")):
        return True
    return line.lstrip().startswith(_DISK_RELAY_PREFIXES)


def _run_logged(cmd: list[str], log_path: Path, relay, label: str) -> int:
    """Run cmd, tee its combined stdout+stderr to log_path, and relay only the
    lines for which relay(line) is True to this process's stdout. Returns rc."""
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[scan] {label} detail → {log_path}", flush=True)
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None
    # buffering=1 → line-buffered, so the log file updates live (tailable).
    with open(log_path, "w", encoding="utf-8", buffering=1) as logf:
        for line in proc.stdout:
            logf.write(line)
            if relay(line):
                sys.stdout.write(line)
                sys.stdout.flush()
    proc.wait()
    return proc.returncode


def _run_pipeline(base: Path, artifact_dir: str | None, no_llm: bool) -> None:
    py = sys.executable
    cmd = [py, str(SCRIPT_DIR / "run_pipeline.py"), "--base-dir", str(base)]
    if artifact_dir:
        cmd += ["--artifact-dir", artifact_dir]
    if no_llm:
        cmd.append("--no-llm")
    rc = _run_logged(cmd, base / "output" / "disk.log", _disk_relay, "Disk pipeline")
    if rc != 0:
        raise RuntimeError(f"run_pipeline.py exited with code {rc}")


def _sudo_prefix() -> list[str]:
    """Non-interactive sudo prefix when not already root (mounting needs root).

    Returns an empty list when already root to avoid double-sudo (so both
    ``python3 -m backbone run …`` and ``sudo -E python3 -m backbone run …`` work).
    """
    return [] if os.geteuid() == 0 else ["sudo", "-n"]


def _collect_from_image(image_dir: Path, artifact_dir: str | None, mode: str) -> bool:
    """Mount the disk image and collect Windows artifacts into ``artifact_dir``.

    Symmetric to RAM's image-driven extraction (scan_result_emitter._run_full_pipeline).
    Mounting/collection require root, so each subprocess is prefixed with ``sudo -n``
    unless already root. Best-effort: on failure we log a WARN and return False so the
    caller falls back to any existing artifacts and the orchestrator still completes.
    The image is ALWAYS unmounted in the ``finally`` block.

    Returns True if mount+collect both succeeded.
    """
    py = sys.executable
    sudo = _sudo_prefix()
    out_dir = artifact_dir or str(_DEFAULT_ARTIFACTS)
    mode_flag = "--full" if mode == "full" else "--fast"

    print(f"[scan] Auto-collecting disk artifacts from image dir: {image_dir}", flush=True)
    print(f"[scan] mode={mode_flag.lstrip('-')} out-dir={out_dir} "
          f"{'(via sudo -n)' if sudo else '(already root)'}", flush=True)

    try:
        # Stage 1: mount image → MOUNT config.json (auto-detects E01/dd/raw/vmdk/vhd).
        mount_cmd = sudo + [
            py, str(_MOUNT_SCRIPT),
            "--image-dir", str(image_dir),
            "--out-config", str(_MOUNT_CONFIG),
        ]
        print(f"[scan] Mounting image: {' '.join(mount_cmd)}", flush=True)
        rc = subprocess.run(mount_cmd, check=False).returncode
        if rc != 0:
            print(f"[scan] WARN: mount_image.py exited {rc} — falling back to "
                  f"existing artifacts in {out_dir}", flush=True)
            return False

        # Stage 2: collect Windows artifacts → artifact_dir.
        collect_cmd = sudo + [
            py, str(_COLLECT_SCRIPT),
            "--config", str(_MOUNT_CONFIG),
            mode_flag,
            "--out-dir", out_dir,
            "--workers", "4",
            "--summary-out", str(Path(out_dir) / "collector_summary.json"),
        ]
        print(f"[scan] Collecting artifacts: {' '.join(collect_cmd)}", flush=True)
        rc = subprocess.run(collect_cmd, check=False).returncode
        if rc != 0:
            print(f"[scan] WARN: disk_collector.py exited {rc} — falling back to "
                  f"existing artifacts in {out_dir}", flush=True)
            return False

        print(f"[scan] Disk collection complete → {out_dir}", flush=True)
        return True
    except Exception as exc:  # never let collection failure abort the orchestrator
        print(f"[scan] WARN: disk collection raised {exc!r} — falling back to "
              f"existing artifacts in {out_dir}", flush=True)
        return False
    finally:
        # Always unmount, even on failure/partial mount.
        umount_cmd = sudo + [py, str(_MOUNT_SCRIPT), "--umount"]
        print(f"[scan] Unmounting image: {' '.join(umount_cmd)}", flush=True)
        subprocess.run(umount_cmd, check=False)


def build_scan_result(
    case_id: str,
    base_dir: Path | None = None,
    *,
    no_llm: bool = False,
    artifact_dir: str | None = None,
    image_dir: str | None = None,
    collect_mode: str = "fast",
    reuse_analysis: bool = False,
) -> dict:
    """Run the disk pipeline and return a ModuleScanResult dict.

    When ``image_dir`` is supplied, the raw disk image is mounted and Windows
    artifacts are collected into ``artifact_dir`` first (symmetric to RAM's
    image-driven extraction). When unset, the existing ``Disk_Artifacts`` are used.

    When ``reuse_analysis`` is True and a prior ``output/analyst.txt`` exists, the
    triage→pivot→analyst LLM pipeline is skipped entirely and the result is
    re-emitted from that existing analyst output (symmetric to RAM reusing
    ``aggregated_analyst.txt`` when no ``ram_image`` is set) — zero LLM cost.
    """
    base = Path(base_dir or BASE_DIR).resolve()
    started_at = _now_iso()

    # Auto-collect from the raw image when configured (mirrors RAM's `if image:` gate).
    if image_dir:
        _collect_from_image(Path(image_dir).resolve(), artifact_dir, collect_mode)

    # Reuse existing analyst output when requested (skip the costly LLM pipeline).
    _reuse = reuse_analysis and (base / "output" / "analyst.txt").exists()
    if reuse_analysis and not _reuse:
        print(
            "[scan] WARN: reuse_analysis set but output/analyst.txt missing — "
            "running the full pipeline instead.",
            flush=True,
        )
    if not _reuse:
        _run_pipeline(base, artifact_dir, no_llm)
    else:
        print("[scan] Reusing existing output/analyst.txt (LLM pipeline skipped).", flush=True)

    completed_at = _now_iso()

    # Prefer analyst.txt (Agent 2 validated); fall back to triage_combined.txt
    analyst_path = base / "output" / "analyst.txt"
    combined_path = base / "output" / "triage_combined.txt"
    legacy_triage = base / "output" / "triage.txt"

    all_findings: list[dict] = []
    used_source = "none"
    human_report = "output/analyst.txt"

    if analyst_path.exists():
        text = analyst_path.read_text(encoding="utf-8", errors="ignore")
        all_findings = _parse_analyst(text)
        used_source = "analyst.txt"
        human_report = str(analyst_path.relative_to(base))
    elif combined_path.exists():
        text = combined_path.read_text(encoding="utf-8", errors="ignore")
        all_findings = _parse_triage_combined(text)
        used_source = "triage_combined.txt"
        human_report = str(combined_path.relative_to(base))
    elif legacy_triage.exists():
        text = legacy_triage.read_text(encoding="utf-8", errors="ignore")
        all_findings = _parse_triage_combined(text)
        used_source = "triage.txt (legacy)"
        human_report = str(legacy_triage.relative_to(base))

    confirmed    = sum(1 for f in all_findings if f["verdict"] == "CONFIRMED")
    inconclusive = sum(1 for f in all_findings if f["verdict"] == "INCONCLUSIVE")
    rejected     = sum(1 for f in all_findings if f["verdict"] == "REJECTED")
    findings     = [f for f in all_findings if f["verdict"] != "REJECTED"]

    return {
        "contract_version": "1.0",
        "case_id": case_id,
        "module": "disk",
        "scan_started_at": started_at,
        "scan_completed_at": completed_at,
        "summary": (
            f"{confirmed + inconclusive} finding(s) from disk artifacts "
            f"(source: {used_source}). "
            f"{confirmed} CONFIRMED, {inconclusive} INCONCLUSIVE, {rejected} REJECTED."
        ),
        "counts": {
            "confirmed": confirmed,
            "inconclusive": inconclusive,
            "rejected": rejected,
        },
        "findings": findings,
        "artifacts": {"human_report": human_report},
    }


async def build_scan_result_async(
    case_id: str,
    base_dir: Path | None = None,
    *,
    no_llm: bool = False,
    artifact_dir: str | None = None,
    image_dir: str | None = None,
    collect_mode: str = "fast",
    reuse_analysis: bool = False,
) -> dict:
    """Async wrapper — runs (optional) collection + pipeline + parsing in a thread pool."""
    return await asyncio.to_thread(
        build_scan_result,
        case_id,
        base_dir,
        no_llm=no_llm,
        artifact_dir=artifact_dir,
        image_dir=image_dir,
        collect_mode=collect_mode,
        reuse_analysis=reuse_analysis,
    )

# TODO: clean CLI after tests ended
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

    all_findings: list[dict] = []
    used_source = "none"
    human_report = "output/analyst.txt"

    if analyst_path.exists():
        text = analyst_path.read_text(encoding="utf-8", errors="ignore")
        all_findings = _parse_analyst(text)
        used_source = "analyst.txt"
        human_report = str(analyst_path.relative_to(base))
    elif combined_path.exists():
        text = combined_path.read_text(encoding="utf-8", errors="ignore")
        all_findings = _parse_triage_combined(text)
        used_source = "triage_combined.txt"
        human_report = str(combined_path.relative_to(base))
    elif legacy_triage.exists():
        text = legacy_triage.read_text(encoding="utf-8", errors="ignore")
        all_findings = _parse_triage_combined(text)
        used_source = "triage.txt (legacy)"
        human_report = str(legacy_triage.relative_to(base))

    confirmed    = sum(1 for f in all_findings if f["verdict"] == "CONFIRMED")
    inconclusive = sum(1 for f in all_findings if f["verdict"] == "INCONCLUSIVE")
    rejected     = sum(1 for f in all_findings if f["verdict"] == "REJECTED")
    findings     = [f for f in all_findings if f["verdict"] != "REJECTED"]

    print(f"[scan] Parsed {len(all_findings)} finding(s) from {used_source} "
          f"({confirmed} CONFIRMED, {inconclusive} INCONCLUSIVE, {rejected} REJECTED)", flush=True)

    scan_result = {
        "contract_version": "1.0",
        "case_id": args.case_id,
        "module": "disk",
        "scan_started_at": started_at,
        "scan_completed_at": completed_at,
        "summary": (
            f"{confirmed + inconclusive} finding(s) from disk artifacts "
            f"(source: {used_source}). "
            f"{confirmed} CONFIRMED, {inconclusive} INCONCLUSIVE, {rejected} REJECTED."
        ),
        "counts": {
            "confirmed": confirmed,
            "inconclusive": inconclusive,
            "rejected": rejected,
        },
        "findings": findings,
        "artifacts": {"human_report": human_report},
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
