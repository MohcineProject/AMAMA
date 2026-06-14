"""Deterministic finding -> tool-execution traceability index.

The incident report is LLM-authored narrative; it cites findings by *entity value*
but carries no machine references back to the tool execution that produced them. This
module closes that gap **deterministically and without the LLM**: it reads the audit
artifacts a run already writes (`*/scan_result.json`, `*/agent_calls.jsonl`,
`threat_intel/queries.jsonl`) and emits an index that maps every finding to the exact
``call_id`` of the agent call that produced it.

Join key everywhere is ``"{type}:{value}"`` — the same entity the narrative cites
verbatim — so a judge reads an entity in the report, finds it here, and gets the
``finding_id``, the verbatim evidence (``source_file:line``) and the producing
``call_id`` to ``grep`` in the named JSONL log. One hop, no guessing.

``finding_id`` -> producing ``call_id`` conventions (verified against example_auditing):
  * RAM   ``ram-chunk_016-f001`` -> ``02_per_chunk_analysis/chunk_016/analyst.txt`` ->
           the single ``ram/pivot_analyst`` call whose ``output_files`` ends with it (1:1).
  * Disk  ``disk-scan-f001`` -> the disk analyst stage (``04_analyst/analyst.txt``); the
           chunked analyst writes one shared file, so this resolves to the *call set* —
           every candidate ``call_id`` is listed (honest; no fabricated 1:1).
  * TI    enrichment carries a ``query_id`` matching ``threat_intel/queries.jsonl`` 1:1.

Usable two ways: called at end-of-run by the orchestrator loop, or standalone via
``python -m backbone.report.traceability <audit_dir>`` to (re)generate for any run.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

_CHUNK_RE = re.compile(r"(chunk_\d+)")
_CONTENT_MAX = 100


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    except Exception:
        return []
    return rows


def _resolve_call(
    module: str, finding_id: str, agent_calls: list[dict[str, Any]]
) -> dict[str, Any]:
    """Map a module ``finding_id`` to the agent call(s) that produced it.

    Returns a ``produced_by`` block. ``call_id`` is a single string when the mapping is
    1:1 (RAM); ``call_ids`` is a list when the finding resolves to a call *set* (disk).
    A missing log or unmatched finding yields ``call_id: null`` with the artifact path
    still recorded, so the chain degrades gracefully rather than breaking.
    """
    log_file = f"{module}/agent_calls.jsonl"

    if module == "ram":
        m = _CHUNK_RE.search(finding_id or "")
        chunk = m.group(1) if m else None
        artifact = (
            f"ram/02_per_chunk_analysis/{chunk}/analyst.txt"
            if chunk
            else "ram/02_per_chunk_analysis/<unknown>/analyst.txt"
        )
        if chunk:
            needle = f"{chunk}/analyst.txt"
            for rec in agent_calls:
                if any(str(o).endswith(needle) for o in rec.get("output_files", [])):
                    return {
                        "agent_name": rec.get("agent_name"),
                        "call_id": rec.get("call_id"),
                        "artifact": artifact,
                        "log_file": log_file,
                    }
        return {"agent_name": "ram/pivot_analyst", "call_id": None,
                "artifact": artifact, "log_file": log_file}

    if module == "disk":
        # Disk findings are all derived from the analyst stage, which writes one shared
        # 04_analyst/analyst.txt across several chunked calls — so the finding maps to
        # the candidate call set, not a single call.
        analyst = [
            rec for rec in agent_calls
            if any(str(o).endswith("analyst.txt") for o in rec.get("output_files", []))
        ]
        call_ids = [rec.get("call_id") for rec in analyst]
        agent_name = analyst[0].get("agent_name") if analyst else "disk/pivot_analyst"
        return {
            "agent_name": agent_name,
            "call_ids": call_ids,
            "artifact": "disk/04_analyst/analyst.txt",
            "log_file": log_file,
            "note": "disk analyst writes one shared file; resolves to the call set",
        }

    return {"agent_name": None, "call_id": None, "artifact": None, "log_file": log_file}


def _evidence_out(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for e in evidence or []:
        content = (e.get("content") or "").replace("\n", " ").replace("\r", " ")
        if len(content) > _CONTENT_MAX:
            content = content[:_CONTENT_MAX] + "…"
        out.append({
            "source_file": e.get("source_file"),
            "line": e.get("line"),
            "content": content,
        })
    return out


def build_trace_index(audit_dir: Path) -> dict[str, Any]:
    """Build the entity-keyed traceability index from an audit folder.

    Reads only files the pipeline already writes; never raises on missing inputs.
    Returns ``{"<type>:<value>": {"type", "value", "findings": [...]}}``.
    """
    audit_dir = Path(audit_dir)
    index: dict[str, Any] = {}

    def _entry(entity: dict[str, Any]) -> dict[str, Any]:
        key = f"{entity.get('type')}:{entity.get('value')}"
        return index.setdefault(
            key,
            {"type": entity.get("type"), "value": entity.get("value"), "findings": []},
        )

    # Forensic modules: finding_id + verbatim evidence -> producing agent call.
    for module in ("ram", "disk"):
        scan = _load_json(audit_dir / module / "scan_result.json")
        if not scan:
            continue
        agent_calls = _load_jsonl(audit_dir / module / "agent_calls.jsonl")
        for f in scan.get("findings", []):
            entity = f.get("primary_entity") or {}
            _entry(entity)["findings"].append({
                "finding_id": f.get("finding_id"),
                "module": module,
                "verdict": f.get("verdict"),
                "severity": f.get("severity"),
                "mitre": f.get("mitre", []),
                "evidence": _evidence_out(f.get("evidence", [])),
                "produced_by": _resolve_call(module, f.get("finding_id", ""), agent_calls),
            })

    # Threat-intel enrichment: each VirusTotal lookup is itself the tool execution,
    # keyed by query_id == call_id record in queries.jsonl.
    for rec in _load_jsonl(audit_dir / "threat_intel" / "queries.jsonl"):
        entity = rec.get("entity") or {}
        if not entity:
            continue
        _entry(entity)["findings"].append({
            "query_id": rec.get("query_id"),
            "module": "ti",
            "verdict": rec.get("verdict"),
            "severity": None,
            "evidence": [],
            "produced_by": {
                "agent_name": rec.get("agent_name", "threat_intel/vt_lookup"),
                "call_id": rec.get("call_id"),
                "artifact": None,
                "log_file": "threat_intel/queries.jsonl",
            },
        })

    return index


def _produced_cell(p: dict[str, Any]) -> str:
    agent = p.get("agent_name") or "—"
    if p.get("call_ids") is not None:
        ids = [c for c in p["call_ids"] if c]
        if not ids:
            return f"{agent} → (no call recorded)"
        if len(ids) == 1:
            return f"{agent} → `{ids[0]}`"
        return f"{agent} → {len(ids)} calls (see log): " + ", ".join(f"`{c}`" for c in ids)
    cid = p.get("call_id")
    return f"{agent} → `{cid}`" if cid else f"{agent} → (no call recorded)"


def _evidence_cell(evidence: list[dict[str, Any]]) -> str:
    if not evidence:
        return "—"
    first = evidence[0]
    loc = f"`{first.get('source_file')}:{first.get('line')}`"
    if len(evidence) > 1:
        loc += f" (+{len(evidence) - 1} more)"
    return loc


def render_markdown(index: dict[str, Any]) -> str:
    """Render the index as the report's deterministic Section 7."""
    lines = [
        "## 7. Evidence Traceability Index",
        "",
        "_Machine-generated (no LLM) — maps every finding to the tool execution that "
        "produced it. Find an entity cited above, read its `finding_id` / `query_id` and "
        "evidence `source_file:line`, then `grep` the `call_id` in the named log "
        "(`produced_by`) to reach the exact agent call (`input_files` / `output_files` / "
        "`timestamp` / tokens). The evidence column shows the first locator with `(+N more)` "
        "when a finding cites several lines; the **complete evidence list — every "
        "`source_file:line` plus its verbatim `content` — is in `backbone/traceability.json`** "
        "(this table mirrors that file)._",
        "",
        "| Entity | finding_id / query_id | module | verdict | severity | "
        "evidence (file:line) | produced_by (agent → call_id) | log |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for key in sorted(index):
        entry = index[key]
        for f in entry["findings"]:
            fid = f.get("finding_id") or f.get("query_id") or "—"
            produced = f.get("produced_by", {})
            lines.append(
                f"| `{key}` | `{fid}` | {f.get('module')} | {f.get('verdict')} | "
                f"{f.get('severity') or '—'} | {_evidence_cell(f.get('evidence', []))} | "
                f"{_produced_cell(produced)} | `{produced.get('log_file') or '—'}` |"
            )
    lines.append("")
    return "\n".join(lines)


def write_index(audit_dir: Path) -> str:
    """Write ``backbone/traceability.json`` into the audit folder; return the Section 7
    markdown. Best-effort: a missing ``backbone/`` dir is created."""
    audit_dir = Path(audit_dir)
    index = build_trace_index(audit_dir)
    bb_dir = audit_dir / "backbone"
    bb_dir.mkdir(parents=True, exist_ok=True)
    (bb_dir / "traceability.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return render_markdown(index)


_SECTION_HEADER = "## 7. Evidence Traceability Index"


def append_section(report_path: Path, section_md: str) -> None:
    """Append (or replace) Section 7 in an incident_report.md, idempotently."""
    report_path = Path(report_path)
    if not report_path.exists():
        return
    text = report_path.read_text(encoding="utf-8")
    idx = text.find(_SECTION_HEADER)
    if idx != -1:
        text = text[:idx].rstrip() + "\n"
    if not text.endswith("\n"):
        text += "\n"
    report_path.write_text(text + "\n---\n\n" + section_md, encoding="utf-8")


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: python -m backbone.report.traceability <audit_dir>", file=sys.stderr)
        return 2
    audit_dir = Path(argv[0])
    if not audit_dir.is_dir():
        print(f"not a directory: {audit_dir}", file=sys.stderr)
        return 2
    section_md = write_index(audit_dir)
    report = audit_dir / "backbone" / "incident_report.md"
    append_section(report, section_md)
    index = build_trace_index(audit_dir)
    n_findings = sum(len(e["findings"]) for e in index.values())
    print(
        f"[traceability] {len(index)} entities, {n_findings} findings → "
        f"{audit_dir / 'backbone' / 'traceability.json'}"
        + (f" + Section 7 in {report.name}" if report.exists() else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
