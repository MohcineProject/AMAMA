"""Tests for the deterministic finding -> tool-execution traceability index."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backbone.report.traceability import (
    append_section,
    build_trace_index,
    render_markdown,
    write_index,
)

_EXAMPLE = Path(__file__).resolve().parents[2] / "example_auditing"


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


@pytest.fixture()
def audit_dir(tmp_path: Path) -> Path:
    """A minimal but representative audit tree covering RAM, disk and TI."""
    _write_json(tmp_path / "ram" / "scan_result.json", {
        "findings": [{
            "finding_id": "ram-chunk_005-f001",
            "verdict": "CONFIRMED",
            "severity": "HIGH",
            "primary_entity": {"type": "pid", "value": "800"},
            "evidence": [{"source_file": "privileges.txt", "line": 185, "content": "800 csrss"}],
        }],
    })
    _write_jsonl(tmp_path / "ram" / "agent_calls.jsonl", [
        {"call_id": "RAM-TRIAGE", "agent_name": "ram/triage_agent",
         "output_files": ["02_per_chunk_analysis/chunk_005/triage.txt"]},
        {"call_id": "RAM-ANALYST", "agent_name": "ram/pivot_analyst",
         "output_files": ["02_per_chunk_analysis/chunk_005/analyst.txt"]},
    ])
    _write_json(tmp_path / "disk" / "scan_result.json", {
        "findings": [{
            "finding_id": "disk-scan-f001",
            "verdict": "CONFIRMED",
            "severity": "HIGH",
            "primary_entity": {"type": "image_name", "value": "SDELETE.EXE"},
            "evidence": [{"source_file": "prefetch_records.txt", "line": 131, "content": "x"}],
        }],
    })
    _write_jsonl(tmp_path / "disk" / "agent_calls.jsonl", [
        {"call_id": "DISK-1", "agent_name": "disk/pivot_analyst",
         "output_files": ["04_analyst/analyst.txt"]},
        {"call_id": "DISK-2", "agent_name": "disk/pivot_analyst",
         "output_files": ["04_analyst/analyst.txt"]},
    ])
    _write_jsonl(tmp_path / "threat_intel" / "queries.jsonl", [
        {"call_id": "TI-1", "query_id": "Q1", "agent_name": "threat_intel/vt_lookup",
         "entity": {"type": "ip", "value": "1.2.3.4"}, "verdict": "NOT_FOUND"},
    ])
    return tmp_path


def test_index_keyed_by_type_value(audit_dir: Path):
    index = build_trace_index(audit_dir)
    assert set(index) == {"pid:800", "image_name:SDELETE.EXE", "ip:1.2.3.4"}


def test_ram_finding_resolves_1to1(audit_dir: Path):
    f = build_trace_index(audit_dir)["pid:800"]["findings"][0]
    assert f["finding_id"] == "ram-chunk_005-f001"
    assert f["produced_by"]["call_id"] == "RAM-ANALYST"  # not the triage call
    assert f["produced_by"]["artifact"].endswith("chunk_005/analyst.txt")


def test_disk_finding_resolves_to_call_set(audit_dir: Path):
    f = build_trace_index(audit_dir)["image_name:SDELETE.EXE"]["findings"][0]
    assert f["produced_by"]["call_ids"] == ["DISK-1", "DISK-2"]
    assert f["produced_by"]["artifact"] == "disk/04_analyst/analyst.txt"


def test_ti_finding_resolves_via_query_id(audit_dir: Path):
    f = build_trace_index(audit_dir)["ip:1.2.3.4"]["findings"][0]
    assert f["module"] == "ti"
    assert f["query_id"] == "Q1"
    assert f["produced_by"]["call_id"] == "TI-1"
    assert f["produced_by"]["log_file"] == "threat_intel/queries.jsonl"


def test_render_markdown_contains_calls(audit_dir: Path):
    md = render_markdown(build_trace_index(audit_dir))
    assert "## 7. Evidence Traceability Index" in md
    for cid in ("RAM-ANALYST", "DISK-1", "DISK-2", "TI-1"):
        assert cid in md


def test_write_index_and_append_idempotent(audit_dir: Path):
    report = audit_dir / "backbone" / "incident_report.md"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text("# Incident Report\n\n## 6. Pipeline Metadata\n", encoding="utf-8")

    for _ in range(2):
        section = write_index(audit_dir)
        append_section(report, section)

    assert (audit_dir / "backbone" / "traceability.json").exists()
    assert report.read_text(encoding="utf-8").count("## 7. Evidence Traceability Index") == 1


def test_missing_inputs_never_raise(tmp_path: Path):
    assert build_trace_index(tmp_path) == {}
    # write_index tolerates an empty tree and still emits the JSON.
    write_index(tmp_path)
    assert (tmp_path / "backbone" / "traceability.json").exists()


@pytest.mark.skipif(not _EXAMPLE.is_dir(), reason="example_auditing not present")
def test_example_every_forensic_finding_traces():
    index = build_trace_index(_EXAMPLE)

    # Every entity in the module scan results is present in the index.
    for module in ("ram", "disk"):
        scan = json.loads((_EXAMPLE / module / "scan_result.json").read_text())
        for finding in scan["findings"]:
            e = finding["primary_entity"]
            key = f"{e['type']}:{e['value']}"
            assert key in index

    ti_query_ids = {
        json.loads(line)["query_id"]
        for line in (_EXAMPLE / "threat_intel" / "queries.jsonl").read_text().splitlines()
        if line.strip()
    }

    for entry in index.values():
        for f in entry["findings"]:
            produced = f["produced_by"]
            if f["module"] == "ram":
                # RAM resolves 1:1 to the producing analyst call.
                assert f["finding_id"]
                assert produced["call_id"], f"unresolved RAM call for {f['finding_id']}"
            elif f["module"] == "disk":
                assert f["finding_id"]
                assert produced["call_ids"], f"unresolved disk calls for {f['finding_id']}"
            elif f["module"] == "ti":
                assert f["query_id"] in ti_query_ids
                assert produced["call_id"]
