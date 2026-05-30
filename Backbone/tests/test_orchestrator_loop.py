"""Orchestrator integration tests.

Coverage:
  test_scan_inputs_are_ingested     — Req 1: graph ingestion from real scan data
  test_case_state_format            — Req 5: case_state.json structure (no LLM)
  test_loop_terminates_convergence  — Req 3a: convergence when nothing left to route
  test_llm_routing_per_finding      — Req 2: LLM closes CONFIRMED, routes INCONCLUSIVE
  test_routing_awareness            — Req 4: LLM routes pid→RAM, file_path→disk
  test_loop_terminates_max_rounds   — Req 3b: loop respects max_rounds cap
  test_end_to_end_case_state        — Req 1+5: full loop on real data, inspects output

Inputs are loaded from  tests/test-data/input/*.json
Outputs are written to  tests/test-data/output/<case-id>/
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from backbone.case_graph import CaseGraph
from backbone.orchestrator.agent import OrchestratorAgent
from backbone.orchestrator.loop import InvestigationLoop

_TEST_DATA = Path(__file__).parent / "test-data"
_INPUT = _TEST_DATA / "input"
_OUTPUT = _TEST_DATA / "output"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load(filename: str) -> dict:
    return json.loads((_INPUT / filename).read_text(encoding="utf-8"))


def _empty_scan(module_id: str, case_id: str) -> dict:
    return {
        "contract_version": "1.0",
        "case_id": case_id,
        "module": module_id,
        "scan_started_at": "2026-05-20T10:00:00Z",
        "scan_completed_at": "2026-05-20T10:00:01Z",
        "summary": "No findings",
        "counts": {"confirmed": 0, "inconclusive": 0, "rejected": 0},
        "findings": [],
    }


def _not_found_response(query: dict) -> dict:
    return {
        "contract_version": "1.0",
        "query_id": query["query_id"],
        "responding_module": query["target_module"],
        "entity": query["entity"],
        "verdict": "NOT_FOUND",
        "severity": None,
        "mitre": [],
        "justification": "No evidence found.",
        "evidence": [],
        "related_entities": [],
        "cost": {"llm_calls": 0, "tokens_in": 0, "tokens_out": 0},
    }


def _mock_module(module_id: str, supported_entity_types: list[str], scan_result: dict) -> MagicMock:
    m = MagicMock()
    m.module_id = module_id
    m.supported_entity_types = supported_entity_types
    m.scan = AsyncMock(return_value=scan_result)
    m.query = AsyncMock(side_effect=_not_found_response)
    return m


def _make_loop(case_id: str, modules: dict, *, max_rounds: int = 5) -> InvestigationLoop:
    out_dir = _OUTPUT / case_id
    return InvestigationLoop(
        case_id=case_id,
        config={"case": {"max_rounds": max_rounds, "output_dir": str(out_dir)}},
        graph=CaseGraph(case_id=case_id),
        orchestrator=OrchestratorAgent(),
        modules=modules,
    )


def _save_output(case_id: str, filename: str, data: dict) -> None:
    out_dir = _OUTPUT / case_id
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / filename).write_text(json.dumps(data, indent=2, default=list), encoding="utf-8")


# ---------------------------------------------------------------------------
# Test 1 — scan ingestion (Req 1) — no LLM
# Input:  scan_real.json
# Output: test-ingest/graph_state.json
# ---------------------------------------------------------------------------

def test_scan_inputs_are_ingested():
    """
    Feeding a real disk scan result into the graph seeds all entities correctly.
    The scanning module must be added to queried_modules for every primary entity.
    """
    data = _load("scan_real.json")
    case_id = "test-ingest"
    graph = CaseGraph(case_id=case_id)

    graph.ingest_scan_result(data)

    unique_primaries = {
        (f["primary_entity"]["type"], f["primary_entity"]["value"])
        for f in data["findings"]
    }
    for key in unique_primaries:
        assert key in graph.nodes, f"Missing entity {key}"

    for key in unique_primaries:
        node = graph.nodes[key]
        assert "disk" in node.queried_modules, f"disk not in queried_modules for {key}"

    summary = graph.summary_for_agent()
    assert summary["case_id"] == case_id
    assert summary["entity_count"] >= len(unique_primaries)
    assert "disk" in summary["modules_scanned"]

    pwdump_key = ("file_path", "SYSVOL\\Windows\\Temp\\perfmon\\PWDumpX.exe")
    assert pwdump_key in graph.nodes
    pwdump_node = graph.nodes[pwdump_key]
    assert any(v["verdict"] == "CONFIRMED" for v in pwdump_node.verdicts_received)
    assert any(v["severity"] == "CRITICAL" for v in pwdump_node.verdicts_received)

    _save_output(case_id, "graph_state.json", graph.to_dict())


# ---------------------------------------------------------------------------
# Test 2 — case_state structure (Req 5) — no LLM
# Input:  scan_real.json
# Output: test-state-format/graph_state.json
# ---------------------------------------------------------------------------

def test_case_state_format():
    """to_dict() must include all keys expected by the report maker."""
    data = _load("scan_real.json")
    case_id = "test-state-format"
    graph = CaseGraph(case_id=case_id)
    graph.ingest_scan_result(data)
    graph.termination_reason = "convergence"

    state = graph.to_dict()

    for key in ("case_id", "entity_count", "modules_scanned", "termination_reason", "rounds", "nodes"):
        assert key in state, f"Missing top-level key: {key!r}"

    assert state["case_id"] == case_id
    assert state["termination_reason"] == "convergence"
    assert isinstance(state["rounds"], list)

    for node_key, node_data in state["nodes"].items():
        for field in ("type", "value", "queried_modules", "finding_count", "verdicts_received"):
            assert field in node_data, f"Node {node_key!r} missing field {field!r}"

    pwdump_key = "file_path:SYSVOL\\Windows\\Temp\\perfmon\\PWDumpX.exe"
    assert pwdump_key in state["nodes"]
    confirmed = next(
        (v for v in state["nodes"][pwdump_key]["verdicts_received"] if v["verdict"] == "CONFIRMED"),
        None,
    )
    assert confirmed is not None
    assert confirmed["severity"] == "CRITICAL"

    _save_output(case_id, "graph_state.json", state)


# ---------------------------------------------------------------------------
# Test 3 — convergence when all entities are CONFIRMED (Req 3a) — no LLM
# Input:  scan_convergence.json
# Output: test-convergence/case_state.json
# ---------------------------------------------------------------------------

def test_loop_terminates_convergence():
    """
    All-CONFIRMED scan → _candidates() returns [] → loop exits with 'convergence'
    before dispatching any round, no LLM call needed.
    """
    case_id = "test-convergence"
    scan = _load("scan_convergence.json")
    scan = dict(scan, case_id=case_id)

    disk = _mock_module("disk", ["file_path"], scan)
    loop = _make_loop(case_id, {"disk": disk})
    loop.run()

    assert loop.graph.termination_reason == "convergence"
    assert len(loop.graph.rounds) == 0

    state_path = _OUTPUT / case_id / "case_state.json"
    state = json.loads(state_path.read_text())
    assert state["termination_reason"] == "convergence"


# ---------------------------------------------------------------------------
# Test 4 — LLM routes INCONCLUSIVE, skips CONFIRMED (Req 2) — LLM
# Input:  scan_llm_routing.json
# Output: test-llm-routing/decisions.json
# ---------------------------------------------------------------------------

@pytest.mark.llm
def test_llm_routing_per_finding():
    """
    OrchestratorAgent.review() pre-filters CONFIRMED entities; only INCONCLUSIVE
    reach the LLM. The LLM must return a 'query' action for the INCONCLUSIVE entity.
    """
    data = _load("scan_llm_routing.json")
    graph = CaseGraph(case_id="test-llm-routing")
    graph.ingest_scan_result(data)

    ram = MagicMock()
    ram.module_id = "ram"
    ram.supported_entity_types = ["ip", "pid", "image_name"]

    decisions = OrchestratorAgent().review(graph, {"ram": ram})

    assert len(decisions) == 1
    decision = decisions[0]
    assert decision["entity"]["value"] == "172.16.10.13"
    assert decision["action"] == "query"
    assert decision["target_module"] == "ram"

    _save_output("test-llm-routing", "decisions.json", decisions)


# ---------------------------------------------------------------------------
# Test 5 — routing awareness: LLM picks correct module (Req 4) — LLM
# Input:  scan_routing_awareness.json
# Output: test-routing-awareness/decisions.json
# ---------------------------------------------------------------------------

@pytest.mark.llm
def test_routing_awareness():
    """
    LLM must route pid→RAM and file_path→disk using only module capability
    declarations, without knowing internal implementation details.
    """
    data = _load("scan_routing_awareness.json")
    graph = CaseGraph(case_id="test-routing-awareness")
    graph.ingest_scan_result(data)

    ram = MagicMock()
    ram.module_id = "ram"
    ram.supported_entity_types = ["pid", "image_name", "mutex"]

    disk = MagicMock()
    disk.module_id = "disk"
    disk.supported_entity_types = ["file_path", "image_name", "ip", "domain", "hash_sha256", "user_sid"]

    decisions = OrchestratorAgent().review(graph, {"ram": ram, "disk": disk})

    by_entity = {d["entity"]["value"]: d for d in decisions}

    pid_decision = by_entity.get("9999")
    assert pid_decision is not None, "No decision for pid:9999"
    assert pid_decision["action"] == "query"
    assert pid_decision["target_module"] == "ram", (
        f"pid:9999 routed to {pid_decision['target_module']!r} instead of 'ram'"
    )

    fp_decision = by_entity.get("C:\\Temp\\suspicious.exe")
    assert fp_decision is not None, "No decision for file_path"
    assert fp_decision["action"] == "query"
    assert fp_decision["target_module"] == "disk", (
        f"file_path routed to {fp_decision['target_module']!r} instead of 'disk'"
    )

    _save_output("test-routing-awareness", "decisions.json", decisions)


# ---------------------------------------------------------------------------
# Test 6 — max_rounds termination (Req 3b) — LLM
# Input:  scan_max_rounds.json
# Output: test-max-rounds/case_state.json
# ---------------------------------------------------------------------------

@pytest.mark.llm
def test_loop_terminates_max_rounds():
    """
    INCONCLUSIVE entity + max_rounds=1: loop dispatches one round then exits
    with 'max_rounds_reached'.
    """
    case_id = "test-max-rounds"
    disk_scan = _load("scan_max_rounds.json")
    disk_scan = dict(disk_scan, case_id=case_id)

    disk = _mock_module("disk", ["ip", "file_path"], disk_scan)
    ram = _mock_module("ram", ["ip", "pid", "image_name"], _empty_scan("ram", case_id))

    loop = _make_loop(case_id, {"disk": disk, "ram": ram}, max_rounds=1)
    loop.run()

    assert loop.graph.termination_reason == "max_rounds_reached"
    assert len(loop.graph.rounds) == 1

    state_path = _OUTPUT / case_id / "case_state.json"
    state = json.loads(state_path.read_text())
    assert state["termination_reason"] == "max_rounds_reached"
    assert len(state["rounds"]) == 1


# ---------------------------------------------------------------------------
# Test 7 — end-to-end with real data (Req 1 + 5) — LLM
# Input:  scan_real.json
# Output: test-e2e-real/case_state.json
# ---------------------------------------------------------------------------

@pytest.mark.llm
def test_end_to_end_case_state():
    """
    Full loop on the real 23-finding disk scan (19 CONFIRMED, 4 INCONCLUSIVE).
    RAM stub returns NOT_FOUND for all queries.
    CONFIRMED entities must never be sent to RAM.
    INCONCLUSIVE entities must be forwarded to RAM (if loop converges).
    """
    data = _load("scan_real.json")
    case_id = "test-e2e-real"
    data = dict(data, case_id=case_id)

    unique_primaries = {
        (f["primary_entity"]["type"], f["primary_entity"]["value"])
        for f in data["findings"]
    }
    inconclusive_entities = {
        (f["primary_entity"]["type"], f["primary_entity"]["value"])
        for f in data["findings"]
        if f["verdict"] == "INCONCLUSIVE"
    }
    confirmed_entities = {
        (f["primary_entity"]["type"], f["primary_entity"]["value"])
        for f in data["findings"]
        if f["verdict"] == "CONFIRMED"
    }

    disk = _mock_module(
        "disk",
        ["file_path", "image_name", "ip", "domain", "hash_sha256", "user_sid"],
        data,
    )
    ram = _mock_module(
        "ram",
        ["file_path", "image_name", "ip", "pid", "mutex"],
        _empty_scan("ram", case_id),
    )

    loop = _make_loop(case_id, {"disk": disk, "ram": ram}, max_rounds=5)
    loop.run()

    graph = loop.graph

    for key in unique_primaries:
        assert key in graph.nodes, f"Entity {key} not ingested"

    for key in confirmed_entities:
        node = graph.nodes[key]
        assert "ram" not in node.queried_modules, (
            f"RAM queried for CONFIRMED entity {key[0]}:{key[1]}"
        )

    if graph.termination_reason == "convergence":
        for key in inconclusive_entities:
            node = graph.nodes[key]
            assert "ram" in node.queried_modules, (
                f"INCONCLUSIVE entity {key[0]}:{key[1]} never sent to RAM"
            )

    assert graph.termination_reason in ("convergence", "max_rounds_reached")

    state_path = _OUTPUT / case_id / "case_state.json"
    state = json.loads(state_path.read_text())

    for key in ("case_id", "entity_count", "modules_scanned", "termination_reason", "rounds", "nodes"):
        assert key in state

    pwdump_key = "file_path:SYSVOL\\Windows\\Temp\\perfmon\\PWDumpX.exe"
    assert pwdump_key in state["nodes"]
    confirmed_v = next(
        (v for v in state["nodes"][pwdump_key]["verdicts_received"] if v["verdict"] == "CONFIRMED"),
        None,
    )
    assert confirmed_v is not None
    assert confirmed_v["severity"] == "CRITICAL"
