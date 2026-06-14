"""Deterministic dispatch-guard test (summary #3) — offline, no LLM.

Verifies that InvestigationLoop._dispatch_round drops a query whose target module
does not support the entity's type (e.g. a pid routed to a TI-style module) while
still dispatching a query for a supported type.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from backbone.case_graph import CaseGraph
from backbone.orchestrator.loop import InvestigationLoop


def _ti_like_module(supported):
    """A module mock with a *real* supports_entity_type (MagicMock would be truthy)."""
    m = MagicMock()
    m.module_id = "ti"
    m.supported_entity_types = supported
    m.supports_entity_type = lambda t, _s=supported: t in _s

    async def _resp(query):
        return {
            "contract_version": "1.0",
            "query_id": query["query_id"],
            "responding_module": query["target_module"],
            "entity": query["entity"],
            "verdict": "INCONCLUSIVE",
            "severity": None,
            "mitre": [],
            "justification": "stub",
            "evidence": [],
            "related_entities": [],
            "cost": {"llm_calls": 1, "tokens_in": 10, "tokens_out": 5},
        }

    m.query = AsyncMock(side_effect=_resp)
    return m


def _loop_with(graph, modules):
    return InvestigationLoop(
        case_id="guard-test",
        config={},
        graph=graph,
        orchestrator=MagicMock(),
        modules=modules,
        report_agent=MagicMock(),
    )


def test_dispatch_skips_unsupported_type():
    graph = CaseGraph(case_id="guard-test")
    graph.get_or_create_node("pid", "1234")
    graph.get_or_create_node("ip", "8.8.8.8")

    ti = _ti_like_module(["ip", "domain", "url"])  # does NOT support pid
    loop = _loop_with(graph, {"ti": ti})

    decisions = [
        {"action": "query", "target_module": "ti",
         "entity": {"type": "pid", "value": "1234"}, "reason": "should be skipped"},
        {"action": "query", "target_module": "ti",
         "entity": {"type": "ip", "value": "8.8.8.8"}, "reason": "should dispatch"},
    ]

    asyncio.run(loop._dispatch_round(decisions, round_num=1))

    # Only the supported (ip) query was dispatched.
    assert ti.query.call_count == 1
    dispatched = ti.query.call_args.args[0]
    assert dispatched["entity"] == {"type": "ip", "value": "8.8.8.8"}

    # The ip node was queried by ti; the pid node was not.
    assert "ti" in graph.nodes[("ip", "8.8.8.8")].queried_modules
    assert "ti" not in graph.nodes[("pid", "1234")].queried_modules
