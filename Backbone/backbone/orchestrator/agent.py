"""Orchestrator agent — reviews findings and drives the investigation loop."""

from __future__ import annotations

from typing import Any

from backbone.case_graph import CaseGraph


class OrchestratorAgent:
    """
    LLM-backed investigator that reads a case graph summary and decides
    follow-up EntityQuery targets. Implementation filled in a later commit.
    """

    def __init__(self, *, use_llm: bool = False) -> None:
        self.use_llm = use_llm

    def review(self, graph: CaseGraph) -> dict[str, Any]:
        """Return orchestrator decisions: summary text + suggested follow-ups."""
        summary = graph.summary_for_agent()
        return {
            "summary": summary,
            "follow_up_queries": [],
            "notes": "Orchestrator agent scaffold — LLM review not yet wired.",
        }
