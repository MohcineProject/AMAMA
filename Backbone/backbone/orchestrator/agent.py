"""Orchestrator agent — reviews the case graph and decides routing via LLM."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import anthropic

from backbone.case_graph import CaseGraph

_SYSTEM_PROMPT = (
    Path(__file__).resolve().parents[2] / "prompts" / "orchestrator.md"
).read_text(encoding="utf-8")

_MODEL = "claude-haiku-4-5-20251001"


class OrchestratorAgent:
    """LLM-backed investigator: reads the case graph, decides routing per entity."""

    def __init__(self) -> None:
        self._client = anthropic.Anthropic()

    def review(
        self,
        graph: CaseGraph,
        available_modules: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Returns a list of routing decisions, each a dict with keys:
          entity, target_module (or null), action ("query" | "close"), reason.
        Returns [] when there is nothing left to route (all entities are closed).
        """
        candidates = self._candidates(graph)
        if not candidates:
            return []

        module_caps = {
            mid: getattr(m, "supported_entity_types", [])
            for mid, m in available_modules.items()
        }
        user_msg = json.dumps(
            {
                "case_id": graph.case_id,
                "candidates": candidates,
                "available_modules": module_caps,
            },
            separators=(",", ":"),
        )

        response = self._client.messages.create(
            model=_MODEL,
            max_tokens=1024,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", response.content[0].text.strip())
        return json.loads(text)

    def _candidates(self, graph: CaseGraph) -> list[dict[str, Any]]:
        """Entities that still need routing: INCONCLUSIVE or NOT_FOUND, never CONFIRMED."""
        candidates = []
        for node in graph.nodes.values():
            verdicts = {f.get("verdict") for f in node.findings}
            if "CONFIRMED" in verdicts or "REJECTED" in verdicts:
                continue
            if not verdicts & {"INCONCLUSIVE", "NOT_FOUND"}:
                continue
            candidates.append(
                {
                    "entity": {"type": node.type, "value": node.value},
                    "verdicts": sorted(v for v in verdicts if v),
                    "queried_modules": sorted(node.queried_modules),
                }
            )
        return candidates
