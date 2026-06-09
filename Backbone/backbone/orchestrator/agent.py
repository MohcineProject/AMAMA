"""Orchestrator agent — reviews the case graph and decides routing via LLM."""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

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
        # Reproducibility provenance + running cost (summary #7).
        self.model = _MODEL
        self.system_prompt = _SYSTEM_PROMPT
        self.usage = {"llm_calls": 0, "tokens_in": 0, "tokens_out": 0}

    def _record_usage(self, response: Any) -> None:
        usage = getattr(response, "usage", None)
        self.usage["llm_calls"] += 1
        self.usage["tokens_in"] += int(getattr(usage, "input_tokens", 0) or 0)
        self.usage["tokens_out"] += int(getattr(usage, "output_tokens", 0) or 0)

    def _append_audit(self, response: Any, latency_ms: int) -> None:
        try:
            audit_root = os.environ.get("AMAMA_AUDIT_DIR", "")
            if not audit_root:
                return
            audit_path = Path(audit_root) / "backbone" / "orchestrator_calls.jsonl"
            if not audit_path.parent.exists():
                return
            usage = getattr(response, "usage", None)
            record = {
                "call_id": str(uuid4()),
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "agent_name": "backbone/orchestrator",
                "model": self.model,
                "tokens_in": int(getattr(usage, "input_tokens", 0) or 0),
                "tokens_out": int(getattr(usage, "output_tokens", 0) or 0),
                "latency_ms": latency_ms,
                "input_files": ["backbone/case_state.json"],
                "output_files": [],
                "query_id": None,
                "entity": None,
                "verdict": None,
                "error": None,
            }
            with open(audit_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            pass

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

        _t0 = time.monotonic()
        response = self._client.messages.create(
            model=_MODEL,
            max_tokens=4096,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
        _latency_ms = int((time.monotonic() - _t0) * 1000)
        self._record_usage(response)
        self._append_audit(response, _latency_ms)
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", response.content[0].text.strip())
        if not text.strip():
            return []
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return []

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
