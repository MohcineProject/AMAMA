"""Report agent — final incident narrative from case state."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import anthropic

from backbone.case_graph import CaseGraph

_SYSTEM_PROMPT = (
    Path(__file__).resolve().parents[2] / "prompts" / "report.md"
).read_text(encoding="utf-8")

_MODEL = "claude-sonnet-4-6"

_REPORTABLE = {"CONFIRMED", "INCONCLUSIVE"}


class ReportAgent:
    """Builds incident_report.md from the case graph via LLM."""

    def __init__(self) -> None:
        self._client = anthropic.Anthropic()

    def _serialize_for_report(self, graph: CaseGraph) -> str:
        """Produce a JSON payload with full finding details for the LLM."""
        entities: list[dict[str, Any]] = []
        for node in graph.nodes.values():
            verdicts = {f.get("verdict") for f in node.findings}
            if not verdicts & _REPORTABLE:
                continue

            findings_out = [
                {
                    "module": f.get("module"),
                    "verdict": f.get("verdict"),
                    "severity": f.get("severity"),
                    "justification": f.get("justification", ""),
                    "mitre": f.get("mitre", []),
                    "evidence": [
                        {
                            "source_file": e.get("source_file"),
                            "content": e.get("content"),
                        }
                        for e in f.get("evidence", [])
                    ],
                }
                for f in node.findings
                if f.get("verdict") in _REPORTABLE
            ]

            if findings_out:
                entities.append(
                    {
                        "type": node.type,
                        "value": node.value,
                        "first_seen_module": node.first_seen_module,
                        "queried_modules": sorted(node.queried_modules),
                        "findings": findings_out,
                    }
                )

        payload: dict[str, Any] = {
            "case_id": graph.case_id,
            "termination_reason": graph.termination_reason,
            "modules_scanned": list(graph.initial_scans.keys()),
            "entities": entities,
        }
        return json.dumps(payload, indent=2, default=list)

    def build(self, graph: CaseGraph, out_path: Path) -> Path:
        serialized = self._serialize_for_report(graph)
        response = self._client.messages.create(
            model=_MODEL,
            max_tokens=16000,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": serialized}],
        )
        text = re.sub(
            r"^```(?:markdown)?\s*|\s*```$",
            "",
            response.content[0].text.strip(),
        )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
        return out_path
