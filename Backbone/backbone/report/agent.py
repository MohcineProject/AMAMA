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
        # Reproducibility provenance + running cost (summary #7).
        self.model = _MODEL
        self.system_prompt = _SYSTEM_PROMPT
        self.usage = {"llm_calls": 0, "tokens_in": 0, "tokens_out": 0}

    def _serialize_for_report(self, graph: CaseGraph) -> str:
        """Produce a JSON payload with full finding details for the LLM."""
        entities: list[dict[str, Any]] = []
        for node in graph.nodes.values():
            verdicts = {f.get("verdict") for f in node.findings}
            if not verdicts & _REPORTABLE:
                continue

            # Include reportable verdicts plus any ThreatIntel finding (even a
            # NOT_FOUND one) so the VT enrichment context — reputation/score,
            # geolocation, registrar/creation date — reaches the report for an
            # already-reportable IOC. Entities with only a TI NOT_FOUND finding are
            # still excluded above, so clean standalone IOCs don't add noise.
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
                if f.get("verdict") in _REPORTABLE or f.get("module") == "ti"
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

        # Factual scaffolding computed in code (summary #3): the LLM must use these
        # exact counts rather than recounting from the entity list, which removes a
        # whole class of numeric hallucination (e.g. inventing a module count).
        modules_scanned = list(graph.initial_scans.keys())
        severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        confirmed_entities = 0
        inconclusive_entities = 0
        for ent in entities:
            verdicts = {f["verdict"] for f in ent["findings"]}
            if "CONFIRMED" in verdicts:
                confirmed_entities += 1
            elif "INCONCLUSIVE" in verdicts:
                inconclusive_entities += 1
            for f in ent["findings"]:
                if f["verdict"] == "CONFIRMED" and f["severity"] in severity_breakdown:
                    severity_breakdown[f["severity"]] += 1

        payload: dict[str, Any] = {
            "case_id": graph.case_id,
            "termination_reason": graph.termination_reason,
            "modules_scanned": modules_scanned,
            "summary": {
                "modules_scanned_count": len(modules_scanned),
                "total_reportable_entities": len(entities),
                "confirmed_entities": confirmed_entities,
                "inconclusive_entities": inconclusive_entities,
                "confirmed_severity_breakdown": severity_breakdown,
            },
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
        usage = getattr(response, "usage", None)
        self.usage["llm_calls"] += 1
        self.usage["tokens_in"] += int(getattr(usage, "input_tokens", 0) or 0)
        self.usage["tokens_out"] += int(getattr(usage, "output_tokens", 0) or 0)
        text = re.sub(
            r"^```(?:markdown)?\s*|\s*```$",
            "",
            response.content[0].text.strip(),
        )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
        return out_path
