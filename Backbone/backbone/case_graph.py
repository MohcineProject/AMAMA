"""Case graph — orchestrator's structured memory for entities and findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from backbone.contracts.types import EntityFindings, ModuleScanResult


def entity_key(entity_type: str, value: str) -> tuple[str, str]:
    return (entity_type, value)


@dataclass
class EntityNode:
    type: str
    value: str
    first_seen_module: str | None = None
    first_seen_finding_id: str | None = None
    queried_modules: set[str] = field(default_factory=set)
    findings: list[dict[str, Any]] = field(default_factory=list)
    related: list[dict[str, str]] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str]:
        return entity_key(self.type, self.value)

    @property
    def verdicts_received(self) -> list[dict[str, Any]]:
        return [
            {"module": f.get("module"), "verdict": f.get("verdict"), "severity": f.get("severity")}
            for f in self.findings
            if f.get("verdict")
        ]


@dataclass
class CaseGraph:
    """In-memory graph keyed by (entity_type, entity_value)."""

    case_id: str
    nodes: dict[tuple[str, str], EntityNode] = field(default_factory=dict)
    initial_scans: dict[str, ModuleScanResult] = field(default_factory=dict)
    rounds: list[dict[str, Any]] = field(default_factory=list)
    termination_reason: str | None = None

    def get_or_create_node(
        self,
        entity_type: str,
        value: str,
        *,
        source_module: str | None = None,
        finding_id: str | None = None,
    ) -> EntityNode:
        key = entity_key(entity_type, value)
        if key not in self.nodes:
            self.nodes[key] = EntityNode(
                type=entity_type,
                value=value,
                first_seen_module=source_module,
                first_seen_finding_id=finding_id,
            )
        return self.nodes[key]

    def ingest_scan_result(self, result: ModuleScanResult) -> int:
        """Seed graph from a module's initial broad scan. Returns new entity count."""
        module = result["module"]
        self.initial_scans[module] = result
        added = 0

        for finding in result.get("findings", []):
            primary = finding["primary_entity"]
            node = self.get_or_create_node(
                primary["type"],
                primary["value"],
                source_module=module,
                finding_id=finding.get("finding_id"),
            )
            node.queried_modules.add(module)
            node.findings.append({"source": "scan", "module": module, **finding})
            added += 1 if node.first_seen_finding_id == finding.get("finding_id") else 0

            for rel in finding.get("related_entities", []):
                self.get_or_create_node(
                    rel["type"],
                    rel["value"],
                    source_module=module,
                    finding_id=finding.get("finding_id"),
                )
                node.related.append(rel)

        return len(self.nodes)

    def ingest_findings(self, findings: EntityFindings) -> None:
        """Merge a query response (or TI enrichment) into the graph."""
        entity = findings["entity"]
        module = findings["responding_module"]
        node = self.get_or_create_node(entity["type"], entity["value"], source_module=module)
        node.queried_modules.add(module)
        node.findings.append({"source": "query", "module": module, **findings})

        for rel in findings.get("related_entities", []):
            self.get_or_create_node(rel["type"], rel["value"], source_module=module)
            node.related.append(rel)

    def summary_for_agent(self, limit: int = 30) -> dict[str, Any]:
        """Compact view for the orchestrator LLM context."""
        hot = []
        for node in self.nodes.values():
            verdicts = [f.get("verdict") for f in node.findings]
            hot.append(
                {
                    "entity": {"type": node.type, "value": node.value},
                    "verdicts": verdicts,
                    "queried_modules": sorted(node.queried_modules),
                    "finding_count": len(node.findings),
                }
            )
        hot.sort(key=lambda x: x["finding_count"], reverse=True)
        return {
            "case_id": self.case_id,
            "entity_count": len(self.nodes),
            "modules_scanned": list(self.initial_scans.keys()),
            "hot_entities": hot[:limit],
        }

    def aggregate_module_cost(self) -> dict[str, int]:
        """Sum the ``cost`` blocks present on module query findings (summary #7).

        Each EntityFindings carries a ``cost`` dict (llm_calls / tokens_in / tokens_out);
        Disk populates real token counts via get_last_usage(), RAM currently emits zeros.
        Scan-phase findings have no cost block and contribute nothing.
        """
        total = {"llm_calls": 0, "tokens_in": 0, "tokens_out": 0}
        for node in self.nodes.values():
            for f in node.findings:
                cost = f.get("cost")
                if isinstance(cost, dict):
                    for k in total:
                        total[k] += int(cost.get(k, 0) or 0)
        return total

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "entity_count": len(self.nodes),
            "modules_scanned": list(self.initial_scans.keys()),
            "termination_reason": self.termination_reason,
            "rounds": self.rounds,
            "nodes": {
                f"{t}:{v}": {
                    "type": n.type,
                    "value": n.value,
                    "first_seen_module": n.first_seen_module,
                    "queried_modules": sorted(n.queried_modules),
                    "finding_count": len(n.findings),
                    "verdicts_received": n.verdicts_received,
                }
                for (t, v), n in self.nodes.items()
            },
        }
