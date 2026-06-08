"""Investigation loop — batch scans, graph ingest, LLM-driven routing rounds."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml

from backbone.case_graph import CaseGraph
from backbone.contracts.base_model import BaseForensicModule
from backbone.orchestrator.agent import OrchestratorAgent
from backbone.registry import load_modules
from backbone.report import ReportAgent


@dataclass
class InvestigationLoop:
    case_id: str
    config: dict[str, Any]
    graph: CaseGraph
    orchestrator: OrchestratorAgent
    modules: dict[str, BaseForensicModule] = field(default_factory=dict)
    report_agent: ReportAgent = field(default_factory=ReportAgent)

    @classmethod
    def from_config(cls, config_path: str, *, case_id: str) -> InvestigationLoop:
        path = Path(config_path)
        if path.exists():
            with path.open(encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
        else:
            config = {}

        graph = CaseGraph(case_id=case_id)
        orchestrator = OrchestratorAgent()
        modules = load_modules(config, config_dir=path.parent if path.exists() else Path.cwd())

        return cls(
            case_id=case_id,
            config=config,
            graph=graph,
            orchestrator=orchestrator,
            modules=modules,
            report_agent=ReportAgent(),
        )

    async def run_initial_scans(self) -> None:
        """Run scan() on every registered module in parallel; ingest into graph."""
        if not self.modules:
            return

        module_ids = list(self.modules.keys())
        results = await asyncio.gather(
            *[module.scan(self.case_id) for module in self.modules.values()],
            return_exceptions=True,
        )
        for mid, result in zip(module_ids, results):
            if isinstance(result, BaseException):
                print(
                    f"[backbone] WARN: module {mid!r} scan failed, skipping: "
                    f"{type(result).__name__}: {result}",
                    flush=True,
                )
                continue
            self.graph.ingest_scan_result(result)

    async def _dispatch_round(self, decisions: list[dict[str, Any]], round_num: int) -> int:
        """Dispatch query-action decisions to their target modules. Returns new entity count."""
        entities_before = len(self.graph.nodes)

        tasks = []
        for decision in decisions:
            if decision.get("action") != "query":
                continue
            mid = decision.get("target_module")
            if not mid or mid not in self.modules:
                continue
            entity = decision.get("entity", {})
            if (entity.get("type"), entity.get("value")) not in self.graph.nodes:
                continue  # LLM invented an entity not in the graph — skip
            query = {
                "contract_version": "1.0",
                "query_id": str(uuid4()),
                "round": round_num,
                "case_id": self.case_id,
                "target_module": mid,
                "entity": decision["entity"],
                "context": {
                    "source_module": "orchestrator",
                    "source_finding_id": None,
                    "reason": decision.get("reason", ""),
                },
            }
            tasks.append(self.modules[mid].query(query))

        if tasks:
            findings_list = await asyncio.gather(*tasks, return_exceptions=True)
            for findings in findings_list:
                if isinstance(findings, BaseException):
                    print(
                        f"[backbone] WARN: a module query failed, skipping: "
                        f"{type(findings).__name__}: {findings}",
                        flush=True,
                    )
                    continue
                self.graph.ingest_findings(findings)

        return len(self.graph.nodes) - entities_before

    def run(self) -> CaseGraph:
        """
        Full investigation pipeline:
          1. Initial parallel scans from all modules
          2. LLM-driven routing rounds until convergence or max_rounds
          3. Write case_state.json to output_dir
        """
        case_cfg = self.config.get("case", {})
        output_dir = Path(case_cfg.get("output_dir", "./output"))
        max_rounds = int(case_cfg.get("max_rounds", 5))

        output_dir.mkdir(parents=True, exist_ok=True)

        asyncio.run(self.run_initial_scans())

        try:
            for round_num in range(1, max_rounds + 1):
                decisions = self.orchestrator.review(self.graph, self.modules)
                queries = [d for d in decisions if d.get("action") == "query"]

                if not queries:
                    self.graph.termination_reason = "convergence"
                    break

                new_entities = asyncio.run(self._dispatch_round(decisions, round_num))
                self.graph.rounds.append(
                    {
                        "round": round_num,
                        "queries_dispatched": len(queries),
                        "new_entities_added": new_entities,
                    }
                )
            else:
                self.graph.termination_reason = "max_rounds_reached"
        finally:
            # Always persist the graph — even if a routing round raised — so a
            # crash after a long scan phase never discards the scan results.
            state_path = output_dir / "case_state.json"
            state_path.write_text(
                json.dumps(self.graph.to_dict(), indent=2, default=list),
                encoding="utf-8",
            )

        report_path = output_dir / "incident_report.md"
        self.report_agent.build(self.graph, report_path)

        module_ids = list(self.modules.keys())
        entity_count = self.graph.summary_for_agent()["entity_count"]
        print(
            f"[backbone] case={self.case_id} modules={module_ids} "
            f"entities={entity_count} termination={self.graph.termination_reason} "
            f"report={report_path}"
        )

        return self.graph
