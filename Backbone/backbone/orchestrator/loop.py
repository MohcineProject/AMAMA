"""Investigation loop — batch scans, graph ingest, orchestrator rounds."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from backbone.case_graph import CaseGraph
from backbone.contracts.base_model import BaseForensicModule
from backbone.orchestrator.agent import OrchestratorAgent
from backbone.registry import load_modules


@dataclass
class InvestigationLoop:
    case_id: str
    config: dict[str, Any]
    graph: CaseGraph
    orchestrator: OrchestratorAgent
    modules: dict[str, BaseForensicModule] = field(default_factory=dict)

    @classmethod
    def from_config(cls, config_path: str, *, case_id: str) -> InvestigationLoop:
        path = Path(config_path)
        if path.exists():
            with path.open(encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
        else:
            config = {}

        graph = CaseGraph(case_id=case_id)
        orchestrator = OrchestratorAgent(
            use_llm=config.get("orchestrator", {}).get("use_llm", False)
        )
        modules = load_modules(config)

        return cls(
            case_id=case_id,
            config=config,
            graph=graph,
            orchestrator=orchestrator,
            modules=modules,
        )

    async def run_initial_scans(self) -> None:
        """Run scan() on every registered module in parallel; ingest into graph."""
        if not self.modules:
            return

        results = await asyncio.gather(
            *[module.scan(self.case_id) for module in self.modules.values()]
        )
        for result in results:
            self.graph.ingest_scan_result(result)

    def run(self) -> CaseGraph:
        """
        Run the batch investigation pipeline.

        Calls run_initial_scans() first, then (implemented incrementally):
          1. Orchestrator review + TI enrichment
          2. Follow-up EntityQuery rounds until convergence
          3. Report generation
        """
        output_dir = Path(self.config.get("case", {}).get("output_dir", "./output"))
        output_dir.mkdir(parents=True, exist_ok=True)

        asyncio.run(self.run_initial_scans())

        review = self.orchestrator.review(self.graph)
        entity_count = self.graph.summary_for_agent()["entity_count"]
        module_ids = list(self.modules.keys())
        print(f"[backbone] case={self.case_id} modules={module_ids} entities={entity_count}")
        print(f"[backbone] orchestrator notes: {review['notes']}")

        return self.graph
