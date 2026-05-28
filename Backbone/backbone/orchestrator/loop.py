"""Investigation loop — batch scans, graph ingest, orchestrator rounds."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from backbone.case_graph import CaseGraph
from backbone.orchestrator.agent import OrchestratorAgent


@dataclass
class InvestigationLoop:
    case_id: str
    config: dict[str, Any]
    graph: CaseGraph
    orchestrator: OrchestratorAgent

    @classmethod
    def from_config(cls, config_path: str, *, case_id: str) -> InvestigationLoop:
        path = Path(config_path)
        if path.exists():
            with path.open(encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
        else:
            config = {}

        case_cfg = config.get("case", {})
        graph = CaseGraph(case_id=case_id)
        orchestrator = OrchestratorAgent(use_llm=config.get("orchestrator", {}).get("use_llm", False))

        return cls(
            case_id=case_id,
            config=config,
            graph=graph,
            orchestrator=orchestrator,
        )

    def run(self) -> CaseGraph:
        """
        Run the batch investigation pipeline.

        Steps (implemented incrementally):
          1. Parallel module scans → ingest ModuleScanResult
          2. Orchestrator review + TI enrichment
          3. Follow-up EntityQuery rounds until convergence
          4. Report generation
        """
        output_dir = Path(self.config.get("case", {}).get("output_dir", "./output"))
        output_dir.mkdir(parents=True, exist_ok=True)

        review = self.orchestrator.review(self.graph)
        print(f"[backbone] case={self.case_id} entities={self.graph.summary_for_agent()['entity_count']}")
        print(f"[backbone] orchestrator notes: {review['notes']}")

        return self.graph
