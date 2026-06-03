"""
Disk forensic module — Backbone BaseForensicModule implementation.

Pluggable entry point for the orchestrator. Wraps:
  - ``scripts.scan``  — initial broad scan → ModuleScanResult
  - ``scripts.query`` — pivot-back EntityQuery → EntityFindings

Loaded via ``backbone.registry.load_modules()`` (set ``path`` in orchestrator YAML).
"""

from __future__ import annotations

from pathlib import Path

from backbone.contracts.base_model import BaseForensicModule
from backbone.contracts.types import EntityFindings, EntityQuery, ModuleScanResult
from scripts.query import SUPPORTED_TYPES, answer_entity_query_async
from scripts.scan import build_scan_result_async

_PKG_DIR = Path(__file__).resolve().parent


class DiskModule(BaseForensicModule):
    """
    Pluggable disk module for the Backbone orchestrator.

    Wraps the existing disk pipeline (preprocess → triage → pivot → analyst)
    and pivot-back query flow.
    """

    module_id = "disk"
    supported_entity_types = sorted(SUPPORTED_TYPES)

    def __init__(
        self,
        *,
        base_dir: str | Path | None = None,
        artifact_dir: str | Path | None = None,
        use_llm: bool = True,
    ) -> None:
        # Module package root (config.json, prompts/, output/ live here)
        self.base_dir = Path(base_dir or _PKG_DIR).resolve()
        # Override config.json artifact_dir when set by orchestrator YAML
        self.artifact_dir = (
            str(Path(artifact_dir).resolve()) if artifact_dir else None
        )
        self.use_llm = use_llm

    async def scan(self, case_id: str) -> ModuleScanResult:
        """Run pipeline + parse output; return validated ModuleScanResult."""
        result = await build_scan_result_async(
            case_id,
            self.base_dir,
            no_llm=not self.use_llm,
            artifact_dir=self.artifact_dir,
        )
        return self.validate_scan_result(result)

    async def query(self, query: EntityQuery) -> EntityFindings:
        """Answer a single orchestrator pivot; return validated EntityFindings."""
        # Fast path: query targeted at a different module
        if query.get("target_module") and query["target_module"] != self.module_id:
            findings: EntityFindings = {
                "contract_version": "1.0",
                "query_id": query["query_id"],
                "responding_module": self.module_id,
                "entity": query["entity"],
                "verdict": "NOT_APPLICABLE",
                "severity": None,
                "mitre": [],
                "justification": (
                    f"Query target_module is {query['target_module']!r}, not {self.module_id!r}"
                ),
                "evidence": [],
                "related_entities": [],
                "cost": {"llm_calls": 0, "tokens_in": 0, "tokens_out": 0},
            }
            return self.validate_findings(findings)

        # Fast path: entity type outside disk's supported set
        if not self.supports_entity_type(query["entity"]["type"]):
            findings = {
                "contract_version": "1.0",
                "query_id": query["query_id"],
                "responding_module": self.module_id,
                "entity": query["entity"],
                "verdict": "NOT_APPLICABLE",
                "severity": None,
                "mitre": [],
                "justification": (
                    f"Disk module does not handle entity type {query['entity']['type']!r}"
                ),
                "evidence": [],
                "related_entities": [],
                "cost": {"llm_calls": 0, "tokens_in": 0, "tokens_out": 0},
            }
            return self.validate_findings(findings)

        # Delegate to 4-stage query flow (grep → whitelist → LLM)
        raw = await answer_entity_query_async(
            dict(query),
            self.base_dir,
            artifact_dir=self.artifact_dir,
            use_llm=self.use_llm,
        )
        return self.validate_findings(raw)  # type: ignore[arg-type]
