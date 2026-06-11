"""
RAM forensic module — Backbone BaseForensicModule implementation.

Pluggable entry point for the orchestrator. Wraps:
  - ``scripts.scan_result_emitter`` — full pipeline scan → ModuleScanResult
  - ``scripts.entity_query``        — pivot-back EntityQuery → EntityFindings

Loaded via ``backbone.registry.load_modules()`` (set ``path`` in orchestrator YAML).
"""

from __future__ import annotations

import sys
from pathlib import Path

from backbone.contracts.base_model import BaseForensicModule
from backbone.contracts.types import EntityFindings, EntityQuery, ModuleScanResult

_PKG_DIR = Path(__file__).resolve().parent

# Put scripts/ on sys.path and import the script modules by their unique
# top-level names (entity_query, scan_result_emitter). We deliberately avoid the
# ``scripts.*`` package prefix because the disk module also ships a ``scripts``
# package — importing via the shared name would clash in a single process.
_SCRIPTS_DIR = _PKG_DIR / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from entity_query import CONDITIONAL_TYPES, SUPPORTED_TYPES, answer_entity_query_async  # noqa: E402
from scan_result_emitter import build_scan_result_async  # noqa: E402


class RamModule(BaseForensicModule):
    """
    Pluggable RAM module for the Backbone orchestrator.

    Wraps the existing RAM pipeline (Volatility extract → collect → triage →
    pivot grep → analyst) and pivot-back query flow.
    """

    module_id = "ram"
    # mutex is conditionally supported (only when handles.txt is present), but
    # advertise it so the orchestrator may still route mutex pivots here.
    supported_entity_types = sorted(SUPPORTED_TYPES | CONDITIONAL_TYPES)

    def __init__(
        self,
        *,
        base_dir: str | Path | None = None,
        artifact_dir: str | Path | None = None,
        use_llm: bool = True,
        ram_image: str | Path | None = None,
        vol_path: str | Path | None = None,
        scan_mode: str = "fast",
        reuse_analysis: bool = False,
    ) -> None:
        # Module package root (config.json, prompts/, output/ live here)
        self.base_dir = Path(base_dir or _PKG_DIR).resolve()
        # Volatility plugin output directory. When ram_image is unset, scan()
        # runs collector + analyse on these pre-collected artifacts (like disk
        # reusing Disk_Artifacts when image_dir is omitted).
        self.artifact_dir = (
            str(Path(artifact_dir).resolve()) if artifact_dir else None
        )
        self.use_llm = use_llm
        # Memory image for a fresh Volatility extraction. When unset, scan()
        # uses pre-collected artifacts in artifact_dir (or RAM_Artifacts/).
        self.ram_image = str(Path(ram_image).resolve()) if ram_image else None
        self.vol_path = str(Path(vol_path).resolve()) if vol_path else None
        self.scan_mode = scan_mode
        # Skip analyse when output/aggregated_analyst.txt already exists.
        self.reuse_analysis = reuse_analysis

    async def scan(self, case_id: str) -> ModuleScanResult:
        """Run the full RAM pipeline + emit; return validated ModuleScanResult."""
        result = await build_scan_result_async(
            case_id,
            self.base_dir,
            image=self.ram_image,
            vol_path=self.vol_path,
            mode=self.scan_mode,
            no_llm=not self.use_llm,
            artifact_dir=self.artifact_dir,
            reuse_analysis=self.reuse_analysis,
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

        # Fast path: entity type outside RAM's supported set
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
                    f"RAM module does not handle entity type {query['entity']['type']!r}"
                ),
                "evidence": [],
                "related_entities": [],
                "cost": {"llm_calls": 0, "tokens_in": 0, "tokens_out": 0},
            }
            return self.validate_findings(findings)

        # Delegate to the 4-stage query flow (dispatch → grep → whitelist → LLM)
        raw = await answer_entity_query_async(
            dict(query),
            self.base_dir,
            artifact_dir=self.artifact_dir,
            use_llm=self.use_llm,
        )
        return self.validate_findings(raw)  # type: ignore[arg-type]
