"""Investigation loop — batch scans, graph ingest, LLM-driven routing rounds."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml

from backbone.case_graph import CaseGraph

# Repo root is 3 levels above this file: backbone/orchestrator/loop.py → backbone/ → Backbone/ → repo root
_REPO_ROOT = Path(__file__).resolve().parents[3]
from backbone.contracts.base_model import BaseForensicModule
from backbone.orchestrator.agent import OrchestratorAgent
from backbone.registry import load_modules
from backbone.report import ReportAgent

# IOC types that are deterministically routed to ThreatIntel for enrichment even
# once CONFIRMED — so the report can carry VT threat score, geolocation, domain
# age, etc. (the orchestrator LLM never routes CONFIRMED entities).
_ENRICHABLE_IOC_TYPES = frozenset(
    {"ip", "domain", "hash_md5", "hash_sha1", "hash_sha256"}
)


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
            # Deterministic type guard (summary #3): drop a query the target module
            # can't answer (e.g. a pid routed to `ti`) instead of paying for a
            # NOT_APPLICABLE round-trip. The module advertises supported_entity_types.
            if not self.modules[mid].supports_entity_type(entity.get("type", "")):
                print(
                    f"[backbone] skip: {mid} does not support entity type "
                    f"{entity.get('type')!r} — query dropped",
                    flush=True,
                )
                continue
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

    def _confirmed_ioc_enrichment_decisions(self) -> list[dict[str, Any]]:
        """Build TI-enrichment queries for CONFIRMED ip/domain/hash entities.

        The orchestrator LLM only routes still-open (INCONCLUSIVE/NOT_FOUND) entities,
        so a CONFIRMED IOC never reaches `ti`. This deterministic pass routes every
        CONFIRMED `ip`/`domain`/`hash_*` entity to `ti` (when supported and not already
        queried) purely to enrich the report with threat-intel context — it does not
        re-adjudicate the verdict.
        """
        ti = self.modules.get("ti")
        if ti is None:
            return []
        decisions: list[dict[str, Any]] = []
        for node in self.graph.nodes.values():
            if node.type not in _ENRICHABLE_IOC_TYPES:
                continue
            if "ti" in node.queried_modules:
                continue
            if not ti.supports_entity_type(node.type):
                continue
            if "CONFIRMED" not in {f.get("verdict") for f in node.findings}:
                continue
            decisions.append(
                {
                    "action": "query",
                    "target_module": "ti",
                    "entity": {"type": node.type, "value": node.value},
                    "reason": "enrich confirmed IOC with threat-intel context",
                }
            )
        return decisions

    def _provenance(self) -> dict[str, Any]:
        """Model + prompt-hash provenance so a run can be reproduced/audited (summary #7)."""
        def _hash(text: str) -> str:
            return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()

        return {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "orchestrator": {
                "model": self.orchestrator.model,
                "prompt_sha256": _hash(self.orchestrator.system_prompt),
            },
            "report": {
                "model": self.report_agent.model,
                "prompt_sha256": _hash(self.report_agent.system_prompt),
            },
        }

    def _cost(self) -> dict[str, Any]:
        """Aggregate token/call usage across modules, orchestrator and report (summary #7)."""
        modules = self.graph.aggregate_module_cost()
        orchestrator = dict(self.orchestrator.usage)
        report = dict(self.report_agent.usage)
        keys = ("llm_calls", "tokens_in", "tokens_out")
        total = {k: modules[k] + orchestrator[k] + report[k] for k in keys}
        return {
            "modules": modules,
            "orchestrator": orchestrator,
            "report": report,
            "total": total,
        }

    def _write_case_state(self, output_dir: Path) -> None:
        """Persist case_state.json with provenance + cost folded in (summary #7)."""
        state = self.graph.to_dict()
        state["provenance"] = self._provenance()
        state["cost"] = self._cost()
        (output_dir / "case_state.json").write_text(
            json.dumps(state, indent=2, default=list),
            encoding="utf-8",
        )

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

        run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        audit_dir = _REPO_ROOT / "auditing" / self.case_id / run_id
        for sub in ("backbone", "ram", "disk", "threat_intel"):
            (audit_dir / sub).mkdir(parents=True, exist_ok=True)
        os.environ["AMAMA_AUDIT_DIR"] = str(audit_dir.resolve())
        run_started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        asyncio.run(self.run_initial_scans())

        # Deterministic enrichment: pull TI context for CONFIRMED IOCs before the
        # routing rounds so the report carries threat score / geolocation / domain
        # age, and any new related entities are still available for LLM pivots.
        enrichment = self._confirmed_ioc_enrichment_decisions()
        if enrichment:
            added = asyncio.run(self._dispatch_round(enrichment, round_num=0))
            self.graph.rounds.append(
                {
                    "round": 0,
                    "phase": "confirmed_ioc_enrichment",
                    "queries_dispatched": len(enrichment),
                    "new_entities_added": added,
                }
            )

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
            # crash after a long scan phase never discards the scan results. This
            # baseline write captures module + orchestrator cost (report runs next).
            self._write_case_state(output_dir)

        report_path = output_dir / "incident_report.md"
        self.report_agent.build(self.graph, report_path)
        # Authoritative re-write now that report usage is known (summary #7).
        self._write_case_state(output_dir)

        self._finalize_audit(audit_dir, output_dir, run_id, run_started_at)

        module_ids = list(self.modules.keys())
        entity_count = self.graph.summary_for_agent()["entity_count"]
        print(
            f"[backbone] case={self.case_id} modules={module_ids} "
            f"entities={entity_count} termination={self.graph.termination_reason} "
            f"report={report_path}"
        )

        return self.graph

    def _finalize_audit(
        self,
        audit_dir: Path,
        output_dir: Path,
        run_id: str,
        run_started_at: str,
    ) -> None:
        """Copy backbone outputs into the audit dir and write run_summary.json."""
        try:
            bb_dir = audit_dir / "backbone"

            for fname in ("case_state.json", "incident_report.md"):
                src = output_dir / fname
                if src.exists():
                    shutil.copy2(src, bb_dir / fname)

            self._write_run_summary(audit_dir, run_id, run_started_at)
        except Exception:
            pass

    def _write_run_summary(
        self,
        audit_dir: Path,
        run_id: str,
        run_started_at: str,
    ) -> None:
        """Write run_summary.json — the single entry-point for an audit run."""
        try:
            cost = self._cost()

            # Build execution_sequence from initial scans + routing rounds
            seq: list[dict[str, Any]] = []
            step = 1
            for mid, scan_result in self.graph.initial_scans.items():
                seq.append({
                    "step": step,
                    "phase": "initial_scan",
                    "module": mid,
                    "started_at": scan_result.get("scan_started_at", ""),
                    "completed_at": scan_result.get("scan_completed_at", ""),
                })
                step += 1
            for round_info in self.graph.rounds:
                entry: dict[str, Any] = {"step": step}
                entry.update(round_info)
                seq.append(entry)
                step += 1
            # Report is always the last step
            seq.append({
                "step": step,
                "phase": "report",
                "completed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            })

            summary: dict[str, Any] = {
                "schema_version": "1.0",
                "case_id": self.case_id,
                "run_id": run_id,
                "run_started_at": run_started_at,
                "run_completed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "termination_reason": self.graph.termination_reason,
                "provenance": self._provenance(),
                "cost_summary": {
                    "total": cost["total"],
                    "by_component": {
                        "backbone/orchestrator": cost["orchestrator"],
                        "backbone/report": cost["report"],
                        "modules": cost["modules"],
                    },
                },
                "execution_sequence": seq,
                "audit_files": {
                    "backbone_orchestrator": "backbone/orchestrator_calls.jsonl",
                    "backbone_report": "backbone/report_call.jsonl",
                    "threat_intel_queries": "threat_intel/queries.jsonl",
                    "ram_agent_calls": "ram/agent_calls.jsonl",
                    "disk_agent_calls": "disk/agent_calls.jsonl",
                },
                "module_artifacts": {
                    "ram": {
                        "chunks": "ram/01_chunks/",
                        "per_chunk_analysis": "ram/02_per_chunk_analysis/",
                        "aggregated_analyst": "ram/aggregated_analyst.txt",
                        "scan_result": "ram/scan_result.json",
                    },
                    "disk": {
                        "preprocess_inputs": "disk/01_preprocess/",
                        "triage_outputs": "disk/02_triage/",
                        "pivot_evidence": "disk/03_pivot/pivot.txt",
                        "analyst_output": "disk/04_analyst/analyst.txt",
                        "mft_audit": "disk/mft_audit.jsonl",
                        "scan_result": "disk/scan_result.json",
                    },
                },
                "backbone_outputs": {
                    "case_state": "backbone/case_state.json",
                    "incident_report": "backbone/incident_report.md",
                },
            }

            (audit_dir / "run_summary.json").write_text(
                json.dumps(summary, indent=2, default=list),
                encoding="utf-8",
            )
        except Exception:
            pass
