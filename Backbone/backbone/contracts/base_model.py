"""Base class every forensic module under ../models/ must inherit."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from backbone.contracts.normalize import normalize_entity
from backbone.contracts.types import EntityFindings, EntityQuery, ModuleScanResult
from backbone.contracts.validate import (
    load_schema,
    validate_findings,
    validate_scan_result,
)


def _normalize_findings_entity_types(findings: EntityFindings) -> None:
    """Correct shape/type mismatches on the primary + related entities (summary #11).

    Defense-in-depth choke point for the query path: even if a module emits an
    in-enum-but-wrong type, it is normalised (and logged) before it reaches the graph.
    """
    primary = findings.get("entity")
    if isinstance(primary, dict):
        normalize_entity(primary)
    related = findings.get("related_entities")
    if isinstance(related, list):
        for rel in related:
            normalize_entity(rel)


def _drop_invalid_related_entities(findings: EntityFindings) -> None:
    """Drop related_entities whose ``type`` is outside the contract enum.

    ``related_entities`` are advisory pivot hints. LLM agents occasionally emit
    near-miss types (e.g. ``username`` instead of ``user_sid``), which are not
    routable by the orchestrator anyway. Rather than fail the whole findings
    payload — and crash the routing round — we drop the offending hints with a
    warning and keep the validated core verdict/evidence.
    """
    related = findings.get("related_entities")
    if not isinstance(related, list):
        return
    try:
        allowed = set(
            load_schema("entity_findings.schema.json")["properties"][
                "related_entities"
            ]["items"]["properties"]["type"]["enum"]
        )
    except (KeyError, TypeError):
        return
    kept = [e for e in related if isinstance(e, dict) and e.get("type") in allowed]
    dropped = len(related) - len(kept)
    if dropped:
        bad = sorted(
            {
                str(e.get("type"))
                for e in related
                if not (isinstance(e, dict) and e.get("type") in allowed)
            }
        )
        print(
            f"[contract] WARN: dropped {dropped} related_entit"
            f"{'y' if dropped == 1 else 'ies'} with unsupported type(s) {bad}",
            flush=True,
        )
        findings["related_entities"] = kept


class BaseForensicModule(ABC):
    """
    Obligatory base for all pluggable models (disk, ram, network, …).

    Subclasses must set module_id and supported_entity_types, then implement
    scan() and query(). Return payloads must validate against the JSON schemas.
    """

    module_id: ClassVar[str]
    supported_entity_types: ClassVar[list[str]]

    @abstractmethod
    async def scan(self, case_id: str) -> ModuleScanResult:
        """Run the module's full triage + pivot pipeline; return ModuleScanResult."""

    @abstractmethod
    async def query(self, query: EntityQuery) -> EntityFindings:
        """Answer a single orchestrator pivot; return EntityFindings."""

    def supports_entity_type(self, entity_type: str) -> bool:
        return entity_type in self.supported_entity_types

    def validate_scan_result(self, result: ModuleScanResult) -> ModuleScanResult:
        validate_scan_result(result)
        return result

    def validate_findings(self, findings: EntityFindings) -> EntityFindings:
        _normalize_findings_entity_types(findings)
        _drop_invalid_related_entities(findings)
        validate_findings(findings)
        return findings
