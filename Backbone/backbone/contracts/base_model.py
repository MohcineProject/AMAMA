"""Base class every forensic module under ../models/ must inherit."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from backbone.contracts.types import EntityFindings, EntityQuery, ModuleScanResult
from backbone.contracts.validate import validate_findings, validate_scan_result


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
        validate_findings(findings)
        return findings
