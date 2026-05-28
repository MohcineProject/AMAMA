"""Module dispatch — invoke pluggable models via scan/query entrypoints."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from backbone.contracts.types import EntityFindings, EntityQuery, ModuleScanResult


class ModuleAdapter(ABC):
    """Interface every model under ../models/ must expose."""

    module_id: str

    @abstractmethod
    async def scan(self, case_id: str, out_dir: Path) -> ModuleScanResult: ...

    @abstractmethod
    async def query(self, query: EntityQuery, out_path: Path) -> EntityFindings: ...

    def supports_entity_type(self, entity_type: str, manifest: dict[str, Any]) -> bool:
        caps = manifest.get("capabilities", {}).get("entity_types", [])
        return entity_type in caps


class SubprocessModuleAdapter(ModuleAdapter):
    """Runs module CLI entrypoints as subprocesses. Implementation in a later commit."""

    def __init__(self, module_id: str, manifest: dict[str, Any]) -> None:
        self.module_id = module_id
        self.manifest = manifest

    async def scan(self, case_id: str, out_dir: Path) -> ModuleScanResult:
        raise NotImplementedError("Module scan dispatch not yet implemented")

    async def query(self, query: EntityQuery, out_path: Path) -> EntityFindings:
        raise NotImplementedError("Module query dispatch not yet implemented")
