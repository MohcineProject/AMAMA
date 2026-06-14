"""Typed helpers and JSON-schema validation for cross-agent contracts."""

from backbone.contracts.base_model import BaseForensicModule
from backbone.contracts.normalize import (
    ENTITY_TYPES,
    normalize_entity,
    normalize_entity_type,
)
from backbone.contracts.types import Entity, EntityFindings, EntityQuery, ModuleScanResult
from backbone.contracts.validate import (
    load_schema,
    validate_findings,
    validate_query,
    validate_scan_result,
)

__all__ = [
    "BaseForensicModule",
    "Entity",
    "EntityQuery",
    "EntityFindings",
    "ModuleScanResult",
    "ENTITY_TYPES",
    "normalize_entity",
    "normalize_entity_type",
    "load_schema",
    "validate_query",
    "validate_findings",
    "validate_scan_result",
]
