"""Typed helpers and JSON-schema validation for cross-agent contracts."""

from backbone.contracts.types import Entity, EntityFindings, EntityQuery, ModuleScanResult
from backbone.contracts.validate import (
    load_schema,
    validate_findings,
    validate_query,
    validate_scan_result,
)

__all__ = [
    "Entity",
    "EntityQuery",
    "EntityFindings",
    "ModuleScanResult",
    "load_schema",
    "validate_query",
    "validate_findings",
    "validate_scan_result",
]
