"""Lightweight type aliases for contract payloads."""

from __future__ import annotations

from typing import Any, TypedDict


class Entity(TypedDict):
    type: str
    value: str


class RelatedEntity(TypedDict):
    type: str
    value: str
    relationship: str


class EvidenceLine(TypedDict, total=False):
    source_file: str
    line: int
    content: str
    verbatim: bool
    timestamp: str | None


class Cost(TypedDict):
    llm_calls: int
    tokens_in: int
    tokens_out: int


class EntityQuery(TypedDict, total=False):
    contract_version: str
    query_id: str
    round: int
    case_id: str
    target_module: str
    entity: Entity
    context: dict[str, Any]
    scope: dict[str, Any]


class EntityFindings(TypedDict, total=False):
    contract_version: str
    query_id: str
    responding_module: str
    entity: Entity
    verdict: str
    severity: str | None
    mitre: list[str]
    justification: str
    evidence: list[EvidenceLine]
    related_entities: list[RelatedEntity]
    cost: Cost


class ScanFinding(TypedDict, total=False):
    finding_id: str
    verdict: str
    severity: str | None
    mitre: list[str]
    primary_entity: Entity
    related_entities: list[RelatedEntity]
    justification: str
    evidence: list[EvidenceLine]


class ModuleScanResult(TypedDict, total=False):
    contract_version: str
    case_id: str
    module: str
    scan_started_at: str
    scan_completed_at: str
    summary: str
    counts: dict[str, int]
    findings: list[ScanFinding]
    artifacts: dict[str, Any]
    host_profile: dict[str, Any]
