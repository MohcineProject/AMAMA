"""Dev/test stub module — demonstrates BaseForensicModule usage."""

from __future__ import annotations

from datetime import datetime, timezone

from backbone.contracts.base_model import BaseForensicModule
from backbone.contracts.types import EntityFindings, EntityQuery, ModuleScanResult


class StubModule(BaseForensicModule):
    module_id = "stub"
    supported_entity_types = ["file_path", "hash_sha256"]

    async def scan(self, case_id: str) -> ModuleScanResult:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        result: ModuleScanResult = {
            "contract_version": "1.0",
            "case_id": case_id,
            "module": self.module_id,
            "scan_started_at": now,
            "scan_completed_at": now,
            "summary": "Stub scan — no findings",
            "counts": {"confirmed": 0, "inconclusive": 0, "rejected": 0},
            "findings": [],
        }
        return self.validate_scan_result(result)

    async def query(self, query: EntityQuery) -> EntityFindings:
        if not self.supports_entity_type(query["entity"]["type"]):
            findings: EntityFindings = {
                "contract_version": "1.0",
                "query_id": query["query_id"],
                "responding_module": self.module_id,
                "entity": query["entity"],
                "verdict": "NOT_APPLICABLE",
                "severity": None,
                "mitre": [],
                "justification": f"Stub module does not handle {query['entity']['type']!r}",
                "evidence": [],
                "related_entities": [],
                "cost": {"llm_calls": 0, "tokens_in": 0, "tokens_out": 0},
            }
        else:
            findings = {
                "contract_version": "1.0",
                "query_id": query["query_id"],
                "responding_module": self.module_id,
                "entity": query["entity"],
                "verdict": "NOT_FOUND",
                "severity": None,
                "mitre": [],
                "justification": "Stub module — no matching evidence",
                "evidence": [],
                "related_entities": [],
                "cost": {"llm_calls": 0, "tokens_in": 0, "tokens_out": 0},
            }
        return self.validate_findings(findings)
