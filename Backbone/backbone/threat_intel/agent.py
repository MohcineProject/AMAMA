"""Threat Intel agent — external IOC enrichment via VirusTotal."""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from uuid import uuid4

from backbone.contracts.base_model import BaseForensicModule
from backbone.contracts.types import Entity, EntityFindings, EntityQuery, ModuleScanResult
from backbone.threat_intel.rate_limiter import RateLimiter
from backbone.threat_intel.vt_client import VTClient


class ThreatIntelAgent(BaseForensicModule):
    """
    Enriches IOC entities via VirusTotal.

    Registered as module_id="ti". The orchestrator routes ip/domain/url/hash
    entities to this module when external reputation data is useful.
    Per-case caching ensures each IOC is queried at most once per case.
    """

    module_id = "ti"
    supported_entity_types = ["ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256"]

    def __init__(self, *, vt_api_key: str | None = None) -> None:
        api_key = vt_api_key or os.environ.get("VT_API_KEY")
        self._rl = RateLimiter(calls_per_minute=4)
        self._vt: VTClient | None = VTClient(api_key, self._rl) if api_key else None
        # (case_id, entity_type, entity_value) → EntityFindings
        self._cache: dict[tuple[str, str, str], EntityFindings] = {}

    # ------------------------------------------------------------------
    # BaseForensicModule interface
    # ------------------------------------------------------------------

    async def scan(self, case_id: str) -> ModuleScanResult:
        """TI has no initial artifact scan; returns an empty result immediately."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        result: ModuleScanResult = {
            "contract_version": "1.0",
            "case_id": case_id,
            "module": self.module_id,
            "scan_started_at": now,
            "scan_completed_at": now,
            "summary": "TI module has no initial scan; enrichment happens on query.",
            "counts": {"confirmed": 0, "inconclusive": 0, "rejected": 0},
            "findings": [],
        }
        return self.validate_scan_result(result)

    async def query(self, query: EntityQuery) -> EntityFindings:
        """Enrich a single entity via VirusTotal. Checks per-case cache first."""
        entity = query["entity"]
        entity_type = entity["type"]
        entity_value = entity["value"]
        query_id = query["query_id"]
        case_id = query.get("case_id", "")

        if not self.supports_entity_type(entity_type):
            findings: EntityFindings = {
                "contract_version": "1.0",
                "query_id": query_id,
                "responding_module": self.module_id,
                "entity": entity,
                "verdict": "NOT_APPLICABLE",
                "severity": None,
                "mitre": [],
                "justification": f"TI module does not enrich entity type {entity_type!r}",
                "evidence": [],
                "related_entities": [],
                "cost": {"llm_calls": 0, "tokens_in": 0, "tokens_out": 0},
            }
            return self.validate_findings(findings)

        cache_key = (case_id, entity_type, entity_value)
        if cache_key in self._cache:
            cached = {**self._cache[cache_key], "query_id": query_id}
            return self.validate_findings(cached)  # type: ignore[arg-type]

        findings = await self._do_lookup(entity, query_id)
        self._cache[cache_key] = findings
        return findings

    # ------------------------------------------------------------------
    # Batch enrichment (called by orchestrator loop at round start)
    # ------------------------------------------------------------------

    async def enrich_batch(self, case_id: str, entities: list[Entity]) -> list[EntityFindings]:
        """Enrich a batch of entities concurrently (rate limiter enforces VT limits)."""
        tasks = [
            self.query(
                EntityQuery(
                    contract_version="1.0",
                    query_id=str(uuid4()),
                    case_id=case_id,
                    entity=entity,
                    context={"source_module": "orchestrator", "source_finding_id": None, "reason": "batch enrichment"},
                )
            )
            for entity in entities
        ]
        return list(await asyncio.gather(*tasks))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _do_lookup(self, entity: Entity, query_id: str) -> EntityFindings:
        entity_type = entity["type"]
        entity_value = entity["value"]

        if self._vt is None:
            return self.validate_findings(
                self._not_found(entity, query_id, "VT_API_KEY not configured")
            )

        try:
            attrs = await self._vt.lookup(entity_type, entity_value)
        except RuntimeError as exc:
            return self.validate_findings(
                self._not_found(entity, query_id, str(exc))
            )
        except Exception as exc:  # network errors, timeouts
            return self.validate_findings(
                self._not_found(entity, query_id, f"VirusTotal lookup failed: {exc}")
            )

        raw_attrs: dict = attrs if attrs is not None else {}

        # Fetch related entities only when we'll likely confirm the IOC
        stats = raw_attrs.get("last_analysis_stats") or {}
        malicious = stats.get("malicious", 0)
        related = []
        if malicious >= 3:
            try:
                related = await self._vt.fetch_related(entity_type, entity_value)
            except Exception:
                related = []

        findings = self._vt.normalize(entity, raw_attrs, query_id, related=related)
        return self.validate_findings(findings)

    @staticmethod
    def _not_found(entity: Entity, query_id: str, reason: str) -> EntityFindings:
        return {
            "contract_version": "1.0",
            "query_id": query_id,
            "responding_module": "ti",
            "entity": entity,
            "verdict": "NOT_FOUND",
            "severity": None,
            "mitre": [],
            "justification": reason,
            "evidence": [],
            "related_entities": [],
            "cost": {"llm_calls": 0, "tokens_in": 0, "tokens_out": 0},
        }
