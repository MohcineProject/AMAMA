"""Threat Intel agent — external IOC enrichment."""

from __future__ import annotations

from typing import Any

from backbone.contracts.types import Entity, EntityFindings


class ThreatIntelAgent:
    """
    Batch-enriches entities via external providers (VirusTotal, AbuseIPDB, …).
    Returns EntityFindings-shaped payloads. Wired in a later commit.
    """

    def __init__(self, *, enabled: bool = True) -> None:
        self.enabled = enabled

    def enrich_batch(self, case_id: str, entities: list[Entity]) -> list[EntityFindings]:
        if not self.enabled or not entities:
            return []
        return []
