"""Threat Intelligence module tests — all HTTP calls are mocked.

Coverage:
  test_confirmed_critical_hash        — VT 45/72 malicious → CONFIRMED/CRITICAL
  test_inconclusive_low_detections    — VT 2/80 → INCONCLUSIVE
  test_not_found_clean_ip             — VT 0/90 → NOT_FOUND
  test_confirmed_domain_related       — VT 15/90 + relationship call → related_entities
  test_url_base64_encoding            — URL entity type handled correctly
  test_not_applicable_pid             — Unsupported entity type → NOT_APPLICABLE, zero HTTP
  test_vt_429_graceful                — VT returns 429 → NOT_FOUND with justification
  test_no_api_key                     — Missing VT_API_KEY → NOT_FOUND immediately
  test_cache_hit_no_http              — Same entity queried twice → only one HTTP call
  test_enrich_batch                   — Batch of 3 entities → 3 EntityFindings returned
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backbone.threat_intel.agent import ThreatIntelAgent
from backbone.threat_intel.vt_client import VTClient, _determine_verdict_severity
from backbone.threat_intel.rate_limiter import RateLimiter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_query(
    entity_type: str,
    entity_value: str,
    query_id: str = "00000000-0000-0000-0000-000000000001",
    case_id: str = "case-test-001",
) -> dict:
    return {
        "contract_version": "1.0",
        "query_id": query_id,
        "case_id": case_id,
        "entity": {"type": entity_type, "value": entity_value},
        "context": {"source_module": "orchestrator", "source_finding_id": None, "reason": "test"},
    }


def _vt_attrs(
    malicious: int = 0,
    total: int = 90,
    tags: list[str] | None = None,
    threat_label: str | None = None,
    sandbox: dict | None = None,
    last_analysis_date: int | None = 1700000000,
    first_submission_date: int | None = None,
    country: str | None = None,
    as_owner: str | None = None,
    crowdsourced_ids: list[dict] | None = None,
) -> dict:
    stats = {
        "malicious": malicious,
        "suspicious": 0,
        "harmless": max(0, total - malicious),
        "undetected": 0,
        "timeout": 0,
    }
    attrs: dict[str, Any] = {"last_analysis_stats": stats}
    if last_analysis_date:
        attrs["last_analysis_date"] = last_analysis_date
    if tags:
        attrs["tags"] = tags
    if threat_label:
        attrs["popular_threat_classification"] = {"suggested_threat_label": threat_label}
    if sandbox:
        attrs["sandbox_verdicts"] = sandbox
    if first_submission_date:
        attrs["first_submission_date"] = first_submission_date
    if country:
        attrs["country"] = country
    if as_owner:
        attrs["as_owner"] = as_owner
    if crowdsourced_ids:
        attrs["crowdsourced_ids"] = crowdsourced_ids
    return attrs


def _make_agent(monkeypatch=None) -> ThreatIntelAgent:
    """Create an agent with a fake API key (no real HTTP calls expected)."""
    return ThreatIntelAgent(vt_api_key="fake-key-for-testing")


# ---------------------------------------------------------------------------
# Pure unit tests for verdict determination
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("malicious,total,expected_verdict,expected_severity", [
    (0, 90, "NOT_FOUND", None),
    (0, 0, "NOT_FOUND", None),
    (1, 80, "INCONCLUSIVE", None),
    (2, 80, "INCONCLUSIVE", None),
    (3, 80, "CONFIRMED", "LOW"),
    (4, 80, "CONFIRMED", "LOW"),
    (5, 80, "CONFIRMED", "MEDIUM"),
    (9, 80, "CONFIRMED", "MEDIUM"),
    (10, 80, "CONFIRMED", "HIGH"),
    (29, 80, "CONFIRMED", "HIGH"),
    (30, 80, "CONFIRMED", "CRITICAL"),
    (72, 90, "CONFIRMED", "CRITICAL"),
])
def test_verdict_thresholds(malicious, total, expected_verdict, expected_severity):
    verdict, severity = _determine_verdict_severity(malicious, total)
    assert verdict == expected_verdict
    assert severity == expected_severity


# ---------------------------------------------------------------------------
# normalize() unit tests (pure, no I/O)
# ---------------------------------------------------------------------------

def test_normalize_confirmed_hash():
    rl = RateLimiter(calls_per_minute=4)
    client = VTClient("fake-key", rl)
    entity = {"type": "hash_sha256", "value": "abc123"}
    attrs = _vt_attrs(
        malicious=45,
        total=72,
        tags=["trojan", "windows"],
        threat_label="trojan.generic/emotet",
        first_submission_date=1690000000,
    )
    findings = client.normalize(entity, attrs, "00000000-0000-0000-0000-000000000001")

    assert findings["verdict"] == "CONFIRMED"
    assert findings["severity"] == "CRITICAL"
    assert findings["responding_module"] == "ti"
    assert any("45/72" in ev["content"] for ev in findings["evidence"])
    assert any("trojan" in ev["content"] for ev in findings["evidence"])
    assert any("emotet" in ev["content"] for ev in findings["evidence"])
    # First submission timestamp should appear in evidence
    assert any(ev.get("timestamp") for ev in findings["evidence"])


def test_normalize_not_found_empty_attrs():
    rl = RateLimiter(calls_per_minute=4)
    client = VTClient("fake-key", rl)
    entity = {"type": "ip", "value": "1.2.3.4"}
    findings = client.normalize(entity, {}, "00000000-0000-0000-0000-000000000002")

    assert findings["verdict"] == "NOT_FOUND"
    assert findings["severity"] is None
    assert len(findings["evidence"]) == 1
    assert "no scan results" in findings["evidence"][0]["content"]


def test_normalize_mitre_ids_extracted():
    rl = RateLimiter(calls_per_minute=4)
    client = VTClient("fake-key", rl)
    entity = {"type": "hash_sha256", "value": "deadbeef"}
    attrs = _vt_attrs(
        malicious=12,
        total=80,
        crowdsourced_ids=[
            {"rule_id": "T1059", "rule_name": "Command and Scripting Interpreter"},
            {"rule_id": "T1055.001", "rule_name": "Process Injection: DLL"},
            {"rule_id": "NOT-ATT&CK", "rule_name": "something else"},
        ],
    )
    findings = client.normalize(entity, attrs, "00000000-0000-0000-0000-000000000003")

    assert "T1059" in findings["mitre"]
    assert "T1055.001" in findings["mitre"]
    assert "NOT-ATT&CK" not in findings["mitre"]


# ---------------------------------------------------------------------------
# Agent integration tests (HTTP mocked via patching VTClient methods)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_confirmed_critical_hash():
    agent = _make_agent()
    attrs = _vt_attrs(malicious=45, total=72, tags=["trojan"], threat_label="trojan.emotet")

    agent._vt.lookup = AsyncMock(return_value=attrs)
    agent._vt.fetch_related = AsyncMock(return_value=[])

    result = await agent.query(_make_query("hash_sha256", "abc" * 21 + "ab"))
    assert result["verdict"] == "CONFIRMED"
    assert result["severity"] == "CRITICAL"
    assert result["responding_module"] == "ti"
    agent._vt.lookup.assert_awaited_once()
    agent._vt.fetch_related.assert_awaited_once()


@pytest.mark.asyncio
async def test_inconclusive_low_detections():
    agent = _make_agent()
    attrs = _vt_attrs(malicious=2, total=80)

    agent._vt.lookup = AsyncMock(return_value=attrs)
    agent._vt.fetch_related = AsyncMock(return_value=[])

    result = await agent.query(_make_query("hash_sha256", "bad" * 21 + "ba"))
    assert result["verdict"] == "INCONCLUSIVE"
    assert result["severity"] is None
    # fetch_related not called when below CONFIRMED threshold
    agent._vt.fetch_related.assert_not_awaited()


@pytest.mark.asyncio
async def test_not_found_clean_ip():
    agent = _make_agent()
    attrs = _vt_attrs(malicious=0, total=90)

    agent._vt.lookup = AsyncMock(return_value=attrs)
    agent._vt.fetch_related = AsyncMock(return_value=[])

    result = await agent.query(_make_query("ip", "8.8.8.8"))
    assert result["verdict"] == "NOT_FOUND"
    assert result["severity"] is None
    agent._vt.fetch_related.assert_not_awaited()


@pytest.mark.asyncio
async def test_confirmed_domain_related_entities():
    agent = _make_agent()
    attrs = _vt_attrs(malicious=15, total=90, tags=["c2", "malware"])
    related_from_vt = [
        {"type": "file", "id": "sha256-hash-001", "attributes": {"sha256": "sha256-hash-001"}},
        {"type": "file", "id": "sha256-hash-002", "attributes": {"sha256": "sha256-hash-002"}},
    ]

    agent._vt.lookup = AsyncMock(return_value=attrs)
    # Simulate fetch_related returning VT relationship objects already normalized
    from backbone.contracts.types import RelatedEntity
    related_entities = [
        RelatedEntity(type="hash_sha256", value="sha256-hash-001", relationship="communicating files"),
        RelatedEntity(type="hash_sha256", value="sha256-hash-002", relationship="communicating files"),
    ]
    agent._vt.fetch_related = AsyncMock(return_value=related_entities)

    result = await agent.query(_make_query("domain", "evil.example.com"))
    assert result["verdict"] == "CONFIRMED"
    assert result["severity"] == "HIGH"
    assert len(result["related_entities"]) == 2
    assert result["related_entities"][0]["type"] == "hash_sha256"
    agent._vt.fetch_related.assert_awaited_once_with("domain", "evil.example.com")


@pytest.mark.asyncio
async def test_url_lookup_handled():
    """URL entity type is supported — base64 encoding is handled by VTClient."""
    agent = _make_agent()
    attrs = _vt_attrs(malicious=10, total=80)

    agent._vt.lookup = AsyncMock(return_value=attrs)
    agent._vt.fetch_related = AsyncMock(return_value=[])

    result = await agent.query(_make_query("url", "https://evil.example.com/payload.exe"))
    assert result["verdict"] == "CONFIRMED"
    agent._vt.lookup.assert_awaited_once_with("url", "https://evil.example.com/payload.exe")


@pytest.mark.asyncio
async def test_not_applicable_unsupported_entity_type():
    """Unsupported entity type returns NOT_APPLICABLE without touching HTTP."""
    agent = _make_agent()
    agent._vt.lookup = AsyncMock()

    result = await agent.query(_make_query("pid", "1234"))
    assert result["verdict"] == "NOT_APPLICABLE"
    assert result["severity"] is None
    agent._vt.lookup.assert_not_awaited()


@pytest.mark.asyncio
async def test_vt_429_returns_not_found():
    """VT rate-limit response yields NOT_FOUND with descriptive justification."""
    agent = _make_agent()
    agent._vt.lookup = AsyncMock(side_effect=RuntimeError("VirusTotal rate-limited (HTTP 429)"))

    result = await agent.query(_make_query("ip", "185.220.101.45"))
    assert result["verdict"] == "NOT_FOUND"
    assert "429" in result["justification"] or "rate-limited" in result["justification"].lower()
    assert result["evidence"] == []


@pytest.mark.asyncio
async def test_no_api_key_returns_not_found(monkeypatch):
    """When VT_API_KEY is not set, every query returns NOT_FOUND immediately."""
    monkeypatch.delenv("VT_API_KEY", raising=False)
    agent = ThreatIntelAgent()  # no key provided, env var absent

    result = await agent.query(_make_query("hash_sha256", "abc" * 21 + "ab"))
    assert result["verdict"] == "NOT_FOUND"
    assert "VT_API_KEY" in result["justification"]


@pytest.mark.asyncio
async def test_cache_hit_no_duplicate_http():
    """The second query for the same entity in the same case makes no HTTP call."""
    agent = _make_agent()
    attrs = _vt_attrs(malicious=5, total=80)
    agent._vt.lookup = AsyncMock(return_value=attrs)
    agent._vt.fetch_related = AsyncMock(return_value=[])

    q1 = _make_query("ip", "1.2.3.4", query_id="00000000-0000-0000-0000-000000000010")
    q2 = _make_query("ip", "1.2.3.4", query_id="00000000-0000-0000-0000-000000000011")

    r1 = await agent.query(q1)
    r2 = await agent.query(q2)

    # HTTP called only once despite two queries
    assert agent._vt.lookup.await_count == 1
    # Verdicts match; query_ids differ
    assert r1["verdict"] == r2["verdict"]
    assert r1["query_id"] == "00000000-0000-0000-0000-000000000010"
    assert r2["query_id"] == "00000000-0000-0000-0000-000000000011"


@pytest.mark.asyncio
async def test_enrich_batch_returns_all_findings():
    """enrich_batch with 3 entities returns 3 EntityFindings."""
    agent = _make_agent()

    async def _mock_lookup(entity_type: str, entity_value: str):
        if entity_type == "ip":
            return _vt_attrs(malicious=12, total=90)
        if entity_type == "domain":
            return _vt_attrs(malicious=0, total=85)
        return None  # 404 for hash

    agent._vt.lookup = AsyncMock(side_effect=_mock_lookup)
    agent._vt.fetch_related = AsyncMock(return_value=[])

    entities = [
        {"type": "ip", "value": "185.220.101.1"},
        {"type": "domain", "value": "clean.example.com"},
        {"type": "hash_sha256", "value": "a" * 64},
    ]
    results = await agent.enrich_batch("case-batch-001", entities)

    assert len(results) == 3
    verdicts = {r["entity"]["value"]: r["verdict"] for r in results}
    assert verdicts["185.220.101.1"] == "CONFIRMED"
    assert verdicts["clean.example.com"] == "NOT_FOUND"
    assert verdicts["a" * 64] == "NOT_FOUND"
