"""VirusTotal API v3 async client with response normalization."""

from __future__ import annotations

import base64
import re
from datetime import datetime, timezone
from typing import Any

import httpx

from backbone.contracts.types import Entity, EntityFindings, EvidenceLine, RelatedEntity
from backbone.threat_intel.rate_limiter import RateLimiter

_BASE_URL = "https://www.virustotal.com/api/v3"

_VT_PATH: dict[str, str] = {
    "ip": "ip_addresses",
    "domain": "domains",
    "url": "urls",
    "hash_md5": "files",
    "hash_sha1": "files",
    "hash_sha256": "files",
}

# Primary relationship endpoint to call per entity type (one extra API call when CONFIRMED)
_REL_TYPE: dict[str, str] = {
    "ip": "communicating_files",
    "domain": "communicating_files",
    "hash_md5": "contacted_ips",
    "hash_sha1": "contacted_ips",
    "hash_sha256": "contacted_ips",
}

# VT type string → our EntityFindings entity type
_VT_ITEM_TYPE: dict[str, str] = {
    "ip_address": "ip",
    "domain": "domain",
    "url": "url",
    "file": "hash_sha256",
}

_MITRE_RE = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")


def _ts_to_iso(unix_ts: int | None) -> str | None:
    if not unix_ts:
        return None
    return datetime.fromtimestamp(unix_ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_url(entity_type: str, entity_value: str) -> str:
    path_seg = _VT_PATH[entity_type]
    if entity_type == "url":
        encoded = base64.urlsafe_b64encode(entity_value.encode()).decode().rstrip("=")
        return f"{_BASE_URL}/{path_seg}/{encoded}"
    return f"{_BASE_URL}/{path_seg}/{entity_value}"


def _determine_verdict_severity(malicious: int, total: int) -> tuple[str, str | None]:
    if total == 0 or malicious == 0:
        return "NOT_FOUND", None
    if malicious <= 2:
        return "INCONCLUSIVE", None
    if malicious <= 4:
        return "CONFIRMED", "LOW"
    if malicious <= 9:
        return "CONFIRMED", "MEDIUM"
    if malicious <= 29:
        return "CONFIRMED", "HIGH"
    return "CONFIRMED", "CRITICAL"


class VTClient:
    """Async VirusTotal API v3 client with built-in rate limiting."""

    def __init__(self, api_key: str, rate_limiter: RateLimiter) -> None:
        self._api_key = api_key
        self._rl = rate_limiter
        self._headers = {"x-apikey": api_key, "accept": "application/json"}

    async def lookup(self, entity_type: str, entity_value: str) -> dict[str, Any] | None:
        """
        Fetch VT attributes for an entity.
        Returns the attributes dict, None on 404, or raises RuntimeError on auth/rate errors.
        """
        await self._rl.acquire()
        url = _build_url(entity_type, entity_value)
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=self._headers)

        if resp.status_code == 404:
            return None
        if resp.status_code == 429:
            raise RuntimeError("VirusTotal rate-limited (HTTP 429)")
        if resp.status_code == 401:
            raise RuntimeError("VirusTotal API key rejected (HTTP 401)")
        resp.raise_for_status()
        body = resp.json()
        return body.get("data", {}).get("attributes") or {}

    async def fetch_related(
        self, entity_type: str, entity_value: str, limit: int = 5
    ) -> list[RelatedEntity]:
        """Fetch top related entities from VT relationship endpoint (one extra API call)."""
        rel_endpoint = _REL_TYPE.get(entity_type)
        if not rel_endpoint:
            return []

        await self._rl.acquire()
        url = _build_url(entity_type, entity_value) + f"/{rel_endpoint}?limit={limit}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=self._headers)

        if not resp.is_success:
            return []

        items = resp.json().get("data") or []
        related: list[RelatedEntity] = []
        rel_label = rel_endpoint.replace("_", " ")

        for item in items:
            vt_type = item.get("type", "")
            item_attrs = item.get("attributes") or {}
            entity_type_out = _VT_ITEM_TYPE.get(vt_type)
            if not entity_type_out:
                continue

            if entity_type_out == "hash_sha256":
                value = item_attrs.get("sha256") or item.get("id", "")
            else:
                value = item.get("id", "")

            if value:
                related.append(
                    RelatedEntity(type=entity_type_out, value=value, relationship=rel_label)
                )

        return related

    def normalize(
        self,
        entity: Entity,
        attrs: dict[str, Any],
        query_id: str,
        related: list[RelatedEntity] | None = None,
    ) -> EntityFindings:
        """Convert VT attributes dict into an EntityFindings payload."""
        stats = attrs.get("last_analysis_stats") or {}
        malicious = stats.get("malicious", 0)
        total = sum(v for v in stats.values() if isinstance(v, int)) if stats else 0
        verdict, severity = _determine_verdict_severity(malicious, total)

        evidence: list[EvidenceLine] = []
        line_num = 0

        def _add(content: str, ts: str | None = None) -> None:
            nonlocal line_num
            line_num += 1
            ev: EvidenceLine = {
                "source_file": "virustotal",
                "line": line_num,
                "content": content,
                "verbatim": True,
            }
            if ts is not None:
                ev["timestamp"] = ts
            evidence.append(ev)

        last_analysis_ts = _ts_to_iso(attrs.get("last_analysis_date"))
        if total > 0:
            _add(
                f"VT detections: {malicious}/{total} engines flagged as malicious",
                ts=last_analysis_ts,
            )
        else:
            _add("VT: no scan results available")

        tags = attrs.get("tags") or []
        if tags:
            _add(f"VT tags: {', '.join(tags)}")

        ptc = attrs.get("popular_threat_classification") or {}
        threat_label = ptc.get("suggested_threat_label")
        if threat_label:
            _add(f"Threat label: {threat_label}")

        meaningful_name = attrs.get("meaningful_name") or (attrs.get("names") or [None])[0]
        if meaningful_name:
            _add(f"Common name: {meaningful_name}")

        country = attrs.get("country")
        as_owner = attrs.get("as_owner")
        asn = attrs.get("asn")
        if country or as_owner:
            parts = []
            if country:
                parts.append(f"country={country}")
            if as_owner:
                parts.append(f"AS={as_owner}")
            if asn:
                parts.append(f"ASN={asn}")
            _add("Geolocation: " + ", ".join(parts))

        registrar = attrs.get("registrar")
        if registrar:
            _add(f"Registrar: {registrar}", ts=_ts_to_iso(attrs.get("creation_date")))

        sandbox = attrs.get("sandbox_verdicts") or {}
        for sandbox_name, sv in list(sandbox.items())[:2]:
            if not isinstance(sv, dict):
                continue
            cat = sv.get("category", "unknown")
            families = sv.get("malware_classification") or []
            line_content = f"Sandbox ({sandbox_name}): {cat}"
            if families:
                line_content += f" — {', '.join(families[:3])}"
            _add(line_content)

        first_sub = attrs.get("first_submission_date")
        if first_sub:
            first_sub_ts = _ts_to_iso(first_sub)
            _add(f"First submitted: {first_sub_ts}", ts=first_sub_ts)

        mitre: list[str] = []
        for entry in attrs.get("crowdsourced_ids") or []:
            if not isinstance(entry, dict):
                continue
            rule_id = entry.get("rule_id", "")
            if _MITRE_RE.match(rule_id) and rule_id not in mitre:
                mitre.append(rule_id)

        if verdict == "CONFIRMED":
            justification = (
                f"VirusTotal: {malicious}/{total} engines flagged as malicious (severity={severity})"
            )
        elif verdict == "INCONCLUSIVE":
            justification = (
                f"VirusTotal: {malicious}/{total} engines flagged — low confidence"
            )
        else:
            justification = "VirusTotal: no malicious detections or no record found"

        return EntityFindings(
            contract_version="1.0",
            query_id=query_id,
            responding_module="ti",
            entity=entity,
            verdict=verdict,
            severity=severity,
            mitre=mitre,
            justification=justification,
            evidence=evidence,
            related_entities=related or [],
            cost={"llm_calls": 0, "tokens_in": 0, "tokens_out": 0},
        )
