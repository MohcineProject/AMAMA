"""Orchestrator-connectivity tests for the RAM module.

These load RamModule exactly the way the orchestrator does (via the registry
``path`` mechanism) and exercise the async scan()/query() contract end-to-end,
asserting the payloads validate against the Backbone JSON schemas. They run with
``use_llm=False`` so no API keys or memory image are required.
"""

from pathlib import Path

import pytest

from backbone.contracts.validate import validate_findings, validate_scan_result
from backbone.registry import load_modules

_RAM_MODULE_ROOT = (
    Path(__file__).resolve().parents[2] / "Modules" / "RAM" / "ram-agentic-architecture"
)

pytestmark = pytest.mark.skipif(
    not (_RAM_MODULE_ROOT / "ram_module.py").is_file(),
    reason="ram module not present in workspace",
)


def _load_ram():
    repo_root = Path(__file__).resolve().parents[2]
    config = {
        "modules": [
            {
                "class": "ram_module.RamModule",
                "path": str(_RAM_MODULE_ROOT),
                "kwargs": {"use_llm": False},
            }
        ]
    }
    return load_modules(config, config_dir=repo_root)["ram"]


def _query(query_id: str, etype: str, value: str) -> dict:
    return {
        "contract_version": "1.0",
        "query_id": query_id,
        "target_module": "ram",
        "entity": {"type": etype, "value": value},
        "context": {"reason": "orchestrator-connectivity test"},
        "scope": {"max_evidence_lines": 10},
    }


@pytest.mark.asyncio
async def test_ram_scan_returns_valid_scan_result():
    ram = _load_ram()
    result = await ram.scan("ram-conn-001")
    validate_scan_result(result)
    assert result["module"] == "ram"
    assert result["case_id"] == "ram-conn-001"


@pytest.mark.asyncio
async def test_ram_query_hash_not_applicable():
    ram = _load_ram()
    findings = await ram.query(
        _query("aaaaaaaa-0001-0001-0001-000000000001", "hash_sha256", "a" * 64)
    )
    validate_findings(findings)
    assert findings["verdict"] == "NOT_APPLICABLE"
    assert findings["responding_module"] == "ram"
    assert findings["cost"]["llm_calls"] == 0


@pytest.mark.asyncio
async def test_ram_query_wrong_target_module():
    ram = _load_ram()
    q = _query("aaaaaaaa-0002-0002-0002-000000000002", "pid", "1234")
    q["target_module"] = "disk"
    findings = await ram.query(q)
    validate_findings(findings)
    assert findings["verdict"] == "NOT_APPLICABLE"


@pytest.mark.asyncio
async def test_ram_query_image_name_no_llm():
    ram = _load_ram()
    findings = await ram.query(
        _query("aaaaaaaa-0003-0003-0003-000000000003", "image_name", "svchost.exe")
    )
    validate_findings(findings)
    # Without an LLM we expect a deterministic verdict (no CONFIRMED).
    assert findings["verdict"] in ("INCONCLUSIVE", "NOT_FOUND", "REJECTED")
    assert findings["cost"]["llm_calls"] == 0
