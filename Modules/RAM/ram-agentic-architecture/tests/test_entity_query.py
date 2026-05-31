"""
Tests for entity_query.py — the RAM module QUERY mode (pivot-back).

Test cases:
  01 — hash_sha256 entity → NOT_APPLICABLE (RAM has no file hashes)
  02 — pid=999999        → NOT_FOUND (guaranteed absent)
  03 — image_name=svchost.exe (no-llm) → schema-valid INCONCLUSIVE (evidence found)
       or NOT_FOUND (if RAM_Artifacts not present)
  04 — image_name=lsass.exe (no-llm) → schema-valid response, correct structure

Fixtures:
  tests/fixtures/queries/query_01_*.json … query_04_*.json  — input EntityQuery files
  tests/fixtures/expected/findings_01_*.json … (partial)    — expected fields for assertions

All tests run with --no-llm so no API key is required.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_DIR / "scripts"
FIXTURES_QUERIES = Path(__file__).parent / "fixtures" / "queries"
FIXTURES_EXPECTED = Path(__file__).parent / "fixtures" / "expected"

ENTITY_QUERY_SCRIPT = SCRIPTS_DIR / "entity_query.py"


def _run_query(query_file: Path, extra_args: list = None) -> dict:
    """Run entity_query.py and return the parsed findings JSON."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name

    cmd = [
        sys.executable,
        str(ENTITY_QUERY_SCRIPT),
        "--query", str(query_file),
        "--out", out_path,
        "--no-llm",
    ]
    if extra_args:
        cmd.extend(extra_args)

    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, \
        f"entity_query.py exited {result.returncode}:\nstdout={result.stdout}\nstderr={result.stderr}"

    with open(out_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_expected(name: str) -> dict:
    path = FIXTURES_EXPECTED / name
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _assert_valid_envelope(findings: dict, query_id: str):
    """Check that the mandatory EntityFindings envelope fields are present and correct."""
    required = {
        "contract_version", "query_id", "responding_module", "entity",
        "verdict", "severity", "mitre", "justification", "evidence",
        "related_entities", "cost",
    }
    missing = required - findings.keys()
    assert not missing, f"Missing fields in EntityFindings: {missing}"
    assert findings["contract_version"] == "1.0"
    assert findings["responding_module"] == "ram"
    assert findings["query_id"] == query_id
    assert isinstance(findings["mitre"], list)
    assert isinstance(findings["evidence"], list)
    assert isinstance(findings["related_entities"], list)
    assert isinstance(findings["cost"], dict)
    # severity must be null for non-CONFIRMED
    if findings["verdict"] != "CONFIRMED":
        assert findings["severity"] is None, \
            f"severity must be null for verdict={findings['verdict']}"


class TestQuery01HashNotApplicable:
    def setup_method(self):
        self.query_file = FIXTURES_QUERIES / "query_01_hash_sha256.json"
        assert self.query_file.exists(), f"Fixture not found: {self.query_file}"
        self.findings = _run_query(self.query_file)

    def test_verdict_is_not_applicable(self):
        assert self.findings["verdict"] == "NOT_APPLICABLE"

    def test_zero_llm_calls(self):
        assert self.findings["cost"]["llm_calls"] == 0

    def test_empty_evidence(self):
        assert self.findings["evidence"] == []

    def test_valid_envelope(self):
        _assert_valid_envelope(self.findings, "aaaaaaaa-0001-0001-0001-000000000001")

    def test_matches_expected(self):
        expected = _load_expected("findings_01_hash_sha256_not_applicable.json")
        if not expected:
            return  # no expected file, skip comparison
        assert self.findings["verdict"] == expected["verdict"]
        assert self.findings["responding_module"] == expected["responding_module"]


class TestQuery02PidNotFound:
    def setup_method(self):
        self.query_file = FIXTURES_QUERIES / "query_02_pid_not_found.json"
        assert self.query_file.exists(), f"Fixture not found: {self.query_file}"
        self.findings = _run_query(self.query_file)

    def test_verdict_is_not_found(self):
        assert self.findings["verdict"] == "NOT_FOUND"

    def test_zero_llm_calls(self):
        assert self.findings["cost"]["llm_calls"] == 0

    def test_empty_evidence(self):
        assert self.findings["evidence"] == []

    def test_valid_envelope(self):
        _assert_valid_envelope(self.findings, "aaaaaaaa-0002-0002-0002-000000000002")

    def test_justification_mentions_pid(self):
        assert "999999" in self.findings["justification"]


class TestQuery03SvchostNoLLM:
    def setup_method(self):
        self.query_file = FIXTURES_QUERIES / "query_03_image_name_svchost.json"
        assert self.query_file.exists(), f"Fixture not found: {self.query_file}"
        self.findings = _run_query(self.query_file)

    def test_valid_envelope(self):
        _assert_valid_envelope(self.findings, "aaaaaaaa-0003-0003-0003-000000000003")

    def test_verdict_is_acceptable(self):
        # Without LLM we expect INCONCLUSIVE (evidence found) or NOT_FOUND (no artifacts)
        assert self.findings["verdict"] in ("INCONCLUSIVE", "NOT_FOUND", "REJECTED")

    def test_zero_llm_calls(self):
        assert self.findings["cost"]["llm_calls"] == 0

    def test_if_evidence_then_inconclusive(self):
        if self.findings["evidence"]:
            assert self.findings["verdict"] in ("INCONCLUSIVE", "REJECTED"), \
                "Evidence was retrieved but verdict is not INCONCLUSIVE/REJECTED"

    def test_entity_echoed_correctly(self):
        assert self.findings["entity"]["type"] == "image_name"
        assert self.findings["entity"]["value"] == "svchost.exe"


class TestQuery04LsassNoLLM:
    def setup_method(self):
        self.query_file = FIXTURES_QUERIES / "query_04_image_name_lsass.json"
        assert self.query_file.exists(), f"Fixture not found: {self.query_file}"
        self.findings = _run_query(self.query_file)

    def test_valid_envelope(self):
        _assert_valid_envelope(self.findings, "aaaaaaaa-0004-0004-0004-000000000004")

    def test_verdict_is_acceptable(self):
        assert self.findings["verdict"] in ("INCONCLUSIVE", "NOT_FOUND", "REJECTED")

    def test_zero_llm_calls(self):
        assert self.findings["cost"]["llm_calls"] == 0

    def test_entity_echoed_correctly(self):
        assert self.findings["entity"]["type"] == "image_name"
        assert self.findings["entity"]["value"] == "lsass.exe"

    def test_responding_module_is_ram(self):
        assert self.findings["responding_module"] == "ram"
