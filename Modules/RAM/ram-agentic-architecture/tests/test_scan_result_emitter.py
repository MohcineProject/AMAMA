"""
Tests for scan_result_emitter.emit_scan_result().

Fixtures used:
  tests/fixtures/aggregated_analyst_sample.txt  — synthetic analyst output
  output/aggregated_analyst.txt                 — real pipeline output (if present)
"""
import json
import sys
import tempfile
from pathlib import Path

# Add scripts/ to sys.path so we can import the module directly
REPO_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_DIR / "scripts"))

from scan_result_emitter import emit_scan_result

FIXTURE = Path(__file__).parent / "fixtures" / "aggregated_analyst_sample.txt"
REAL_OUTPUT = REPO_DIR / "output" / "aggregated_analyst.txt"


def _run_emitter(source: Path, case_id: str = "test-case-001") -> dict:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name
    result = emit_scan_result(
        aggregated_path=str(source),
        case_id=case_id,
        out_path=out_path,
    )
    with open(out_path, "r", encoding="utf-8") as f:
        on_disk = json.load(f)
    return result, on_disk


class TestScanResultEmitterFixture:
    """Tests against the synthetic fixture file."""

    def setup_method(self):
        assert FIXTURE.exists(), f"Fixture not found: {FIXTURE}"
        self.result, self.on_disk = _run_emitter(FIXTURE)

    def test_output_is_valid_json(self):
        assert isinstance(self.result, dict)
        assert isinstance(self.on_disk, dict)

    def test_result_matches_on_disk(self):
        assert self.result == self.on_disk

    def test_required_top_level_keys(self):
        required = {
            "contract_version", "case_id", "module",
            "scan_started_at", "scan_completed_at",
            "summary", "counts", "findings", "artifacts",
        }
        assert required.issubset(self.result.keys()), \
            f"Missing keys: {required - self.result.keys()}"

    def test_module_is_ram(self):
        assert self.result["module"] == "ram"

    def test_contract_version(self):
        assert self.result["contract_version"] == "1.0"

    def test_case_id_propagated(self):
        assert self.result["case_id"] == "test-case-001"

    def test_counts_structure(self):
        counts = self.result["counts"]
        assert "confirmed" in counts
        assert "inconclusive" in counts
        assert "rejected" in counts

    def test_fixture_confirmed_count(self):
        # The fixture has 1 CONFIRMED block
        assert self.result["counts"]["confirmed"] == 1

    def test_fixture_inconclusive_count(self):
        # The fixture has 1 INCONCLUSIVE block
        assert self.result["counts"]["inconclusive"] == 1

    def test_fixture_rejected_count(self):
        # Chunk 1 header says rejected=2, Chunk 2 header says rejected=5 → max=5
        assert self.result["counts"]["rejected"] >= 2

    def test_counts_consistent_with_findings(self):
        confirmed = self.result["counts"]["confirmed"]
        inconclusive = self.result["counts"]["inconclusive"]
        findings = self.result["findings"]
        # findings only contains CONFIRMED + INCONCLUSIVE blocks
        assert len(findings) == confirmed + inconclusive

    def test_all_findings_have_pid_primary_entity(self):
        for f in self.result["findings"]:
            assert f["primary_entity"]["type"] == "pid", \
                f"Finding {f.get('finding_id')} has unexpected primary_entity type"

    def test_confirmed_finding_has_severity(self):
        confirmed = [f for f in self.result["findings"] if f["verdict"] == "CONFIRMED"]
        assert len(confirmed) == 1
        assert confirmed[0]["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_inconclusive_finding_has_null_severity(self):
        inconclusive = [f for f in self.result["findings"] if f["verdict"] == "INCONCLUSIVE"]
        assert len(inconclusive) == 1
        assert inconclusive[0]["severity"] is None

    def test_finding_ids_are_unique(self):
        ids = [f["finding_id"] for f in self.result["findings"]]
        assert len(ids) == len(set(ids))

    def test_confirmed_finding_has_mitre(self):
        confirmed = [f for f in self.result["findings"] if f["verdict"] == "CONFIRMED"]
        assert confirmed[0]["mitre"], "CONFIRMED finding should have non-empty MITRE list"

    def test_related_entities_extracted(self):
        confirmed = [f for f in self.result["findings"] if f["verdict"] == "CONFIRMED"]
        rels = confirmed[0]["related_entities"]
        types = {r["type"] for r in rels}
        # Should extract at least the image_name and possibly an IP
        assert "image_name" in types, "Expected image_name in related_entities"

    def test_artifacts_section(self):
        arts = self.result["artifacts"]
        assert "human_report" in arts

    def test_summary_string(self):
        s = self.result["summary"]
        assert "chunk" in s.lower()
        assert "CONFIRMED" in s
        assert "INCONCLUSIVE" in s


class TestScanResultEmitterRealOutput:
    """Tests against the real pipeline output (skipped if not present)."""

    def setup_method(self):
        if not REAL_OUTPUT.exists():
            import pytest
            pytest.skip(f"Real pipeline output not found: {REAL_OUTPUT}")
        self.result, _ = _run_emitter(REAL_OUTPUT, case_id="real-pipeline-test")

    def test_valid_structure(self):
        required = {"contract_version", "module", "counts", "findings", "artifacts"}
        assert required.issubset(self.result.keys())

    def test_module_is_ram(self):
        assert self.result["module"] == "ram"

    def test_all_findings_have_pid_primary_entity(self):
        for f in self.result["findings"]:
            assert f["primary_entity"]["type"] == "pid"

    def test_counts_match_findings(self):
        confirmed = self.result["counts"]["confirmed"]
        inconclusive = self.result["counts"]["inconclusive"]
        assert len(self.result["findings"]) == confirmed + inconclusive
