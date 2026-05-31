"""
Integration test — runs the full pipeline end-to-end with --no-llm.

Verifies:
  1. Pipeline exits cleanly
  2. aggregated_analyst.txt is produced and non-empty
  3. scan_result.json is produced, valid JSON, correct structure
  4. scan_result.json module == "ram" and case_id matches
  5. No report.md is produced (report agent removed)
  6. per-chunk directories (chunk_001/, etc.) each contain triage.txt, pivot.txt, analyst.txt

Prerequisites:
  - INPUT/chunk_*.txt files must exist
  - RAM_Artifacts/ directory must exist (may be empty; pipeline will degrade gracefully)

Run with:
    python -m pytest tests/test_pipeline_integration.py -v
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_DIR / "scripts"
INPUT_DIR = REPO_DIR.parent / "INPUT"
RUN_PIPELINE = SCRIPTS_DIR / "run_pipeline.py"

TEST_CASE_ID = "integration-test-001"


def _run_pipeline(out_dir: Path, extra_args: list = None) -> subprocess.CompletedProcess:
    cmd = [
        sys.executable,
        str(RUN_PIPELINE),
        "--no-llm",
        "--case-id", TEST_CASE_ID,
        "--out", str(out_dir),
    ]
    if extra_args:
        cmd.extend(extra_args)
    return subprocess.run(cmd, capture_output=True, text=True)


class TestPipelineIntegration:
    def setup_method(self):
        if not INPUT_DIR.exists():
            import pytest
            pytest.skip(f"INPUT directory not found: {INPUT_DIR}")
        chunks = list(INPUT_DIR.glob("chunk_*.txt"))
        if not chunks:
            import pytest
            pytest.skip(f"No chunk_*.txt files found in {INPUT_DIR}")

        self.tmp_dir = Path(tempfile.mkdtemp(prefix="ram_test_"))
        self.result = _run_pipeline(self.tmp_dir)
        self.chunks_found = sorted(chunks)

    def test_pipeline_exits_cleanly(self):
        assert self.result.returncode == 0, (
            f"Pipeline failed with exit code {self.result.returncode}\n"
            f"stdout: {self.result.stdout[-1000:]}\n"
            f"stderr: {self.result.stderr[-1000:]}"
        )

    def test_aggregated_analyst_exists(self):
        path = self.tmp_dir / "aggregated_analyst.txt"
        assert path.exists(), "aggregated_analyst.txt was not created"
        assert path.stat().st_size > 0, "aggregated_analyst.txt is empty"

    def test_scan_result_json_exists(self):
        path = self.tmp_dir / "scan_result.json"
        assert path.exists(), "scan_result.json was not created"

    def test_scan_result_json_is_valid(self):
        path = self.tmp_dir / "scan_result.json"
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert isinstance(data, dict)
        self.scan_result = data

    def test_scan_result_module_is_ram(self):
        path = self.tmp_dir / "scan_result.json"
        with open(path) as f:
            data = json.load(f)
        assert data["module"] == "ram"

    def test_scan_result_case_id(self):
        path = self.tmp_dir / "scan_result.json"
        with open(path) as f:
            data = json.load(f)
        assert data["case_id"] == TEST_CASE_ID

    def test_scan_result_required_keys(self):
        path = self.tmp_dir / "scan_result.json"
        with open(path) as f:
            data = json.load(f)
        required = {
            "contract_version", "case_id", "module",
            "scan_started_at", "scan_completed_at",
            "summary", "counts", "findings", "artifacts",
        }
        assert required.issubset(data.keys()), \
            f"Missing keys: {required - data.keys()}"

    def test_counts_keys_present(self):
        path = self.tmp_dir / "scan_result.json"
        with open(path) as f:
            data = json.load(f)
        assert "confirmed" in data["counts"]
        assert "inconclusive" in data["counts"]
        assert "rejected" in data["counts"]

    def test_no_report_md(self):
        report_path = self.tmp_dir / "report.md"
        assert not report_path.exists(), \
            "report.md should NOT be produced — report agent was removed"

    def test_per_chunk_outputs_exist(self):
        n_chunks = len(self.chunks_found)
        for i in range(1, n_chunks + 1):
            chunk_dir = self.tmp_dir / f"chunk_{i:03d}"
            assert chunk_dir.exists(), f"Chunk directory not found: {chunk_dir}"
            for fname in ("triage.txt", "pivot.txt", "analyst.txt"):
                fpath = chunk_dir / fname
                assert fpath.exists(), f"Missing {fname} in {chunk_dir}"

    def test_artifacts_human_report_path(self):
        path = self.tmp_dir / "scan_result.json"
        with open(path) as f:
            data = json.load(f)
        human_report = data["artifacts"].get("human_report", "")
        assert "aggregated_analyst" in human_report

    def test_summary_mentions_chunks(self):
        path = self.tmp_dir / "scan_result.json"
        with open(path) as f:
            data = json.load(f)
        assert "chunk" in data["summary"].lower()


class TestEntityQueryAuditDir:
    """Verify that entity_query.py creates the queries/ audit directory."""

    def setup_method(self):
        import pytest
        # This test runs entity_query separately and checks audit output
        fixtures = Path(__file__).parent / "fixtures" / "queries"
        self.query_file = fixtures / "query_01_hash_sha256.json"
        if not self.query_file.exists():
            pytest.skip("Fixture query_01 not found")

    def test_audit_file_created(self):
        import tempfile
        from pathlib import Path
        import subprocess

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path = tmp.name

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS_DIR / "entity_query.py"),
                "--query", str(self.query_file),
                "--out", out_path,
                "--no-llm",
            ],
            capture_output=True, text=True,
        )
        assert result.returncode == 0

        audit_dir = REPO_DIR / "output" / "queries"
        # Audit dir should be created (may already exist from pipeline runs)
        query_id = "aaaaaaaa-0001-0001-0001-000000000001"
        audit_file = audit_dir / f"{query_id}.txt"
        assert audit_file.exists(), f"Audit file not created: {audit_file}"
