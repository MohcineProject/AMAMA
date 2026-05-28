"""Tests for Backbone scaffolds."""

from backbone.case_graph import CaseGraph


def test_ingest_scan_result_seeds_graph():
    graph = CaseGraph(case_id="case-test-001")
    result = {
        "contract_version": "1.0",
        "case_id": "case-test-001",
        "module": "disk",
        "scan_started_at": "2026-05-20T10:00:00Z",
        "scan_completed_at": "2026-05-20T10:05:00Z",
        "summary": "1 finding",
        "counts": {"confirmed": 1, "inconclusive": 0, "rejected": 0},
        "findings": [
            {
                "finding_id": "disk-mft-f001",
                "verdict": "CONFIRMED",
                "severity": "HIGH",
                "primary_entity": {"type": "file_path", "value": "C:\\Temp\\evil.exe"},
                "related_entities": [
                    {"type": "hash_sha256", "value": "abc123", "relationship": "file_hash"},
                ],
                "justification": "Suspicious path in MFT.",
                "evidence": [
                    {
                        "source_file": "mft_records.txt",
                        "line": 42,
                        "content": "evil.exe ...",
                        "verbatim": True,
                    }
                ],
            }
        ],
        "artifacts": {"human_report": "output/analyst.txt"},
    }

    graph.ingest_scan_result(result)

    assert len(graph.nodes) == 2
    assert ("file_path", "C:\\Temp\\evil.exe") in graph.nodes
    assert ("hash_sha256", "abc123") in graph.nodes

    summary = graph.summary_for_agent()
    assert summary["case_id"] == "case-test-001"
    assert summary["entity_count"] == 2
