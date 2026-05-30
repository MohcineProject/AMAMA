# Session Updates

## Overview

- **Completed the orchestrator scaffolds** — `agent.py` and `loop.py` both had placeholder implementations. The agent now calls the Anthropic API (Claude Haiku) using the system prompt in `prompts/orchestrator.md`, pre-filters CONFIRMED entities before sending candidates to the LLM, and strips markdown code fences from responses. The loop now runs a proper multi-round investigation cycle: dispatch → ingest → track → repeat until convergence or `max_rounds`.

- **Added a guard against LLM entity invention** — the loop validates that each entity returned by the LLM actually exists in the graph before dispatching a query. Without this guard, the LLM was inferring entities (e.g. extracting an IP from an `image_name` label) and routing them, polluting the graph with fabricated nodes.

- **Extended `CaseGraph` and `EntityNode`** with three small additions needed for clean test assertions and report-maker compatibility: `termination_reason` field, `verdicts_received` property (derived from findings), and marking the scanning module as queried in `ingest_scan_result()` so it is not re-queried in subsequent rounds.

- **Built the test suite** — 7 tests covering all five requirements. Non-LLM tests (3) run fast with no API key; LLM tests (4) are marked `@pytest.mark.llm` and skipped automatically when `ANTHROPIC_API_KEY` is absent. All routing decisions and case states are written to `tests/test-data/output/` on each run for inspection.

- **Organised test data** — all inputs extracted to `tests/test-data/input/` as standalone JSON files; outputs written to `tests/test-data/output/<case-id>/` so every test run is fully traceable from input to output.

---

## Files

| Path | Action | Description |
|---|---|---|
| `backbone/orchestrator/agent.py` | Implemented | Replaced scaffold with LLM routing: pre-filters CONFIRMED candidates, builds compact JSON message (candidates + module capabilities), calls Claude Haiku, strips code fences, returns decision list |
| `backbone/orchestrator/loop.py` | Implemented | Replaced single-pass scaffold with multi-round loop: dispatches query decisions async, ingests findings, tracks rounds, guards against LLM-invented entities, writes `case_state.json`, sets `termination_reason` |
| `backbone/case_graph.py` | Modified | Added `termination_reason: str \| None` to `CaseGraph`; `verdicts_received` property to `EntityNode`; `ingest_scan_result()` now adds scanning module to `node.queried_modules`; `to_dict()` includes `termination_reason`, `rounds`, and `verdicts_received` per node |
| `pyproject.toml` | Modified | Added `anthropic>=0.28` to production dependencies |
| `tests/conftest.py` | Created | Registers `llm` pytest marker; auto-skips `@pytest.mark.llm` tests when `ANTHROPIC_API_KEY` is unset |
| `tests/test_orchestrator_loop.py` | Created | 7 integration tests covering all 5 requirements (3 no-LLM, 4 LLM); loads inputs from `test-data/input/`, writes outputs to `test-data/output/` |
| `tests/test-data/input/scan_real.json` | Created | Real 23-finding disk scan (19 CONFIRMED, 4 INCONCLUSIVE) — used by tests 1, 2, 7 |
| `tests/test-data/input/scan_convergence.json` | Created | Single CONFIRMED finding — loop must converge with no routing rounds (test 3) |
| `tests/test-data/input/scan_llm_routing.json` | Created | 1 CONFIRMED + 1 INCONCLUSIVE — verifies LLM pre-filter and per-finding routing (test 4) |
| `tests/test-data/input/scan_routing_awareness.json` | Created | 2 INCONCLUSIVE from a `triage` module (not in `available_modules`) — verifies LLM routes `pid→ram` and `file_path→disk` without knowing module internals (test 5) |
| `tests/test-data/input/scan_max_rounds.json` | Created | 1 INCONCLUSIVE ip — loop must exit with `max_rounds_reached` at `max_rounds=1` (test 6) |
| `tests/test-data/output/test-ingest/graph_state.json` | Generated | `graph.to_dict()` after ingesting `scan_real.json` — 22 unique entities, all marked `queried_modules: ["disk"]` |
| `tests/test-data/output/test-state-format/graph_state.json` | Generated | Same as above with `termination_reason: "convergence"` set — reference for report-maker key structure |
| `tests/test-data/output/test-convergence/case_state.json` | Generated | Loop output: 1 CONFIRMED entity, `rounds: []`, `termination_reason: "convergence"` |
| `tests/test-data/output/test-llm-routing/decisions.json` | Generated | LLM decisions for 1 INCONCLUSIVE candidate: `action: "query"`, `target_module: "ram"` |
| `tests/test-data/output/test-routing-awareness/decisions.json` | Generated | LLM decisions: `pid:9999 → ram`, `file_path:C:\Temp\suspicious.exe → disk` |
| `tests/test-data/output/test-max-rounds/case_state.json` | Generated | Loop output: 1 round dispatched, `termination_reason: "max_rounds_reached"` |
| `tests/test-data/output/test-e2e-real/case_state.json` | Generated | Full loop output: 22 entities, 19 CONFIRMED never touched by RAM, 4 INCONCLUSIVE routed to RAM (NOT_FOUND), `termination_reason: "convergence"` in 2 rounds |
