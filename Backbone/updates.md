# Session Updates

## ORCHESTRATOR

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
| `tests/test-data/input/orchestrator-input/scan_real.json` | Created | Real 23-finding disk scan (19 CONFIRMED, 4 INCONCLUSIVE) — used by tests 1, 2, 7 |
| `tests/test-data/input/orchestrator-input/scan_convergence.json` | Created | Single CONFIRMED finding — loop must converge with no routing rounds (test 3) |
| `tests/test-data/input/orchestrator-input/scan_llm_routing.json` | Created | 1 CONFIRMED + 1 INCONCLUSIVE — verifies LLM pre-filter and per-finding routing (test 4) |
| `tests/test-data/input/orchestrator-input/scan_routing_awareness.json` | Created | 2 INCONCLUSIVE from a `triage` module (not in `available_modules`) — verifies LLM routes `pid→ram` and `file_path→disk` without knowing module internals (test 5) |
| `tests/test-data/input/orchestrator-input/scan_max_rounds.json` | Created | 1 INCONCLUSIVE ip — loop must exit with `max_rounds_reached` at `max_rounds=1` (test 6) |
| `tests/test-data/output/orchestrator-tests/test-ingest/graph_state.json` | Generated | `graph.to_dict()` after ingesting `scan_real.json` — 22 unique entities, all marked `queried_modules: ["disk"]` |
| `tests/test-data/output/orchestrator-tests/test-state-format/graph_state.json` | Generated | Same as above with `termination_reason: "convergence"` set — reference for report-maker key structure |
| `tests/test-data/output/orchestrator-tests/test-convergence/case_state.json` | Generated | Loop output: 1 CONFIRMED entity, `rounds: []`, `termination_reason: "convergence"` |
| `tests/test-data/output/orchestrator-tests/test-llm-routing/decisions.json` | Generated | LLM decisions for 1 INCONCLUSIVE candidate: `action: "query"`, `target_module: "ram"` |
| `tests/test-data/output/orchestrator-tests/test-routing-awareness/decisions.json` | Generated | LLM decisions: `pid:9999 → ram`, `file_path:C:\Temp\suspicious.exe → disk` |
| `tests/test-data/output/orchestrator-tests/test-max-rounds/case_state.json` | Generated | Loop output: 1 round dispatched, `termination_reason: "max_rounds_reached"` |
| `tests/test-data/output/orchestrator-tests/test-e2e-real/case_state.json` | Generated | Full loop output: 22 entities, 19 CONFIRMED never touched by RAM, 4 INCONCLUSIVE routed to RAM (NOT_FOUND), `termination_reason: "convergence"` in 2 rounds |

## THREAT INTELLIGENCE MODULE

## Overview

- **Implemented `ThreatIntelAgent` as a full `BaseForensicModule`** — replaced the stub returning `[]` with a working module (`module_id="ti"`) that implements `scan()`, `query()`, and `enrich_batch()`. `scan()` returns an empty result immediately (TI has no artifact to read at case start); `query()` is the main entry point for orchestrator-driven lookups; `enrich_batch()` handles batch enrichment for all new entities at the start of each round.

- **VirusTotal API v3 client with response normalisation** — `VTClient` covers all six supported entity types (`ip`, `domain`, `url`, `hash_md5`, `hash_sha1`, `hash_sha256`) with the correct endpoint per type (URL lookups use url-safe base64 encoding). Raw VT attributes are normalised into `EntityFindings`: detection ratio, tags, threat label, common name, geolocation/ASN (IPs), registrar (domains), sandbox verdicts (top 2), first-submission timestamp, and MITRE ATT&CK IDs extracted from `crowdsourced_ids`. Related entities (contacted IPs, communicating files) are fetched via a second relationship call only when the IOC is CONFIRMED, to conserve API quota.

- **Verdict and severity mapping** — deterministic thresholds with no LLM involvement: 0 malicious → `NOT_FOUND`; 1–2 → `INCONCLUSIVE`; 3–4 → `CONFIRMED/LOW`; 5–9 → `CONFIRMED/MEDIUM`; 10–29 → `CONFIRMED/HIGH`; ≥30 → `CONFIRMED/CRITICAL`. No `REJECTED` verdict is issued — zero VT detections does not mean definitively benign.

- **Async sliding-window rate limiter** — `RateLimiter` tracks call timestamps in a 60-second deque and blocks callers (via `asyncio.sleep`) until a slot opens. Wired to VT's free-tier cap of 4 req/min. Transparent to callers: no exceptions, just latency. Verified live with a 5-IOC batch that triggered 7 total API calls (two CONFIRMED IOCs each added a relationship call) and completed cleanly in 62 seconds.

- **Per-case caching** — `(case_id, entity_type, entity_value)` cache on the agent instance ensures the same IOC is never sent to VT twice within a case, regardless of how many orchestrator rounds query it. Cache hits return the stored findings with the new `query_id` substituted in.

- **Graceful failure on every error path** — VT 429, 401, network timeout, and missing `VT_API_KEY` all produce `NOT_FOUND` with a descriptive `justification` string. The orchestrator loop continues normally; no exception propagates.

- **Test suite — 25 tests, all mocked** — 12 parametrised threshold tests, 3 pure `normalize()` unit tests (no I/O), and 10 async agent integration tests covering: CONFIRMED/CRITICAL hash, INCONCLUSIVE, NOT_FOUND clean IP, CONFIRMED domain with related entities, URL base64 encoding, NOT_APPLICABLE unsupported type, VT 429 handling, missing API key, cache hit (zero duplicate HTTP), and `enrich_batch` with 3 mixed entities.

- **Live smoke test** — validated against real VT API: EICAR hash returned CONFIRMED/CRITICAL (65/75 engines, threat label `virus.eicar/test`, sandbox verdicts from Zenbox and Lastline, first submission 2006, 5 contacted IPs as related entities); 8.8.8.8 returned NOT_FOUND with geolocation; 185.220.101.45 (Tor exit node) returned CONFIRMED/HIGH.

- **Test data** — all 10 mocked test cases have their inputs persisted under `tests/test-data/input/` and their exact outputs (produced by running the code) under `tests/test-data/output/`. The live smoke test input and output are stored separately under `ti-smoke-live/`.

---

## Files

| Path | Action | Description |
|---|---|---|
| `backbone/threat_intel/agent.py` | Implemented | Replaced stub with full `BaseForensicModule` subclass: `scan()` returns empty result; `query()` checks cache then calls VT; `enrich_batch()` fans out concurrently via `asyncio.gather`; per-case cache; graceful NOT_FOUND on all error paths |
| `backbone/threat_intel/vt_client.py` | Created | VT API v3 async client: `lookup()` per entity type, `fetch_related()` for relationship endpoint, `normalize()` converting raw attributes to `EntityFindings`; `_determine_verdict_severity()` with deterministic thresholds |
| `backbone/threat_intel/rate_limiter.py` | Created | Async sliding-window rate limiter: deque of monotonic timestamps, drops entries older than 60s, sleeps until a slot opens when at capacity |
| `backbone/threat_intel/__init__.py` | Unchanged | Already exported `ThreatIntelAgent` |
| `pyproject.toml` | Modified | Added `httpx>=0.27` to production dependencies |
| `tests/test_threat_intel.py` | Created | 25 tests: 12 parametrised verdict-threshold tests, 3 `normalize()` unit tests, 10 async agent integration tests (all HTTP mocked via `AsyncMock`) |
| `tests/test-data/input/threat-intell-input/ti_query_confirmed_hash.json` | Created | SHA256 EICAR hash query |
| `tests/test-data/input/threat-intell-input/ti_query_inconclusive_hash.json` | Created | Hash query with 2/80 VT detections |
| `tests/test-data/input/threat-intell-input/ti_query_clean_ip.json` | Created | IP query expected to return NOT_FOUND |
| `tests/test-data/input/threat-intell-input/ti_query_confirmed_domain.json` | Created | Domain query expected to return CONFIRMED/HIGH with related entities |
| `tests/test-data/input/threat-intell-input/ti_query_confirmed_url.json` | Created | URL query (exercises base64 encoding path) |
| `tests/test-data/input/threat-intell-input/ti_query_not_applicable_pid.json` | Created | PID query — NOT_APPLICABLE, no HTTP call made |
| `tests/test-data/input/threat-intell-input/ti_query_vt_429_error.json` | Created | Query that triggers VT rate-limit error path |
| `tests/test-data/input/threat-intell-input/ti_query_no_api_key.json` | Created | Query with no VT_API_KEY configured |
| `tests/test-data/input/threat-intell-input/ti_query_cache_hit.json` | Created | Two queries for same entity — verifies single HTTP call |
| `tests/test-data/input/threat-intell-input/ti_batch_enrichment.json` | Created | Batch input: 3 mixed entity types |
| `tests/test-data/input/threat-intell-input/ti_smoke_live.json` | Created | Live smoke test input: EICAR hash, 8.8.8.8, service.thedoctorswife.ca |
| `tests/test-data/output/threat-intell-tests/ti-confirmed-hash/findings.json` | Generated | CONFIRMED/CRITICAL — 45/72, threat label, sandbox verdicts, first-submission timestamp |
| `tests/test-data/output/threat-intell-tests/ti-inconclusive-hash/findings.json` | Generated | INCONCLUSIVE — 2/80 detections |
| `tests/test-data/output/threat-intell-tests/ti-clean-ip/findings.json` | Generated | NOT_FOUND — 0/90, geolocation evidence line |
| `tests/test-data/output/threat-intell-tests/ti-confirmed-domain/findings.json` | Generated | CONFIRMED/HIGH — 15/90, 2 related hash_sha256 entities |
| `tests/test-data/output/threat-intell-tests/ti-confirmed-url/findings.json` | Generated | CONFIRMED/HIGH — 10/80, URL entity type |
| `tests/test-data/output/threat-intell-tests/ti-not-applicable-pid/findings.json` | Generated | NOT_APPLICABLE — pid type rejected before any HTTP |
| `tests/test-data/output/threat-intell-tests/ti-vt-429-error/findings.json` | Generated | NOT_FOUND — justification contains rate-limit message |
| `tests/test-data/output/threat-intell-tests/ti-no-api-key/findings.json` | Generated | NOT_FOUND — justification: "VT_API_KEY not configured" |
| `tests/test-data/output/threat-intell-tests/ti-cache-hit/findings.json` | Generated | Two findings with matching verdict, differing query_ids |
| `tests/test-data/output/threat-intell-tests/ti-batch-enrichment/findings.json` | Generated | 3 findings: CONFIRMED/HIGH (IP), NOT_FOUND (domain), NOT_FOUND (unknown hash) |
| `tests/test-data/output/threat-intell-tests/ti-smoke-live/findings.json` | Generated | Live VT API output: EICAR CONFIRMED/CRITICAL, 8.8.8.8 NOT_FOUND, domain NOT_FOUND |
