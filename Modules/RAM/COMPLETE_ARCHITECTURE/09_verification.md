# 09 — Verification

How we know the architecture works end-to-end. Each test below has: what it covers, who runs it, and how to know it passed.

## Test 1 — Schema contract test

**Covers:** the three JSON schemas are well-formed and the example envelopes in `02_contracts.md` validate against them.

**Who runs it:** `Cyber-contracts/` CI on every PR. Also run by each module in its own CI on the pinned copy.

**How to know it passed:**

```bash
cd Cyber-contracts/
python -m pytest tests/test_validate.py
```

Expected: all `tests/fixtures/valid_*.json` pass validation; all `tests/fixtures/invalid_*.json` are rejected.

**Specific fixtures to include:**

- `valid_query.json` — the example from `02_contracts.md` §1
- `valid_findings.json` — the example from `02_contracts.md` §2
- `valid_scan_result.json` — the example from `02_contracts.md` §3
- `invalid_query_missing_contract_version.json`
- `invalid_findings_confirmed_without_severity.json` — confirms the conditional severity rule
- `invalid_query_bad_uuid.json`
- `invalid_findings_severity_on_rejected.json` — severity should be null for non-CONFIRMED

## Test 2 — RAM smoke test (refactor regression)

**Covers:** after the RAM refactor (per `06_ram_module_changes.md`), the existing TXT outputs are byte-identical (modulo timestamps and LLM variance).

**Who runs it:** RAM team CI, once after the refactor lands.

**How to know it passed:**

```bash
cd Cyber-agent/agentic-architecture/

# Before refactor (snapshot)
python scripts/run_pipeline.py --use-llm --out output_before/

# After refactor
python scripts/run_pipeline.py --case-id test-case --use-llm --out output_after/

# Compare the audit-trail TXT files
diff -r output_before/chunk_001/ output_after/chunk_001/
diff output_before/aggregated_analyst.txt output_after/aggregated_analyst.txt
```

Expected: identical per-chunk files; identical aggregated TXT (modulo timestamps).

Also: `output_after/scan_result.json` exists, validates against `module_scan_result.schema.json`, and the findings counts match the `Counts:` line in `aggregated_analyst.txt`.

`output_after/report.md` should **not** exist (Stage 4 removed from RAM).

## Test 3 — RAM query test (one-entity pivot)

**Covers:** `entity_query.py` produces correct verdicts for known-suspicious entities from the existing fixtures.

**Who runs it:** RAM team CI.

**How to know it passed:**

Given the existing fixture (the 9 chunks in `INPUT/` and 67 files in `Grep_input/`), and assuming the canonical "evil case" includes a CONFIRMED finding for PID 3412 (powershell.exe, encoded -Enc command), then:

```bash
# Construct a query for PID 3412
cat > /tmp/q.json <<'EOF'
{
  "contract_version": "1.0",
  "query_id": "00000000-0000-4000-8000-000000000001",
  "round": 1,
  "case_id": "test-case",
  "target_module": "ram",
  "entity": { "type": "pid", "value": "3412" },
  "context": {
    "source_module": "orchestrator",
    "source_finding_id": "test",
    "reason": "Confirm whether this process executed a suspicious encoded PowerShell payload"
  }
}
EOF

python scripts/entity_query.py --query /tmp/q.json --out /tmp/r.json

# Assertions:
jq -r '.verdict' /tmp/r.json                  # → CONFIRMED
jq -r '.severity' /tmp/r.json                 # → HIGH or CRITICAL
jq '.evidence | length' /tmp/r.json            # → > 0
jq -r '.evidence[].verbatim' /tmp/r.json       # → all true
jq '.related_entities | length' /tmp/r.json    # → > 0 (should include image_name=powershell.exe)
```

Additional cases:

- **`NOT_FOUND` case:** query for `{"type": "pid", "value": "999999"}` → assert `verdict: NOT_FOUND`, `evidence: []`, `cost.llm_calls: 0`.
- **`NOT_APPLICABLE` case:** query for `{"type": "hash_sha256", "value": "abcd..."}` → assert `verdict: NOT_APPLICABLE`, `cost.llm_calls: 0`.
- **Whitelisted REJECT case:** query for a known System32 binary path → assert `verdict: REJECTED`, `cost.llm_calls: 0`, evidence shows whitelist match.

## Test 4 — Cross-module integration (mocked)

**Covers:** the orchestrator's loop wires modules and TI together correctly.

**Who runs it:** orchestrator team CI.

**How to know it passed:**

Use mock modules that return canned `ModuleScanResult` and `EntityFindings`:

- Mock RAM emits one CONFIRMED finding with `primary_entity = {type: "pid", value: "3412"}` and `related_entities = [{type: "image_name", value: "powershell.exe"}, {type: "ip", value: "1.2.3.4"}]`.
- Mock disk emits zero initial findings. Answers an `EntityQuery` for `image_name=powershell.exe` with `NOT_APPLICABLE` and for `ip` with `NOT_APPLICABLE`.
- Mock network emits zero initial findings. Answers an `EntityQuery` for `ip=1.2.3.4` with `verdict: CONFIRMED`, `severity: HIGH`, `related_entities: [{type: "domain", value: "evil.example.com"}]`.
- Mock TI returns `{type: "hash_sha256", value: "abc"}` for `image_name=powershell.exe` (system file, REJECTED) and CONFIRMED for `ip=1.2.3.4` with `related_entities: [{type: "domain", value: "evil.example.com"}]`.

Expected: orchestrator runs 2 rounds, picks up `domain=evil.example.com` in round 2 from both network and TI (dedup applies), no new entities in round 3, terminates by convergence. Final `report.md` mentions the IP, the domain, the PID, and the image.

Test assertions:

```python
assert case_state["rounds"][-1]["new_entities_added"] == 0  # convergence
assert ("ip", "1.2.3.4") in case_state["entities"]
assert ("domain", "evil.example.com") in case_state["entities"]
assert any(f["verdict"] == "CONFIRMED" for f in case_state["entities"][("ip", "1.2.3.4")]["verdicts_received"])
```

## Test 5 — Loop termination test

**Covers:** `max_rounds` hard cap fires even when entities keep being added.

**Who runs it:** orchestrator team CI.

**How to know it passed:**

Use a mock TI that, for each entity it's enriched with, returns 50 new `related_entities` (synthetic IOC campaign). The loop would never converge naturally.

Expected: orchestrator runs exactly `max_rounds` (default 5) rounds and stops. The termination reason in `case_state.json` should be `"max_rounds_reached"`, not `"convergence"`.

## Test 6 — Timeline ordering

**Covers:** the final report orders events chronologically using `evidence[].timestamp` when available, falling back to first-seen order when not.

**Who runs it:** orchestrator team CI.

**How to know it passed:**

Construct three mocked findings:

- A: timestamp `2026-05-13T19:14:00Z` (Registry process creation)
- B: timestamp `2026-05-13T19:26:58Z` (PowerShell -Enc command)
- C: no timestamp (network connection, RAM didn't surface a time)

Expected order in the report's "Attack Timeline" section: A → B → C (timestamps first in chronological order; untimestamped events follow in first-seen order).

## Test 7 — Graceful TI failure

**Covers:** when TI's external provider is down/rate-limited, the loop continues without crashing.

**Who runs it:** orchestrator team CI.

**How to know it passed:**

Mock TI raises `ProviderUnavailable` for one specific IP. The TI implementation must catch this and return `verdict: NOT_FOUND` with `justification` explaining the failure.

Expected: orchestrator does not crash; the case completes; the affected IP appears in the report's "Confidence Assessment" section with a note that external enrichment was unavailable.

## Test 8 — Contract version handling

**Covers:** modules reject envelopes with unknown contract versions.

**Who runs it:** each module CI.

**How to know it passed:**

```bash
cat > /tmp/q_future.json <<'EOF'
{
  "contract_version": "99.0",
  "query_id": "00000000-0000-4000-8000-000000000001",
  "round": 1,
  "case_id": "test",
  "target_module": "ram",
  "entity": { "type": "pid", "value": "1" },
  "context": { "source_module": "orchestrator", "source_finding_id": "t", "reason": "test" }
}
EOF

python scripts/entity_query.py --query /tmp/q_future.json --out /tmp/r.json

# Assertion:
jq -r '.verdict' /tmp/r.json                  # → NOT_APPLICABLE
jq -r '.justification' /tmp/r.json | grep -i version  # justification mentions version
```

## Test 9 — Validation rejects malformed envelopes

**Covers:** modules don't process invalid envelopes.

**Who runs it:** each module CI.

**How to know it passed:**

Send an `EntityQuery` missing `entity.type`. Expected: module returns `verdict: NOT_APPLICABLE`, `justification: "invalid EntityQuery"` (or equivalent), no other side effects (no LLM call, no audit file beyond the error block).

## End-to-end acceptance

The system is "done" for v1 when:

1. Tests 1–9 all pass in CI.
2. A real case (e.g., one of the existing FIND_EVIL test corpora) runs end-to-end through the orchestrator, produces a `report.md`, and a human analyst reviewing the report finds it equivalent in quality to today's RAM-only report — plus disk findings — plus at least one cross-module pivot that wouldn't have been possible before.
3. Total wall-clock for a 9-chunk RAM + medium-disk-image case is under 10 minutes with `--use-llm`.
4. Total LLM token spend for the same case is documented and tracked round-by-round in `case_state.json`.
