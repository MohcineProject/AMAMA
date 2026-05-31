# 06 — RAM module changes

The internal RAM pipeline does **not change**. What changes is a thin adapter layer that makes RAM speak the contract. This document is the action list for the RAM refactor lead.

## What stays unchanged

- The 9-chunk loop in `scripts/run_pipeline.py`
- Agent 1 (`scripts/triage_agent.py`) and `prompts/agent1_triage.md`
- The deterministic grep stage (`scripts/pivot_grep.py`)
- Agent 2 (`scripts/pivot_analyst.py`) and `prompts/agent2_pivot.md`
- Per-chunk TXT outputs: `output/chunk_N/triage.txt`, `pivot.txt`, `analyst.txt`
- `output/aggregated_analyst.txt` (audit-trail concatenation)
- Configuration: `config.json`, `llm_config.json`, `whitelist.txt`
- The schemas in `schemas/*.md` (kept for human-readable internal documentation)
- `scripts/llm_client.py`, `scripts/utils.py`
- All fallback paths (rule-based scoring in Agent 1, "all INCONCLUSIVE" in Agent 2)

If you `run_pipeline.py --use-llm` after this refactor, every existing TXT output is byte-identical to today (modulo timestamps and LLM variance).

## What is removed

- `scripts/report_agent.py` — **deleted from RAM**. The final report is now produced by the orchestrator at the end of the loop, over the full case state.
- `prompts/agent3_report.md` — **deleted**.
- `schemas/report_output_format.md` — **deleted** (moves to the orchestrator repo).
- The `Stage 4: Report Writer` call in `run_pipeline.py` — **removed**. The pipeline stops after the aggregation step.

## What is added

### 1. `scripts/scan_result_emitter.py` (new)

Wraps the existing pipeline output and emits `ModuleScanResult` JSON.

**Inputs:**
- `output/aggregated_analyst.txt` (existing)
- `--case-id <id>` flag

**Output:**
- `output/scan_result.json` matching `module_scan_result.schema.json`

**Logic:**
1. Parse each `[CONFIRMED]` and `[INCONCLUSIVE]` block from the aggregated TXT (re-use the regex from the old `report_agent.py::extract_blocks` — it can be lifted before deletion).
2. For each block, extract:
   - PID → `primary_entity = {type: "pid", value: <pid>}`
   - Image name → `related_entities[]` with `relationship: "process_image"`
   - PPID → `related_entities[]` with `relationship: "parent_pid"` (if present in the block header)
   - IPs in `Cmdline:` and `Key Evidence:` lines → `related_entities[]` with `relationship: "outbound_or_listening"`
   - File paths in `Cmdline:` and `Key Evidence:` → `related_entities[]` with `relationship: "referenced_path"`
   - SIDs from privileges/SIDs evidence → `related_entities[]` with `relationship: "process_owner"` or `"granted_sid"`
   - URLs → `related_entities[]` with `relationship: "referenced_url"`
   - Each `Key Evidence` line → `evidence[]` entry with `source_file` taken from the artifact filename in the line (e.g., `--- cmdline.txt ---` headers in the pivot output)
3. Best-effort timestamps: try to parse from `start=` fields in the original FIND_EVIL chunk lines, or from evidence lines that contain ISO-8601 timestamps. Leave `null` otherwise.
4. Write `scan_result.json`.

This script does **not** re-run any LLM. It only restructures already-produced output. Expected runtime: <2 seconds.

### 2. `scripts/entity_query.py` (new)

The pivot-back entry point. Implements the four-stage flow from `03_pivot_back.md` and `05_module_implementation.md`.

**Inputs:**
- `--query <path>` — path to an `EntityQuery` JSON file
- `--out <path>` — where to write the `EntityFindings` JSON

**Output:**
- The `EntityFindings` JSON at `--out`
- A TXT audit block at `output/queries/<query_id>.txt`

**Internal structure:**

```python
RETRIEVERS = {
    "pid":           _retrieve_by_pid,          # reuse pivot_grep logic
    "image_name":    _retrieve_by_image_name,
    "file_path":     _retrieve_by_file_path,
    "ip":            _retrieve_by_ip,
    "domain":        _retrieve_by_domain,
    "url":           _retrieve_by_url,
    "registry_key":  _retrieve_by_registry_key,
    "user_sid":      _retrieve_by_user_sid,
    # types not handled by RAM:
    "hash_md5":      None,  # → NOT_APPLICABLE
    "hash_sha1":     None,
    "hash_sha256":   None,
    "mutex":         _retrieve_by_mutex,  # only if handles.txt exists; else None
}
```

Each `_retrieve_by_*` function returns a list of evidence dicts (see `05_module_implementation.md`). All of them are thin wrappers around `utils.py::grep_file_for_pattern` with module-appropriate file lists and regex patterns. See §"Entity-type → retrieval map" below.

The triviality check (stage 3) reuses `utils.py::is_whitelisted_path` against `whitelist.txt`.

The LLM interpreter (stage 4) reuses `llm_client.py::call_chat` with the new `agentQ_focused.md` prompt.

### 3. `prompts/agentQ_focused.md` (new)

A smaller version of `agent2_pivot.md`, scoped to one entity instead of a list of PIDs. Skeleton:

```markdown
# Focused Entity Analyst

You are validating ONE entity at a time. Read the EntityQuery context.reason
to understand what the orchestrator is asking. Cite only the evidence passed
to you — never invent. Add to related_entities only what appears in evidence.

# Verdict rules
- CONFIRMED: clear evidence supports the suspicion implied by context.reason
- INCONCLUSIVE: some signal, but insufficient to confirm or reject
- REJECTED: evidence positively shows benign behavior; explain what behavior

Conservative bias: when uncertain between CONFIRMED and INCONCLUSIVE, pick
INCONCLUSIVE. False negatives are preferable to false positives.

# Output format
A single JSON object matching entity_findings.schema.json. No prose outside
the JSON.

# Fields you write
- verdict
- severity (only when verdict=CONFIRMED)
- mitre[] (only techniques you can specifically map; empty otherwise)
- justification (1-4 sentences, must address context.reason)
- evidence[] (the lines you used; verbatim; subset of what was passed in)
- related_entities[] (only entities appearing in the evidence)

# What you must NOT do
- Cite evidence that wasn't in the input
- Claim CONFIRMED on a single weak signal
- List related_entities not in the evidence
```

Token budget target: ~2k context, ~500 output. Smaller than Agent 2's prompt because the input is smaller.

### 4. `schemas/` — JSON schemas added

Pin the three contract schemas from `Cyber-contracts/`:

```
schemas/
├── triage_output_format.md           # existing
├── pivot_output_format.md            # existing
├── pivot_analyst_output_format.md    # existing
├── entity_query.schema.json          # NEW — copied/pinned from Cyber-contracts/
├── entity_findings.schema.json       # NEW
└── module_scan_result.schema.json    # NEW
```

When `Cyber-contracts/` bumps a version, you update these three files.

## Update to existing files

### `scripts/run_pipeline.py`

- **Remove** the Stage 4 (report agent) call and its CLI flag handling.
- **Add** a call to `scan_result_emitter.py` at the end, passing the `--case-id` it received from the orchestrator.
- **Add** a `--case-id <id>` argument (required when run by orchestrator, optional with a default for local testing).

The CLI surface becomes:

```
python scripts/run_pipeline.py \
  --case-id <id> \
  --use-llm \
  [--config PATH] [--llm-config PATH] [--out DIR]
```

### `config.json`

No required changes. Optionally, add new file lists for the pivot retrievers if you find that the existing `pid_files` / `path_files` lists are missing files needed by IP / domain / registry retrievers:

- For `ip` / `domain` retrieval: `netscan.txt`, `netstat.txt`, `cmdline.txt`, `envars.txt`
- For `registry_key` retrieval: `registry_printkey.txt`, `registry_*.txt`
- For `user_sid` retrieval: `getsids.txt` (if produced by your Volatility runs), `privileges.txt`, `sessions.txt`

Suggest adding:

```json
"network_files": ["netscan.txt", "netstat.txt", "cmdline.txt", "envars.txt"],
"registry_files": ["registry_printkey.txt"],
"sid_files": ["getsids.txt", "privileges.txt", "sessions.txt"]
```

Missing files are skipped silently — same behavior as today.

## Entity-type → retrieval map (RAM)

| Entity type | Strategy | Files |
|---|---|---|
| `pid` | word-boundary regex `\b{pid}\b` | `pid_files` (existing 20) |
| `image_name` | case-insensitive substring | `pslist.txt`, `pstree.txt`, `cmdline.txt`, `psscan.txt` |
| `file_path` | case-insensitive substring | `path_files` (existing 25): `dlllist.txt`, `ldrmodules.txt`, `malfind.txt`, `vadinfo.txt`, `cmdline.txt`, registry_*.txt |
| `ip` / `domain` | literal substring (escape regex metachars) | `netscan.txt`, `netstat.txt`, `cmdline.txt`, `envars.txt` |
| `url` | literal substring | `cmdline.txt`, `envars.txt`, malfind dumps if available |
| `registry_key` | case-insensitive substring of the key path | `registry_printkey.txt`, `registry_*.txt` |
| `user_sid` | literal substring of the SID string | `getsids.txt`, `privileges.txt`, `sessions.txt` |
| `mutex` | literal substring | `handles.txt` (if present); else return `NOT_APPLICABLE` |
| `hash_md5` / `hash_sha1` / `hash_sha256` | `NOT_APPLICABLE` (RAM artifacts don't carry file hashes) | — |

The retrievers all share a 1-line core: `grep_file_for_pattern(file, pattern, max_lines)` from `utils.py`. Cap at `scope.max_evidence_lines` from the inbound query, falling back to `config.json::max_total_lines_per_target` (default 400).

## Removal checklist

When the refactor lands, run:

```bash
git rm agentic-architecture/scripts/report_agent.py
git rm agentic-architecture/prompts/agent3_report.md
git rm agentic-architecture/schemas/report_output_format.md
```

And update the README / `How_to_use_it.md` / `Detailed_explanation.md` to remove references to Stage 4 / `report.md`. The "final output" of the RAM module is now `output/scan_result.json` (machine) + `output/aggregated_analyst.txt` (human audit).

## Estimated effort

- `scan_result_emitter.py`: ~150 LOC, ~1 day with tests
- `entity_query.py` (8 retrievers, dispatch, audit writer): ~400 LOC, ~2 days with tests
- `agentQ_focused.md` prompt: ~1 day to draft + tune against fixtures
- Updates to `run_pipeline.py` and config: ~half day
- Removal of report agent and docs cleanup: ~half day
- Integration smoke test with the orchestrator stub: ~1 day

**Total: ~1 week** for one engineer who knows the codebase.
