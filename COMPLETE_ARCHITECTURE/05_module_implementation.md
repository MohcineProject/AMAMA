# 05 — Module implementation guide (generic)

This document defines what **every** module must implement to be a peer in the system. It is module-agnostic — RAM, disk, and network all follow the same outline.

For RAM-specific deltas see `06_ram_module_changes.md`. For the disk team's checklist see `07_disk_module_spec.md`.

## The two entry points

Every module must expose two callable interfaces. CLI scripts are fine; both can be the same Python entry file if you prefer.

### Entry point 1: `scan` (INITIAL mode)

```
python -m <module>.scan \
  --case-id <case_id> \
  --out <output_dir>
```

- Triggered by the orchestrator at case start.
- Runs the module's full pipeline (e.g., RAM's `run_pipeline.py`, disk's MFT/USN/registry analysis, network's pcap processing).
- Emits exactly **one** file: `<output_dir>/scan_result.json` matching `module_scan_result.schema.json`.
- Optionally writes other audit-trail files (e.g., RAM's per-chunk `analyst.txt`); these are referenced from `scan_result.json.artifacts`.

### Entry point 2: `query` (QUERY mode)

```
python -m <module>.query \
  --query <path_to_entity_query.json> \
  --out <path_to_entity_findings.json>
```

- Triggered by the orchestrator any time it wants to ask about a specific entity.
- Reads an `EntityQuery` JSON.
- Emits exactly **one** file: the `EntityFindings` JSON matching `entity_findings.schema.json`.
- Also writes a TXT audit block to `output/queries/<query_id>.txt`.

A module that doesn't yet handle a given entity type returns `verdict: NOT_APPLICABLE` immediately (no work done). This is a valid first-week implementation — you can ship the query entry point handling only a subset of entity types, and expand coverage over time.

## What the query entry point does internally

This is the four-stage flow from `03_pivot_back.md`, made concrete:

```python
def handle_query(query: EntityQuery) -> EntityFindings:
    # Stage 1: type dispatch
    retriever = RETRIEVERS.get(query["entity"]["type"])
    if retriever is None:
        return _make_findings(
            query, verdict="NOT_APPLICABLE",
            justification=f"This module does not handle entity type '{query['entity']['type']}'",
            evidence=[], related_entities=[], cost=ZERO_COST
        )

    # Stage 2: deterministic retrieval
    evidence = retriever(query["entity"]["value"], scope=query.get("scope", {}))
    if not evidence:
        return _make_findings(
            query, verdict="NOT_FOUND",
            justification="No matching lines in any artifact",
            evidence=[], related_entities=[], cost=ZERO_COST
        )

    # Stage 3: triviality / whitelist check
    if _is_trivially_benign(query["entity"], evidence):
        return _make_findings(
            query, verdict="REJECTED",
            justification="Entity matches whitelist for known-benign artifacts",
            evidence=evidence[:5],  # show the whitelist match
            related_entities=[],
            cost=ZERO_COST
        )

    # Stage 4: scoped LLM interpreter
    return _llm_interpret(query, evidence)
```

You don't have to literally write this Python — your language and structure can differ — but every module must implement the same stage sequence.

## What goes in each stage (per module)

### Stage 1: type dispatch

Define a static map of supported entity types to retrieval strategies. Unsupported types short-circuit to `NOT_APPLICABLE`. See each module spec for its specific map.

### Stage 2: retrieval

Deterministic. No LLM. Reads only the module's own artifact files. Returns a list of evidence dicts:

```python
[
  {"source_file": "...", "line": int, "content": str, "verbatim": True, "timestamp": str | None},
  ...
]
```

Cap at `scope.max_evidence_lines` (default 50). RAM uses `grep_file_for_pattern` from `utils.py` and a configurable per-file/per-PID cap — that pattern is reusable for any module.

### Stage 3: triviality check

Module-specific. Conservative — if there's any reason for doubt, skip and proceed to stage 4. Examples:

- **RAM:** path matches `whitelist.txt` AND there are no other suspicious indicators in the retrieved lines (no `-Enc`, no foreign IPs, no `SeDebugPrivilege` on a non-system process).
- **Disk:** file is signed by a trusted publisher AND signature is valid AND no anomalous registry references.
- **Network:** IP/domain is in an internal allowlist AND no high-entropy/low-reputation subdomain pattern.

A `REJECTED` from this stage must still include the whitelist evidence (e.g., the line showing the path matched System32) so an analyst can verify.

### Stage 4: scoped LLM interpreter

The module's "mini Agent 2" — one entity, one verdict. Inputs:

- `entity` (type + value)
- `context.reason` from the `EntityQuery`
- the retrieved `evidence[]`

System prompt requirements (every module must enforce):

1. The LLM may only cite evidence that was passed in. Citing anything else is a contract violation.
2. The LLM may only add `related_entities[]` that appear in the retrieved evidence lines.
3. Conservative bias: when in doubt between CONFIRMED and INCONCLUSIVE, pick INCONCLUSIVE.
4. The justification must answer `context.reason` specifically, not generically.
5. Output must conform to `entity_findings.schema.json`.

If the LLM call fails (rate limit, timeout, network), fall back to `verdict: INCONCLUSIVE` with `justification: "LLM unavailable — manual review required"` and the raw evidence preserved. This mirrors the existing pattern in `pivot_analyst.py`.

## What the scan entry point does internally

This is module-specific. Each module already has its own pipeline today (or will have). The new requirement is to emit `scan_result.json` at the end.

Suggested approach: a thin emitter script that wraps the existing pipeline. RAM's `scan_result_emitter.py` will:

1. Parse `aggregated_analyst.txt` (or the new structured equivalent) for each `[CONFIRMED]` and `[INCONCLUSIVE]` block.
2. Extract primary entity (PID) and related entities (image name from `Image:`, IP from `Cmdline:` / `Key Evidence`).
3. Format each as a finding object per `module_scan_result.schema.json`.
4. Write `scan_result.json`.

The emitter does **not** re-run the pipeline. It only restructures already-produced output.

## File layout (recommended, not required)

Inside a module repo:

```
<module>/
├── scripts/
│   ├── scan.py              # entry point 1: scan
│   ├── query.py             # entry point 2: query
│   └── (existing pipeline scripts)
├── prompts/
│   ├── (existing prompts)
│   └── agentQ_focused.md    # the scoped interpreter prompt
├── schemas/                 # symlink or pinned copy from Cyber-contracts/
│   ├── entity_query.schema.json
│   ├── entity_findings.schema.json
│   └── module_scan_result.schema.json
├── output/
│   ├── scan_result.json     # produced by scan
│   ├── queries/             # produced by query
│   │   ├── <query_id>.txt   # audit block
│   │   └── <query_id>.json  # findings
│   └── (existing audit artifacts)
└── README.md
```

## Validation requirements

Every module **must**:

1. Validate inbound `EntityQuery` against `entity_query.schema.json` before processing. Reject with `verdict: NOT_APPLICABLE` and `justification: "invalid EntityQuery"` if validation fails.
2. Validate outbound `EntityFindings` against `entity_findings.schema.json` before writing. If validation fails, this is a bug — log loudly and write a fallback INCONCLUSIVE.
3. Validate outbound `ModuleScanResult` against `module_scan_result.schema.json` before writing.

Suggested: use `jsonschema` (Python) or equivalent. Validation runs in <10ms and catches contract drift early.

## Cost reporting

Every `EntityFindings` must populate `cost`:

```json
{ "llm_calls": <int>, "tokens_in": <int>, "tokens_out": <int> }
```

When no LLM fires (stages 1–3), all three are 0. When the interpreter fires, populate from the LLM provider's response.

The orchestrator may aggregate these to print a per-case cost summary at the end.

## What you can reuse from the RAM repo

If your module is starting from scratch, these patterns transfer directly:

- `agentic-architecture/scripts/utils.py::grep_file_for_pattern` — capped line grep
- `agentic-architecture/scripts/utils.py::is_whitelisted_path` — glob-style whitelist check (for stage 3)
- `agentic-architecture/scripts/llm_client.py` — multi-provider LLM client with retries and 429 handling
- `agentic-architecture/scripts/llm_client.py::extract_json` — robust LLM JSON output extraction
- The shape of `agent2_pivot.md` as a starting template for `agentQ_focused.md`

The disk and network repos may copy these files or import them; either is fine. They are not part of the contract — they are reference implementations.
