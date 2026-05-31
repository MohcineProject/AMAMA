# 07 — Disk module spec (for the disk team)

This document is your checklist. It does **not** prescribe how your pipeline works internally — that's your call. It only specifies what your module must read and emit so it can plug into the orchestrator.

If you also want to understand the wider system, start with `01_architecture.md`. The minimum required reading to implement your adapter is this file + `02_contracts.md` + `05_module_implementation.md`.

## What you have to deliver

Two CLI entry points, three JSON files, one prompt.

### CLI entry point 1: `scan`

A script that runs your full disk forensic pipeline and emits `scan_result.json`.

```
python -m disk.scan \
  --case-id <case_id> \
  --out <output_dir>
```

- Reads your existing disk artifacts (MFT, USN journal, $LogFile, registry hives, prefetch, browser history, event logs, whatever your current pipeline produces).
- Runs your existing analysis logic (whatever you have today).
- Writes one file: `<output_dir>/scan_result.json` matching `module_scan_result.schema.json`.
- May write any number of audit-trail files alongside; reference them from `scan_result.json.artifacts`.

### CLI entry point 2: `query`

A script that answers a single `EntityQuery`.

```
python -m disk.query \
  --query <path_to_entity_query.json> \
  --out <path_to_entity_findings.json>
```

- Reads an `EntityQuery` from disk.
- Implements the four-stage flow from `03_pivot_back.md`.
- Writes the `EntityFindings` JSON at `--out` and a TXT audit block at `output/queries/<query_id>.txt`.

### Files

- `output/scan_result.json` (produced by entry point 1) — matches `module_scan_result.schema.json`
- `output/queries/<query_id>.json` (produced by entry point 2) — matches `entity_findings.schema.json`
- `output/queries/<query_id>.txt` (audit-trail companion, human-readable)

### Prompt

`prompts/agentQ_focused.md` (or your language's equivalent) — the scoped LLM interpreter prompt. Skeleton in `06_ram_module_changes.md` works as a starting point; adapt the rules section to disk-specific evidence patterns.

## Entity types you must handle

Required for v1 (must produce a useful verdict, not `NOT_APPLICABLE`):

| Type | Why you own this | Notes |
|---|---|---|
| `file_path` | You have authoritative file metadata (size, MAC times, signature, hash) | Stage 2 retrieval = MFT lookup + filescan |
| `image_name` | Same as file_path but by name | May resolve to multiple paths; return them all in `related_entities` |
| `hash_md5` / `hash_sha1` / `hash_sha256` | You compute these from the file | Stage 2 = hash table lookup; orchestrator wants you first for hash queries |
| `registry_key` | You read hives | Stage 2 = registry hive parse + grep |
| `user_sid` | SAM/SECURITY hive data | |

Recommended for v1 (handle if your pipeline naturally surfaces them):

| Type | Strategy |
|---|---|
| `pid` | `NOT_APPLICABLE` is fine — disk doesn't track runtime PIDs |
| `ip` / `domain` / `url` | Look in browser history, hosts file, scheduled tasks, registry. If your tools don't surface these, return `NOT_APPLICABLE`. |
| `mutex` | `NOT_APPLICABLE` is fine |

## Entity-type → suggested retrieval (disk)

This is a suggestion, not a contract. You know your tools better.

| Entity type | Suggested artifacts to grep / query |
|---|---|
| `file_path` | MFT records, filescan output, $LogFile, prefetch (file references), USN journal entries, registry references |
| `image_name` | MFT (by name), prefetch (one prefetch file per binary executed), Amcache, Shimcache |
| `hash_*` | Hash tables you precompute during scan, VirusShare-style lookups, NSRL whitelists |
| `registry_key` | Parsed hives, AutoRuns-style export, RegRipper output |
| `user_sid` | SAM hive, SECURITY hive, ProfileList, event log Security records |
| `ip` / `domain` / `url` | Browser history DBs, hosts file, scheduled tasks XML, registry IP entries (e.g., RDP MRU) |

## Triviality / whitelist policy (your stage 3)

The disk-side benign signals are stronger than RAM's because you can verify file signatures. Suggested:

- **Strong REJECT** (stage 3, no LLM):
  - File is signed with a valid Authenticode signature from a known trusted publisher (Microsoft, Apple, Mozilla, Google, etc.)
  - AND no anomalous registry persistence references to the file
  - AND the file's MAC times are consistent with its install / patch cycle

- **Otherwise → stage 4 LLM**

The LLM still needs to interpret cases where a signed legitimate binary is being abused (e.g., LOLBin paths — a signed `rundll32.exe` executing a payload). The whitelist is only for "the file itself is unambiguously what it claims to be."

## Best-effort linkage (what to populate in `related_entities`)

Whatever your pipeline naturally produces. Examples:

- File path → related `image_name`, `hash_sha256`, registry persistence keys, parent directory, owner SID
- Registry key → related `file_path` (the value's binary), responsible user SID, last-write timestamp's account context
- Hash → file paths it appears at, related signing certificate (as a `domain` or `image_name` if useful)

Do not do extra work to compute linkages your pipeline doesn't naturally surface. The orchestrator will pivot back with an `EntityQuery` if it wants more.

## Validation and error handling

Before you write any envelope:

1. Validate against the schema using `jsonschema` or equivalent.
2. If your generation logic produced an invalid envelope, that's a bug — log it loudly and fall back to a safe `INCONCLUSIVE` response with `justification: "internal validation failure"`.
3. On any internal exception (file not found, parse error, etc.), still emit a valid `EntityFindings`. Use `verdict: INCONCLUSIVE` with `justification` explaining the failure mode. **The pipeline must never crash the orchestrator's loop.**

## Cost reporting

Even when you don't call an LLM, emit `cost: {"llm_calls": 0, "tokens_in": 0, "tokens_out": 0}`. The orchestrator's per-case cost summary depends on every module reporting honestly.

## What you reuse from `Cyber-contracts/`

```
pip install cyber-contracts  # or equivalent
```

The package exposes:

- The three JSON schemas
- Python type hints / TypedDict definitions for the three envelopes
- A validate-or-raise helper: `validate_query(d)`, `validate_findings(d)`, `validate_scan_result(d)`
- The closed enum lists (entity types, verdicts, severities) as Python constants

You pin a version (e.g., `cyber-contracts==1.0.*`). When 1.1 ships with new entity types or fields, you decide when to upgrade.

## Concrete first sprint (suggested)

If you're starting from a working disk pipeline today:

| Day | Task |
|---|---|
| 1 | Write `scan_result_emitter` for your existing pipeline output. Validate against schema. |
| 2 | Stub `query.py` with stage 1 (type dispatch) and `NOT_APPLICABLE` for everything. Validates the contract end-to-end with a mock orchestrator. |
| 3–4 | Implement retrievers (stage 2) for `file_path`, `image_name`, `hash_*`. |
| 5 | Implement triviality check (stage 3) using your signature-verification logic. |
| 6–7 | Implement the LLM interpreter (stage 4) with `agentQ_focused.md`. Reuse RAM's `llm_client.py` if helpful. |
| 8 | Add retrievers for `registry_key`, `user_sid`. |
| 9 | End-to-end test against the orchestrator integration stub. |
| 10 | Polish + docs. |

**Total: ~2 weeks** for one engineer, assuming the disk pipeline itself is already working.

## What the orchestrator will and will not send you

It will:
- Send queries with `target_module: "disk"` only when an entity type matches your routing priority (see `04_orchestrator_and_ti.md`'s routing table).
- Honor your `NOT_APPLICABLE` responses by not retrying you for that entity type in the same case.
- Throttle per-round queries (default 30 per round across all modules combined).

It will not:
- Send you queries with `target_module` other than `"disk"`.
- Send you the same `(entity.type, entity.value)` twice in the same case.
- Care about your internal pipeline structure or your tool choices.
