# Disk Module — Architecture

---

## Overview

The Disk module is a three-layer pipeline. Each layer's output is the next layer's input:

```
[E01/EWF Disk Image]
        │
        ▼  Layer 1 — disk-image-mounter/
[config.json]  (mount points, partition offsets, artifact paths)
        │
        ▼  Layer 2 — disk-collector/
[Disk_Artifacts/*.txt]  (normalized KEY=VALUE artifact records)
        │
        ▼  Layer 3 — disk-agentic-architecture/
[output/analyst.txt]  (AI-generated findings with verbatim evidence)
        │
        ▼  Orchestrator entry points: scan.py / query.py
[ModuleScanResult JSON / EntityFindings JSON]
        │
        ▼  Backbone Orchestrator
```

---

## Layer 1 — Disk Image Mounter

**Entry point:** `disk-image-mounter/mount_image.py`

### What it does

1. Mounts the EWF/E01 image via `ewfmount` FUSE at `/tmp/dfir_ewf`
2. Discovers the Windows NTFS partition using `mmls` (partition table) and `fsstat` (filesystem type detection)
3. Handles bare-partition images (whole-device E01 with no partition table)
4. Detects BitLocker-encrypted volumes and emits a clear error
5. Mounts the NTFS volume read-only at `/tmp/dfir_ntfs` using the kernel `ntfs3` driver (falls back to `ntfs-3g` if needed)
6. Extracts `$MFT` via `icat` to `/tmp/test_raw_mft`
7. Discovers the Windows username by scanning `Users/` (skips service accounts: `.NET*`, `NetworkService`, `LocalService`, `systemprofile`, `MSSQL*`, `IIS*`)
8. Probes for `Amcache.hve` with both case variants (`AppCompat/` and `appcompat/`)
9. Writes `config.json` — a complete, ready-to-use collector configuration

### config.json generation

`config.json` is regenerated on every mount. It merges:
- Auto-discovered values: mount points, volume paths, partition offsets, username, amcache path
- Analyst-customizable defaults from `disk-collector/config.example.json`: `mft_exclude_paths`, `mft_exclude_extensions`, `suspicious_paths`, `zimmerman_tools`, whitelist prefixes, etc.

**To persist custom tuning** (e.g. custom `suspicious_paths`), edit `disk-collector/config.example.json` — those values survive every remount.

---

## Layer 2 — Disk Collector

**Entry point:** `disk-collector/disk_collector.py`

### Sub-collectors

| Collector key | File | Output file(s) | Zimmerman tool | Python fallback |
|---|---|---|---|---|
| `mft` | `mft_collector.py` | `mft_records.txt` | MFTECmd | `analyzeMFT` + `pytsk3` |
| `zregistry` | `zimmerman_registry_collector.py` | `registry_autoruns.txt`, `registry_misc.txt` | RECmd | `python-registry` |
| `zevtx` | `zimmerman_eventlog_collector.py` | `eventlog_security.txt`, `eventlog_system.txt`, `eventlog_application.txt`, `eventlog_other.txt` | EvtxECmd | `python-evtx` |
| `zexecution` | `zimmerman_execution_collector.py` | `registry_shimcache.txt`, `amcache_records.txt` | AppCompatCacheParser + AmcacheParser | `python-registry` + binary struct |
| `persistence` | `persistence_collector.py` | `scheduled_tasks.txt`, `wmi_subscriptions.txt` | — | pure Python (XML/WMI parsing) |
| `browser` | `browser_collector.py` | `browser_history.txt` | SQLECmd | `python-evtx` |

All collectors share a uniform `KEY=VALUE` record format defined in `_common.py`. Every record begins with a `type=` field followed by artifact-specific fields, and a normalized ISO8601 UTC timestamp.

### Parallel phase architecture

```
Phase 1 (parallel, blocking):    persistence + browser + zexecution + zregistry
Phase 2 (parallel, background):  mft + zevtx
```

Phase 1 artifacts are written to disk while Phase 2 (MFT parse and event log extraction — the slow collectors) runs in background threads. Sentinel files `.phase1_done` / `.phase2_done` are written to the output directory on completion so callers can poll or watch for readiness.

### CLI flags

| Flag | Effect |
|---|---|
| `--fast` | Default. MFT limited to suspicious paths only, PE entropy analysis skipped |
| `--full` | Complete MFT parse + PE entropy analysis (slower, more thorough) |
| `--only <keys>` | Run specific collectors sequentially (backward-compatible) |
| `--workers N` | Thread count for parallel phases (default: CPU count) |
| `--check-deps` | Print dependency status table and exit |

### Python fallback mode

When .NET or Zimmerman tools are unavailable, all three Zimmerman collectors fall back to pure-Python implementations automatically. A one-time startup warning is printed. Coverage differences:
- `zevtx` fallback: main Security/System/Application logs only; archive `.evtx` files skipped
- `zregistry` fallback: Run keys, services, Winlogon from SOFTWARE/SYSTEM/NTUSER.DAT
- `zexecution` fallback: shimcache limited to Win10/11 `CACHE` magic format; amcache via `InventoryApplicationFile` hive keys

---

## Layer 3 — Agentic Pipeline

**Entry point:** `disk-agentic-architecture/scripts/run_pipeline.py`

### Pipeline stages

```
Stage 1: preprocess.py
    Reads Disk_Artifacts/*.txt
    Applies whitelist policy, publisher rules, event deduplication, MFT anomaly scoring
    Writes TRIAGE_INPUT_PERSISTENCE.txt, TRIAGE_INPUT_EVENTS.txt, TRIAGE_INPUT_MFT.txt
         │
         ▼
Stage 2: triage_agent.py (×3, run sequentially)
    --mode persistence → agent1_persistence.md → triage_persistence.txt
    --mode events      → agent1_events.md      → triage_events.txt
    --mode mft         → agent1_mft.md         → triage_mft.txt
    Merge step → triage_combined.txt  (findings prefixed P/E/M for source traceability)
         │
         ▼
Stage 3: pivot_search.py
    For each [FINDING] in triage_combined.txt, grep the Key field across all Disk_Artifacts/*.txt
    Retrieves verbatim artifact lines with [source_file L<N>] prefixes
    Writes output/pivot.txt
         │
         ▼
Stage 4: pivot_analyst.py  (agent2_pivot.md)
    Validates triage findings against pivot evidence
    Assigns CONFIRMED / INCONCLUSIVE / REJECTED verdicts
    Writes output/analyst.txt
```

### MFT anomaly scoring (Stage 1)

`preprocess.py` assigns a score to every MFT record before sending to the triage agent:

| Signal | Points |
|---|---|
| Executable extension in suspicious path | +4 |
| Entropy > 7.0 (possible packing) | +3 |
| SI/FN timestamp delta > threshold | +3 |
| Timestamp within attack window | +2 |
| File in `$Recycle.Bin` | +2 |
| Missing `Zone.Identifier` ADS on downloaded-looking file | +2 |
| NSRL match (known-good hash) | −5 |
| Deep path under system directories | +1 |

Only the top-N records by score (default 200) reach the LLM. Filtered records go to `output/audit/mft_filtered.jsonl`.

### Verdict model

- **CONFIRMED** — corroborating evidence across at least two independent artifact types
- **INCONCLUSIVE** — some signal, insufficient to confirm or rule out
- **REJECTED** — evidence shows legitimate behavior, or no corroborating evidence found

Single-artifact findings must never be CONFIRMED. The pipeline is biased toward false negatives over false positives.

---

## Prompt Files

| File | Stage | Domain |
|---|---|---|
| `prompts/agent1_persistence.md` | Triage | Registry autoruns, scheduled tasks, WMI, shimcache, amcache, prefetch, browser delivery |
| `prompts/agent1_events.md` | Triage | Authentication, logon patterns, privilege escalation, lateral movement, log clearing |
| `prompts/agent1_mft.md` | Triage | MFT structural anomalies, entropy, timestomping, Zone.Identifier, deleted files |
| `prompts/agent2_pivot.md` | Analyst | Evidence synthesis, cross-artifact verdict building, narrative |
| `prompts/agentQ_focused.md` | Query | Entity-focused evidence interpretation for `query.py` responses |

---

## Orchestrator Integration

Two CLI entry points connect the module to the Backbone orchestrator.

### `scan.py` — INITIAL mode

```bash
python scripts/scan.py \
  --case-id <case_id> \
  --out <output_dir>/ \
  [--base-dir <disk-agentic-architecture/>] \
  [--artifact-dir <Disk_Artifacts/>] \
  [--run-pipeline]   # optionally invoke run_pipeline.py first
  [--no-llm]         # pass through to run_pipeline.py
```

**Output:** `<output_dir>/scan_result.json` — validated against `module_scan_result.schema.json`.

**Parsing `analyst.txt`:** `scan.py` splits the file into `[CONFIRMED]` and `[INCONCLUSIVE]` blocks and maps each to a `ModuleScanResult` entity. The `primary_entity` type is inferred from the `Key:` field:

| Key pattern | Entity type |
|---|---|
| Starts with `HK(LM\|CU\|U\|CR\|CC)\` | `registry_key` |
| Starts with `http(s)://` | `url` |
| Matches IPv4 | `ip` |
| Matches domain pattern (`x.y.z`) | `domain` |
| 32/40/64-char hex | `hash_md5` / `hash_sha1` / `hash_sha256` |
| Contains `\` or `/` | `file_path` |
| Has executable extension | `image_name` |
| Otherwise | `image_name` (safe fallback) |

**Evidence traceability:** Agent 2 (`agent2_pivot.md`) is instructed to prefix every Key Evidence line with `[artifact_filename.txt L<N>]`. The `_parse_evidence_lines()` function in `scan.py` extracts the filename and line number from this prefix and sets `source_file` to the original artifact (e.g. `registry_shimcache.txt`). Legacy analyst.txt files without the prefix fall back to `source_file="analyst.txt"`.

**`related_entities`:** Not yet populated — secondary entity extraction from evidence text is not implemented. The orchestrator pivots back with `EntityQuery` calls for entities it identifies from the justification and evidence.

---

### `query.py` — QUERY mode

```bash
python scripts/query.py \
  --query <entity_query.json> \
  --out   <entity_findings.json> \
  [--base-dir <disk-agentic-architecture/>] \
  [--artifact-dir <Disk_Artifacts/>] \
  [--no-llm]   # return INCONCLUSIVE with raw evidence, skip LLM
```

**Output:** `EntityFindings` JSON validated against `entity_findings.schema.json`. Audit trail written to `output/queries/<query_id>.txt` (full query, retrieved evidence, LLM prompt/response, final result).

**Four-stage processing:**

1. **Type dispatch** — check if entity type is supported, best-effort, or not applicable for disk artifacts
2. **Deterministic retrieval** — grep across artifact files using type-specific patterns (case-insensitive, word-boundary matched for hashes). Capped at `scope.max_evidence_lines` (default 50). Returns `NOT_FOUND` if 0 hits.
3. **Whitelist check** — for `file_path` and `image_name` only: if the path starts with a known-good prefix (Windows system dirs, Microsoft Program Files), return `REJECTED` unless any evidence line triggers a conservative escape hatch (entropy > 7.0, `suspicious=true`, `deleted=true`, execution from temp dir, Recycle.Bin).
4. **LLM interpretation** — `agentQ_focused.md` prompt with all retrieved evidence. Failure fallback: `INCONCLUSIVE` with raw evidence (the orchestrator must not crash when this module is unavailable).

**Supported entity types:**

| Entity type | Support | Artifact files searched |
|---|---|---|
| `file_path` | Full | All files |
| `image_name` | Full | MFT + execution + persistence + browser |
| `hash_md5/sha1/sha256` | Full | MFT + execution (amcache, shimcache, prefetch) |
| `registry_key` | Full | `registry_autoruns.txt`, `registry_misc.txt`, scheduled tasks |
| `user_sid` | Full | All files |
| `ip` / `domain` | Best-effort | Browser + persistence + event logs |
| `url` | Best-effort | Browser + persistence |
| `pid` / `mutex` | NOT_APPLICABLE | Not recorded in disk artifacts |

---

## Schema Contracts

Schema files live at `Backbone/schemas/` (project root), shared with the RAM module. `scan.py` resolves the path at runtime by walking up from `__file__` to the project root.

- `module_scan_result.schema.json` — output of `scan.py`
- `entity_findings.schema.json` — output of `query.py`
- `entity_query.schema.json` — input to `query.py`

Validation uses `jsonschema.Draft7Validator`. `scan.py` exits with code 1 on validation failure; `query.py` logs a warning but still writes the file.

---

## Data Flow & Traceability

Every finding in the final JSON traces back through the pipeline:

```
Disk artifact file (verbatim line)
  → mft_records.txt L1842: type=mft path=C:\ProgramData\... suspicious=true
        │
        ▼ pivot_search.py greps this key
  → output/pivot.txt: [mft_records.txt L1842] type=mft path=...
        │
        ▼ pivot_analyst.py cites this
  → output/analyst.txt Key Evidence: L1842: type=mft path=...
        │
        ▼ scan.py maps evidence line
  → scan_result.json evidence[].verbatim=true line=1842
```

This traceability is enforced at the prompt level — triage agents must cite source lines in `reasons:`, and the analyst agent must cite `Key Evidence:` lines verbatim. The `scan.py` parser preserves those citations into the structured output.

---

## Known Limitations

| Item | Status |
|---|---|
| `python -m disk.scan` package invocation | Not yet implemented; entry points remain `python scripts/scan.py` / `python scripts/query.py` |
|Future improvement:  SQLECmd / LECmd integration | Available in Zimmerman install but not yet wired into collectors |
