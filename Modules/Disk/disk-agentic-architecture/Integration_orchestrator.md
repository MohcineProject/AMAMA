# Disk Module — Orchestrator Integration

This document records the specific design choices made for the two CLI entry points
(`scan.py` and `query.py`) so they can be reviewed and adjusted before the orchestrator
integration test.

---

## Entry Point 1: `scan.py` — INITIAL mode

### Invocation
```bash
python scripts/scan.py \
  --case-id <case_id> \
  --out <output_dir> \
  [--base-dir <disk-agentic-architecture/>] \
  [--artifact-dir <Disk_Artifacts/>] \
  [--run-pipeline]   # optional: invoke run_pipeline.py first
  [--no-llm]         # pass to run_pipeline.py to skip LLM stages
```

Output: `<output_dir>/scan_result.json` matching `module_scan_result.schema.json`.

### How existing pipeline output is mapped to `ModuleScanResult`

#### Source priority
1. `output/analyst.txt` (Agent 2 validated) — preferred
2. `output/triage_combined.txt` (Agent 1 only, no pivot validation) — fallback
3. `output/triage.txt` (legacy single-agent) — last resort

#### Parsing `analyst.txt` blocks
The file contains `[CONFIRMED]` and `[INCONCLUSIVE]` blocks in this format:
```
[CONFIRMED]
---
Finding:    <N>
Type:       <type>
Key:        <key value>
Severity:   CRITICAL|HIGH|MEDIUM|LOW
MITRE:      T1105 — ...

Justification:
  ...

Key Evidence:
  - L<lineno>: <verbatim artifact line>
---
```

**Regex used:**
- Block split: `re.split(r"(?=\[(?:CONFIRMED|INCONCLUSIVE)\])", text)`
- Field extraction: `re.search(rf"^{name}:\s*(.+)$", chunk, re.MULTILINE)`
- Evidence: `re.search(r"Key Evidence:\s*\n(.*?)(?:\n-{40}|\Z)", chunk, re.DOTALL)`
- MITRE: `re.findall(r"T\d{4}(?:\.\d{3})?", mitre_raw)`

#### `primary_entity` type inference (from `Key:` field)
| Key pattern | Entity type |
|---|---|
| Starts with `HK(LM\|CU\|U\|CR\|CC)\` | `registry_key` |
| Starts with `http(s)://` | `url` |
| Matches IPv4 pattern | `ip` |
| Matches domain regex (`x.y.z`) | `domain` |
| Matches 32/40/64-char hex | `hash_md5` / `hash_sha1` / `hash_sha256` |
| Contains `\` or `/` | `file_path` |
| Has executable extension (`.exe` etc.) | `image_name` |
| Otherwise | `image_name` (safest fallback) |

#### Evidence items
Key Evidence lines with `L<N>: content` format are parsed as:
- `source_file: "analyst.txt"` (secondary output — line numbers reference original artifacts)
- `line`: extracted from `L<N>:` prefix
- `verbatim: true` (lines are verbatim citations from the pivot evidence)

**Limitation:** source_file is reported as "analyst.txt" rather than the original artifact
filename. The orchestrator can use the line content to cross-reference against
`artifacts.human_report` if it needs the true source. A future improvement would be
to look up line numbers from `output/pivot.txt` to get exact source file mapping.

#### `related_entities`
Currently empty (`[]`) — `scan.py` does not do secondary entity extraction.
The orchestrator will pivot back with `EntityQuery` for secondary entities it identifies
from the `justification` and `Key Evidence` content.

#### `artifacts` field
```json
"artifacts": { "human_report": "output/analyst.txt" }
```

---

## Entry Point 2: `query.py` — QUERY mode

### Invocation
```bash
python scripts/query.py \
  --query <entity_query.json> \
  --out   <entity_findings.json> \
  [--base-dir <disk-agentic-architecture/>] \
  [--artifact-dir <Disk_Artifacts/>] \
  [--no-llm]   # return INCONCLUSIVE with raw evidence, skip LLM
```

Output:
- `--out` path: `EntityFindings` JSON matching `entity_findings.schema.json`
- `output/queries/<query_id>.txt`: human-readable audit block

### Stage 1 — Type dispatch

| Entity type | Support level | Notes |
|---|---|---|
| `file_path` | Full | Searched in all artifact files |
| `image_name` | Full | Searched in MFT, execution, persistence, browser |
| `hash_md5` | Full | Searched in MFT, amcache, shimcache |
| `hash_sha1` | Full | Same |
| `hash_sha256` | Full | Same |
| `registry_key` | Full | Searched in `registry_autoruns.txt`, `registry_misc.txt`, scheduled tasks |
| `user_sid` | Full | Searched in all artifact files |
| `ip` | Best-effort | Searched in browser history, scheduled tasks, event logs |
| `domain` | Best-effort | Same |
| `url` | Best-effort | Searched in browser history, scheduled tasks |
| `pid` | NOT_APPLICABLE | Disk doesn't track runtime PIDs |
| `mutex` | NOT_APPLICABLE | Not recorded in disk artifacts |

### Stage 2 — Deterministic retrieval

**Grep patterns by entity type:**

| Type | Pattern strategy |
|---|---|
| `file_path` | Case-insensitive match of full path OR basename |
| `image_name` | Case-insensitive basename with delimiter boundaries (`[\s="'/\]`) |
| `hash_*` | Word-boundary match (`\b<hash>\b`) to prevent partial collisions |
| `registry_key` | Case-insensitive substring |
| `user_sid` | Case-insensitive substring |
| `ip/domain/url` | Case-insensitive substring |

**Artifact files searched per entity type:**

```
file_path    → ALL files (MFT, persistence, execution, browser, event logs)
image_name   → MFT + execution + persistence + browser
hash_*       → MFT + execution (amcache, shimcache, prefetch)
registry_key → persistence files only
user_sid     → ALL files
ip/domain    → browser + persistence + event logs
url          → browser + persistence
```

**Cap:** `scope.max_evidence_lines` (default 50). Returns `NOT_FOUND` if 0 hits.

### Stage 3 — Triviality / whitelist check

**Only applied to `file_path` and `image_name` types.**

1. Normalize the entity value: lowercase, `/` → `\`, strip leading drive letter (`c:\`).
2. Check if normalized path starts with any prefix in `config.json:mft_whitelist_path_prefixes`.
3. **Conservative escape hatches** — skip to Stage 4 if ANY evidence line matches:
   - `entropy=[7-9]\.\d` (entropy > 7.0 → potential packing)
   - `suspicious=true`
   - `malware`
   - `deleted=true` (deleted file in any associated artifact)
   - `appdata...temp` (execution from temp dir)
   - `recycle\.bin`

Returns `REJECTED` with up to 5 evidence lines when whitelist matches with no escape triggers.

**Current whitelist prefixes (from `config.json`):**
```
windows\system32   windows\syswow64   windows\winsxs   windows\assembly
windows\installer  windows\softwaredistribution   windows\servicing
windows\system32\driverstore   windows\system32\catroot
program files\microsoft        program files (x86)\microsoft
program files\windows defender program files (x86)\windows defender
program files\common files\microsoft   programdata\microsoft
```

### Stage 4 — Scoped LLM interpreter

**Prompt:** `prompts/agentQ_focused.md`

**User message structure:**
```
Entity type: <type>
Entity value: <value>

Reason for this query (from orchestrator):
<context.reason>

Retrieved evidence (<N> lines):
============================================================
[<source_file> L<line>] <content>
...
============================================================

Respond with a JSON block matching EntityFindings.
query_id must be: <query_id>
```

**JSON extraction:** `llm_client.extract_json()` — robust regex/JSON extraction from LLM response.

**Failure fallback:** If LLM call fails or JSON parsing fails → `INCONCLUSIVE` with raw evidence
preserved. The orchestrator must not crash when this module is unavailable.

**Cost reporting:** `cost.llm_calls` is set to 1 after a successful LLM call; 0 for stages 1–3.
`tokens_in` and `tokens_out` are set to 0 (the llm_client does not currently expose token counts
from the response object — this can be improved when the API response is parsed more deeply).

### Audit trail

For every query, `output/queries/<query_id>.txt` is written containing:
1. The full `EntityQuery` JSON
2. All retrieved evidence lines with `[source_file L<N>]` prefix
3. The LLM prompt (if LLM was called)
4. The raw LLM response (if LLM was called)
5. The final `EntityFindings` JSON

---

## Schema validation

Both entry points validate their output against the local `schemas/` copies of:
- `module_scan_result.schema.json`
- `entity_findings.schema.json`
- `entity_query.schema.json`

These are direct copies of `COMPLETE_ARCHITECTURE/schemas/`. They are NOT symlinks, so they
can survive the module being moved to a separate repo.

Validation uses `jsonschema.Draft7Validator`. If validation fails:
- `scan.py`: prints warnings, exits with code 1
- `query.py`: prints warnings but still writes the file (the pipeline must not crash)

---

## Dummy-data smoke tests (verified)

All tests run from `disk-agentic-architecture/` with `./../.venv/bin/python`.

### scan.py tests

```bash
# Create synthetic analyst.txt with 2 findings, run scan
cp /tmp/dummy_analyst.txt output/analyst.txt
python scripts/scan.py --case-id test-001 --out /tmp/scan_test_out/
# Result: scan_result.json produced, schema PASS
# CONFIRMED: 1, INCONCLUSIVE: 1
```

### query.py tests

| Test | Command | Expected verdict | Schema |
|---|---|---|---|
| Unsupported type (`pid`) | `--query query_pid.json` | `NOT_APPLICABLE` | PASS |
| Unknown value | `--query query_notfound.json` | `NOT_FOUND` | PASS |
| Real hit, no LLM | `--query query_hit.json --no-llm` | `INCONCLUSIVE` | PASS |
| Clean system file | `--query query_whitelist2.json --no-llm --artifact-dir /tmp/test_artifacts` | `REJECTED` | PASS |

### Whitelist edge case

`C:\Windows\System32\svchost.exe` against the real `Disk_Artifacts/` returns `INCONCLUSIVE`
(not REJECTED) because the MFT contains `deleted=true` for a related prefetch file
(`SVCHOST.EXE-7AC6742A.pf`). This is the correct conservative behavior — the deleted prefetch
triggers the escape hatch.

---

## Known limitations / future improvements

1. **`related_entities` not populated in `scan.py`** — secondary entity extraction from
   evidence lines (IPs, hashes, domains) is not yet implemented. The orchestrator will
   need to parse the `justification` text for entity candidates.

2. **`cost.tokens_in/tokens_out` always 0** — `llm_client.py` does not currently expose token
   counts from the API response. Wire up when needed.

3. **`evidence[].source_file` in `scan.py` is `"analyst.txt"`** — it should ideally be the
   original artifact filename. This requires cross-referencing with `output/pivot.txt` to map
   Key Evidence line numbers back to their source artifact file.

4. **No `python -m disk.scan` package invocation** — current entry points are `python scripts/scan.py`
   and `python scripts/query.py`. For proper `python -m disk.scan` support, create a `disk/`
   package at the repo root with `scan.py` and `query.py` as `__main__.py` delegates.
   This is a packaging concern only, not a logic change.

5. **SQLECmd and LECmd not yet tested** — requires the NTFS volume to be mounted at
   `/tmp/dfir_ntfs`. Run `sudo python disk-image-mounter/mount_image.py` first. These tools
   would enrich browser history (Edge/Firefox via SQLECmd) and LNK file artefacts (LECmd).
