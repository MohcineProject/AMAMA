# Detailed Technical Explanation: RAM Forensic Pipeline

## Design Philosophy

The pipeline is built on four principles:

1. **LLM-first, deterministic fallback** — Agents default to LLM reasoning. If the API is unavailable, deterministic rule-based logic takes over. The pipeline never blocks.

2. **Token efficiency through pre-filtering** — Raw Volatility files can be hundreds of thousands of lines. The pipeline does not send raw data to LLMs. Instead, the grep stage extracts only the lines relevant to suspicious PIDs, and agents receive compact, pre-processed context.

3. **Conservative bias** — The system is tuned to produce false negatives rather than false positives. Analyst trust is the primary asset; a missed finding is preferable to a noisy alert. Agent 2 only issues a CONFIRMED verdict when evidence is unambiguous.

4. **Evidence traceability** — Every finding cites verbatim lines from the original Volatility artifact files, with line numbers. An analyst can verify any claim by opening the source file. This carries through to `scan_result.json` and `EntityFindings` responses.

---

## Full Data Flow

```
┌─────────────────────────────────────────────────────────┐
│  INPUT  (prepared by DFIR-Collector)                    │
│                                                         │
│  RAM/INPUT/chunk_001.txt  …                             │
│    (FIND_EVIL collector format — one process per line,  │
│     split into up to 9 chunks)                          │
│                                                         │
│  RAM/RAM_Artifacts/*.txt                                │
│    (67 Volatility 3 artifact files)                     │
└─────────────────────────────────────────────────────────┘
                      │
                      │  run_pipeline.py loops over each chunk
                      ▼
         ┌────────────────────────────┐
         │  For each chunk_N.txt:     │
         │                            │
         │  [Agent 1: triage_agent]   │
         │      ↓ triage.txt          │
         │  [Grep:    pivot_grep]     │
         │      ↓ pivot.txt           │
         │  [Agent 2: pivot_analyst]  │
         │      ↓ analyst.txt         │
         └────────────────────────────┘
                      │
                      │  Aggregate all analyst.txt
                      ▼
         ┌────────────────────────────┐
         │  aggregated_analyst.txt    │
         │  (all chunks, with headers)│
         └────────────────────────────┘
                      │
                      │  scan_result_emitter (no LLM)
                      ▼
         ┌────────────────────────────┐
         │  scan_result.json          │
         │  (ModuleScanResult — for   │
         │   orchestrator consumption)│
         └────────────────────────────┘
```

Each chunk is processed independently through Agents 1 and 2. This isolation prevents cross-chunk hallucination: an LLM that has seen chunk 3 cannot retroactively color its reading of chunk 1.

---

## Input Format: FIND_EVIL Collector Chunks

Each `chunk_N.txt` is a subset of a full FIND_EVIL collector run. The format is one process per line:

```
# FIND_EVIL Collector — /path/to/image — 2026-05-16T20:22:41
pid=136 ppid=4 name=Registry path= cmd="" start=2026-05-13 19:14:00.000000 UTC dlls= nets= sids= privs=SeCreateTokenPrivilege;...;SeChangeNotifyPrivilege|Present,Enabled,Default;... handles=
pid=2380 ppid=4240 name=cmd.exe path=C:\WINDOWS\system32\cmd.exe cmd="C:\\WINDOWS\\system32\\cmd.exe /c \"...\"" start=2026-05-13 19:26:56.000000 UTC dlls=C:\WINDOWS\system32\cmd.exe;C:\WINDOWS\SYSTEM32\ntdll.dll;... nets= sids= privs=... handles=
```

| Field | Content |
|---|---|
| `pid` | Process ID |
| `ppid` | Parent process ID |
| `name` | Executable name (image filename) |
| `path` | Full path to the executable |
| `cmd` | Full command line |
| `start` | Process create time |
| `end` | Process exit time (if already exited) |
| `dlls` | Semicolon-separated DLL paths |
| `nets` | Semicolon-separated network connections |
| `sids` | Security identifiers |
| `privs` | Privilege list: `Name\|attrs;Name\|attrs;...` |
| `handles` | Handle information |

---

## Stage 1: Triage Agent (`scripts/triage_agent.py`)

### Role
Initial scan of all processes in a chunk. Flags suspicious ones with a severity rating and short reason tags. Broad by design — it generates candidates for Agent 2 to validate.

### Inputs
- One `chunk_N.txt` file from `INPUT/`
- `config.json` — suspicious keywords, directory patterns
- `whitelist.txt` — glob patterns for legitimate DLL/path locations
- `prompts/agent1_triage.md` — LLM system prompt

### Pre-processing (always runs, no LLM)

**Chunk parsing** — iterates each non-comment line, detects known field names as position markers, extracts values between consecutive pairs.

**Process tree construction** — indexes processes by PID and builds a PPID → [child PIDs] map.

**Structural anomaly detection** — three checks:
- **Spawn anomaly**: Office apps or browsers spawning shell interpreters
- **Privilege anomaly**: non-system process holding both SYSTEM SID and a user SID
- **Spawn volume**: a shell interpreter spawning more than 5 child processes

**Context construction** — builds a compact text block for the LLM: resolved parent names, start/exit times, command line, non-whitelisted DLLs, network connections, high-risk enabled privileges.

### LLM reasoning path

The LLM receives the compact context and `agent1_triage.md`, which instructs it to walk seven detection categories per process:

1. **Process identity and path** — typosquats, well-known names in wrong paths, hex-like executables, missing paths, orphaned PIDs
2. **Parent-child anomalies** — svchost not under services.exe, lsass not under wininit.exe, Office/browser → shell spawning
3. **LOLBin abuse** — certutil, mshta, regsvr32, bitsadmin, wmic, cscript, rundll32, msiexec
4. **Obfuscation signals** — `-Enc`, `-EncodedCommand`, IEX, DownloadString, Base64 blobs
5. **DLL provenance** — DLLs in Temp, AppData, Downloads from processes that should not load them
6. **Network anomalies** — non-server processes with external connections, suspicious ports
7. **SID/privilege signals** — SYSTEM SID on user-context process

**Signal stacking**: when weak signals from different categories converge on the same process, severity is raised one tier.

### Rule-based fallback (if LLM fails)

Scores each process:
- +3 for each suspicious keyword match in command line
- +2 for executable in a suspicious directory
- +2 for hex-like executable name

### Output: `triage.txt`

```
=== TRIAGE REPORT ===
Generated: 2026-05-17T14:32:07Z
Chunk: chunk_001.txt
Summary: Office spawn, encoded PS, LOLBin abuse

[PROCESS]
pid: 3412
ppid: 3120
image: powershell.exe
cmdline: powershell.exe -Enc SQBFAFgA...
severity: CRITICAL
reasons: parent_mismatch: WINWORD.EXE->powershell.exe | encoded_ps: -Enc + Base64
```

---

## Stage 2: Grep Pivot (`scripts/pivot_grep.py`)

### Role
Extract verbatim evidence from the 67 Volatility artifact files for each PID flagged by Agent 1. Zero LLM — pure deterministic grep with output capping.

### Why a separate grep stage?

1. **Integrity**: the grep stage reads unmodified source files. There is no risk of the LLM hallucinating evidence — Agent 2 can only cite lines that actually appear in the artifacts.
2. **Token control**: grepping 67 files would return thousands of lines. The capping system keeps only the most relevant lines in the LLM context.

### How grepping works

For each PID from `triage.txt`:
1. Compiles a word-boundary regex: `\b3412\b`
2. Iterates through the 20 files in `config.json`'s `pid_files`
3. Records line number and verbatim content as `L<N>: <line>`
4. Caps at `max_lines_per_file` (default 120) per file
5. Caps at `max_total_lines_per_target` (default 400) across all files for that PID

### Output: `pivot.txt`

```
=== PIVOT EVIDENCE REPORT ===

=== PID 3412 (powershell.exe, ppid=3120) ===
Cmdline: powershell.exe -Enc SQBFAFgA...

--- cmdline.txt ---
L542: 3412  powershell.exe  -Enc SQBFAFgA...

--- privileges.txt ---
L88: 3412  SeDebugPrivilege  Enabled

=== PID 3688 (a3f8c21d.exe, ppid=3412) ===
(no matching lines in any artifact file)
```

Empty blocks mean that PID appeared in no artifact files — a signal Agent 2 factors into its verdict.

---

## Stage 3: Pivot Analyst (`scripts/pivot_analyst.py`)

### Role
Pure reasoner. Reads Agent 1's suspicions alongside the actual grep evidence and decides for each finding: CONFIRMED, REJECTED, or INCONCLUSIVE. Does not gather new evidence — only interprets what the grep stage provided.

### Inputs
- `triage.txt` — what Agent 1 flagged and why
- `pivot.txt` — verbatim lines from the artifact files per PID
- `prompts/agent2_pivot.md` — LLM system prompt

### Context construction

Merges both TXT inputs into a structured block per PID:

```
=== TRIAGE FINDINGS TO VALIDATE ===
...

--- [PID 3412] powershell.exe (ppid=3120, Agent1 severity=CRITICAL) ---
  Cmdline: powershell.exe -Enc SQBFAFgA...
  Agent 1 reasons: parent_mismatch | encoded_ps
  [cmdline.txt] (1 hits):
    L542: 3412  powershell.exe  -Enc SQBFAFgA...
  [privileges.txt] (1 hits):
    L88: 3412  SeDebugPrivilege  Enabled
```

### The 9 reasoning lenses

The `agent2_pivot.md` prompt instructs the LLM to reason through each PID using nine lenses:

1. **Command-line plausibility** — encoded PS, download cradles, LOLBin patterns
2. **DLL provenance** — user-writable paths, random-named DLLs, side-loading
3. **Privilege footprint** — SeDebugPrivilege, SeTcbPrivilege, SeImpersonatePrivilege on non-system binaries
4. **Handle cross-references** — cross-process injection handles, suspicious mutexes, LSASS access
5. **Environment variables** — COR_PROFILER hijack, PYTHONPATH injection, unusual PATH prepends
6. **File/path corroboration** — presence in filescan, registry Run/RunOnce keys
7. **Code injection markers** — malfind RWX regions, unmapped PE headers, shellcode signatures
8. **Timeline coherence** — activity after ExitTime, DLL loads before CreateTime
9. **Group SID anomalies** — SYSTEM SID on user-context processes, unfamiliar account SIDs

**Conservative bias rules:**
- Empty grep block + weak original signal → almost always REJECTED or INCONCLUSIVE
- CONFIRMED requires clear, corroborating evidence across artifact types OR a single unambiguous indicator
- When rejecting, must explicitly name the legitimate behavior observed

### Verdict model

| Verdict | Criteria |
|---|---|
| **CONFIRMED** | Clear corroborating evidence across artifact types OR single unambiguous indicator |
| **INCONCLUSIVE** | Some signal present but insufficient to confirm or reject |
| **REJECTED** | Evidence shows legitimate behavior, OR empty grep block with weak original signal |

### Severity tiers (CONFIRMED only)

| Severity | Activity |
|---|---|
| LOW | Nuisance-grade: PUP, adware, telemetry beacon |
| MEDIUM | Reconnaissance, enumeration, pre-attack staging |
| HIGH | C2 communication, persistence mechanism, backdoor, reverse shell |
| CRITICAL | Credential dumping, ransomware, lateral movement, rootkit |

### Fallback behavior

If the LLM fails, writes a valid `analyst.txt` with `confirmed=0` and all findings as INCONCLUSIVE with the note "LLM unavailable — manual review required."

---

## Aggregation Step

After all chunks are processed, `run_pipeline.py` concatenates all `chunk_N/analyst.txt` files into `output/aggregated_analyst.txt`:

```
=== CHUNK 1: chunk_001.txt ===
<full contents of output/chunk_001/analyst.txt>

=== CHUNK 2: chunk_002.txt ===
<full contents of output/chunk_002/analyst.txt>
...
```

This is the human audit trail. The orchestrator reads it; analysts read it; no information is lost compared to per-chunk files.

---

## Scan Result Emitter (`scripts/scan_result_emitter.py`)

### Role
Converts `aggregated_analyst.txt` into `scan_result.json` matching the `ModuleScanResult` JSON schema. Called by `run_pipeline.py` directly after aggregation — no LLM, no subprocess, expected runtime < 2 seconds.

### Logic

1. Parses each `[CONFIRMED]` and `[INCONCLUSIVE]` block from the aggregated TXT using regex.
2. For each block builds a `finding` dict:
   - `finding_id`: `"ram-<chunk_label>-f<N>"`
   - `primary_entity`: `{type: "pid", value: "<pid>"}`
   - `related_entities`: extracts image_name, PPID, IPs, file paths, SIDs from Cmdline and Key Evidence lines
   - `mitre`: parsed MITRE technique codes from the MITRE field
   - `evidence`: each Key Evidence line → `{source_file, line, content, verbatim: true}`
3. Counts CONFIRMED/INCONCLUSIVE/REJECTED from block headers.
4. Writes the envelope with `contract_version`, `case_id`, `module`, timestamps, `summary`, `counts`, `findings`, `artifacts`.
5. Validates against `schemas/module_scan_result.schema.json` (best-effort; warns but does not abort on validation errors).

### Why no CLI?

This is an internal pipeline step. It is not invoked standalone by the user or the orchestrator — `run_pipeline.py` imports and calls `emit_scan_result()` directly. The orchestrator receives the finished `scan_result.json` file, not a subprocess invocation.

---

## Orchestrator Query Mode (`scripts/entity_query.py`)

### Role
Pivot-back entry point. Answers a single `EntityQuery` from the orchestrator by searching RAM artifacts for the requested entity and optionally calling the LLM to interpret the evidence.

### The 4-stage flow

**Stage 1 — Type dispatch**  
Checks if the entity type is supported. Returns `NOT_APPLICABLE` immediately for `hash_md5/sha1/sha256` (RAM artifacts carry no file hashes) and for unknown types.

**Stage 2 — Deterministic retrieval**  
Greps the relevant artifact files using a type-appropriate regex pattern. Returns `NOT_FOUND` if zero hits. Caps at `scope.max_evidence_lines` from the query (default 50).

**Stage 3 — Triviality / whitelist check**  
Only applied to `file_path` and `image_name`. Checks the value against `whitelist.txt`. If matched AND no suspicious indicators in the evidence (RWX, shellcode, malfind, high entropy, temp paths), returns `REJECTED` immediately without LLM call.

**Stage 4 — LLM interpreter**  
Calls `prompts/agentQ_focused.md` with the entity, orchestrator's `context.reason`, and retrieved evidence lines. Produces an `EntityFindings` JSON. Falls back to `INCONCLUSIVE` if `--no-llm` or LLM unavailable.

### Entity type → artifact file mapping

| Entity type | Pattern | Files |
|---|---|---|
| `pid` | word-boundary regex | `pid_files` (20 files) |
| `image_name` | case-insensitive substring | pslist, pstree, cmdline, psscan |
| `file_path` | case-insensitive, also matches basename | `path_files` (25+ files) |
| `ip` / `domain` | literal substring | netscan, netstat, cmdline, envars |
| `url` | literal substring | cmdline, envars |
| `registry_key` | case-insensitive | registry_printkey |
| `user_sid` | literal substring | getsids, privileges, sessions |
| `mutex` | literal substring | handles.txt (or NOT_APPLICABLE if absent) |

### EntityFindings output contract

```json
{
  "contract_version": "1.0",
  "query_id": "<from EntityQuery>",
  "responding_module": "ram",
  "entity": { "type": "...", "value": "..." },
  "verdict": "CONFIRMED|INCONCLUSIVE|REJECTED|NOT_FOUND|NOT_APPLICABLE",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|null",
  "mitre": ["T1059.001"],
  "justification": "1-4 sentences addressing context.reason",
  "evidence": [ { "source_file": "...", "line": N, "content": "...", "verbatim": true, "timestamp": null } ],
  "related_entities": [ { "type": "...", "value": "...", "relationship": "..." } ],
  "cost": { "llm_calls": 1, "tokens_in": 0, "tokens_out": 0 }
}
```

An audit trail is written to `output/queries/<query_id>.txt` for every query answered.

---

## agentQ_focused.md Prompt

A focused single-entity analyst prompt, scoped to one entity at a time (contrast with `agent2_pivot.md` which handles a full list of PIDs). Key properties:

- Conservative bias: CONFIRMED requires ≥ 2 independent RAM signals
- RAM-specific guidance: malfind RWX = injection signal; netscan ESTABLISHED to suspicious IP = C2 signal; DKOM (psscan hit without pslist hit) = rootkit signal; SeDebugPrivilege ENABLED on non-system process = credential dumper indicator
- Output is raw JSON only — no prose outside the JSON block
- `justification` must directly address `context.reason` from the orchestrator query

---

## LLM Configuration and Fallback Resolution (`scripts/llm_client.py`)

### `load_llm_config(path)`

Loads `llm_config.json` and resolves which provider config to actually use:

1. Checks primary provider: `api_key` field (if non-empty), then `os.environ[api_key_env]`
2. If no key found, iterates `fallback_providers` in order — uses the first one with a key
3. Returns the resolved config dict (fallback fields merged over primary; `fallback_providers` key removed)
4. If no key found anywhere, returns primary config — downstream will raise on first API call

### `call_chat(messages, config)`

Dispatches based on `provider`:
- **`anthropic`**: posts to `/v1/messages` with `x-api-key` + `anthropic-version` headers; extracts the system message from the messages list into the top-level `system` field; parses `content[0].text`
- **`openrouter` / `openai-compatible`**: posts to `/chat/completions` endpoint; parses `choices[0].message.content`

Both branches: automatic 429 retry up to `max_retries` times, with `_parse_retry_after()` for dynamic backoff.

### `extract_json(text)`

Handles three common LLM JSON return patterns: raw JSON, JSON in markdown code fences, JSON embedded in prose (brace-counting extraction). Used by Agent 1 (JSON output) and `entity_query.py` (EntityFindings JSON).

---

## Configuration Reference

### `config.json`

| Field | Default | Description |
|---|---|---|
| `input_dir` | `"../INPUT"` | Path to chunk files (relative to `ram-agentic-architecture/`) |
| `grep_input_dir` | `"../RAM_Artifacts"` | Path to Volatility artifact files |
| `max_lines_per_file` | 120 | Maximum grep hits per artifact file per PID |
| `max_total_lines_per_target` | 400 | Maximum grep hits across all files for one PID |
| `pid_files` | 20 files | Artifact files searched by PID (word-boundary match) |
| `path_files` | 25 files | Artifact files searched by path (case-insensitive) |
| `network_files` | 4 files | Artifact files for IP/domain entity queries |
| `registry_files` | 1 file | Artifact files for registry key entity queries |
| `sid_files` | 3 files | Artifact files for SID entity queries |
| `suspicious_keywords` | list | Command-line substrings for rule-based scoring |
| `suspicious_dirs` | list | Directory fragments for elevated scoring |

### `llm_config.json`

| Field | Description |
|---|---|
| `provider` | Primary provider: `anthropic`, `openrouter`, or `openai-compatible` |
| `api_base` | Full API endpoint URL |
| `model` | Model ID (e.g. `claude-opus-4-6`) |
| `api_key` | API key (leave blank to use env var) |
| `api_key_env` | Environment variable name for the key |
| `fallback_providers` | Ordered list of fallback configs; first one with a key is used |
| `temperature` | Sampling temperature (0.2 = low randomness) |
| `max_tokens` | Maximum tokens per LLM response (currently 30,000) |
| `max_retries` | Max 429 retry attempts before falling back (default: 5) |
| `verify_ssl` | Set to `false` for TLS-inspection proxy environments |

---

## Intermediate File Formats

Internal TXT format specifications are documented in `schemas/`:

| File | Schema document |
|---|---|
| `chunk_N/triage.txt` | `schemas/triage_output_format.md` |
| `chunk_N/pivot.txt` | `schemas/pivot_output_format.md` |
| `chunk_N/analyst.txt` | `schemas/pivot_analyst_output_format.md` |

Orchestrator JSON contract schemas (used for validation):

| Schema | Description |
|---|---|
| `schemas/entity_query.schema.json` | Inbound query from orchestrator |
| `schemas/entity_findings.schema.json` | Response from `entity_query.py` |
| `schemas/module_scan_result.schema.json` | Response from `run_pipeline.py` (scan_result.json) |

---

## Design Patterns Summary

**Chunk isolation**: Agents 1 and 2 run once per chunk. A process seen in chunk 3 cannot influence Agent 2's reading of chunk 1. Only the emitter sees the aggregated view.

**LLM JSON internal, TXT external**: Agent 1 asks the LLM to output JSON (structured, reliable) then converts it to human-readable TXT on disk. Agent 2 outputs TXT directly. `entity_query.py` and `scan_result_emitter.py` output JSON for the orchestrator.

**Read-only evidence**: No stage modifies the Volatility artifact files. All writes go to `output/`. This preserves chain-of-custody integrity.

**Graceful degradation**:
- Agent 1 LLM fails → rule-based scoring
- Agent 2 LLM fails → all INCONCLUSIVE
- `entity_query.py` LLM fails → INCONCLUSIVE with raw evidence
- `scan_result_emitter` never calls LLM — always produces output

**Audit trail**: Per-chunk TXT files + `aggregated_analyst.txt` + `scan_result.json` + `output/queries/<id>.txt` together constitute a complete audit trail. Any claim in `scan_result.json` or any `EntityFindings` response traces back to a specific line number in a specific Volatility artifact file.

**Orchestrator contract boundary**: The only outputs consumed by the orchestrator are `scan_result.json` (after pipeline run) and `EntityFindings` JSON (after each query). All internal TXT intermediates are for human review and debugging only.
