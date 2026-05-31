# Detailed Technical Explanation: Cyber-Agent Forensic Pipeline

## Design Philosophy

The pipeline is built on four principles:

1. **LLM-first, deterministic fallback** — Agents default to LLM reasoning. If the API is unavailable, deterministic rule-based logic takes over. The pipeline never blocks.

2. **Token efficiency through pre-filtering** — Raw Volatility files can be hundreds of thousands of lines. The pipeline does not send raw data to LLMs. Instead, the grep stage extracts only the lines relevant to suspicious PIDs, and agents receive compact, pre-processed context.

3. **Conservative bias** — The system is tuned to produce false negatives rather than false positives. Analyst trust is the primary asset; a missed finding is preferable to a noisy alert. Agent 2 only issues a CONFIRMED verdict when evidence is unambiguous.

4. **Evidence traceability** — Every finding in the final report cites verbatim lines from the original Volatility artifact files, with line numbers. An analyst can verify any claim by opening the source file.

---

## Full Data Flow

```
┌──────────────────────────────────────────────────┐
│  INPUT  (prepared by upstream project)           │
│                                                  │
│  Cyber_agent/INPUT/chunk_001.txt  ...            │
│    (FIND_EVIL collector format — one process     │
│     per line, split into 9 chunks)               │
│                                                  │
│  Cyber_agent/Grep_input/*.txt                    │
│    (67 Volatility 3 artifact files)              │
└──────────────────────────────────────────────────┘
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
                      │
                      ▼
         ┌────────────────────────────┐
         │  [Agent 3: report_agent]   │
         │      ↓ report.md           │
         └────────────────────────────┘
```

Each chunk is processed independently through Agents 1 and 2. This isolation prevents cross-chunk hallucination: an LLM that has seen chunk 3 cannot retroactively color its reading of chunk 1.

---

## Input Format: FIND_EVIL Collector Chunks

Each `chunk_N.txt` is a subset of a full FIND_EVIL collector run. The format is one process per line (indented children are trimmed during parsing):

```
# FIND_EVIL Collector — /path/to/image — 2026-05-16T20:22:41
pid=136 ppid=4 name=Registry path= cmd="" start=2026-05-13 19:14:00.000000 UTC dlls= nets= sids= privs=SeCreateTokenPrivilege;...;SeChangeNotifyPrivilege|Present,Enabled,Default;... handles=
pid=2380 ppid=4240 name=cmd.exe path=C:\WINDOWS\system32\cmd.exe cmd="C:\\WINDOWS\\system32\\cmd.exe /c \"...\"" start=2026-05-13 19:26:56.000000 UTC dlls=C:\WINDOWS\system32\cmd.exe;C:\WINDOWS\SYSTEM32\ntdll.dll;... nets= sids= privs=... handles=
```

Field meanings:

| Field | Content |
|---|---|
| `pid` | Process ID |
| `ppid` | Parent process ID |
| `name` | Executable name (image filename) |
| `path` | Full path to the executable |
| `cmd` | Full command line (double-quoted) |
| `start` | Process create time |
| `end` | Process exit time (if already exited) |
| `dlls` | Semicolon-separated DLL paths loaded by the process |
| `nets` | Semicolon-separated network connections |
| `sids` | Security identifiers associated with the process |
| `privs` | Privilege list: `Name|attrs;Name|attrs;...` where attrs is `Present,Enabled,Default` etc. |
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

**Chunk parsing** (`parse_input_chunk`)  
Iterates each non-comment line. Detects known field names (`pid`, `ppid`, `name`, `path`, `cmd`, `dlls`, `nets`, `sids`, `privs`, `handles`) as position markers and extracts the value between each consecutive pair. This handles values containing spaces (e.g. timestamps) without splitting on them.

**Process tree construction** (`_build_process_tree`)  
Indexes processes by PID and builds a PPID → [child PIDs] map for parent-child lookups.

**Structural anomaly detection** (`_extract_anomalies`)  
Three checks:
- **Spawn anomaly**: Office apps or browsers spawning shell interpreters (cmd.exe, powershell.exe, wscript.exe, mshta.exe, rundll32.exe)
- **Privilege anomaly**: A non-system process holding both the SYSTEM SID (S-1-5-18) and a user SID (S-1-5-21) simultaneously — token impersonation signal
- **Spawn volume**: A shell interpreter spawning more than 5 child processes — unusual for interactive use

**Context construction** (`_build_llm_context`)  
Builds a compact text block — not the raw chunk text — for the LLM:
- Lists each process with parent name resolved, start/exit times, command line
- Filters DLLs: only non-whitelisted (non-System32) paths are shown
- Includes network connections and high-risk enabled privileges (SeDebugPrivilege, SeTcbPrivilege, SeImpersonatePrivilege, SeLoadDriverPrivilege, etc.)
- Appends the pre-computed anomaly list as confirmed starting points

### LLM reasoning path

The LLM receives the compact context and `agent1_triage.md`, which instructs it to walk seven detection categories per process:

1. **Process identity and path** — typosquats, well-known names in wrong paths, hex-like executables, missing paths, orphaned PIDs
2. **Parent-child anomalies** — svchost not under services.exe, lsass not under wininit.exe, Office/browser → shell spawning
3. **LOLBin abuse** — certutil, mshta, regsvr32, bitsadmin, wmic, cscript, rundll32, msiexec patterns
4. **Obfuscation signals** — `-Enc`, `-EncodedCommand`, IEX, DownloadString, Net.WebClient, Base64 blobs
5. **DLL provenance** — DLLs in Temp, AppData, Downloads from processes that should not load them
6. **Network anomalies** — non-server processes with external connections, suspicious ports (4444, 1337, 31337), listening processes
7. **SID/privilege signals** — SYSTEM SID on user-context process

**Signal stacking**: when weak signals from different categories converge on the same process, severity is raised one tier.

The LLM outputs a JSON object internally (reliable for structured parsing). The `write_triage_txt()` function converts this to the key:value TXT format on disk.

### Rule-based fallback (if LLM fails)

Scores each process:
- +3 for each suspicious keyword match in command line
- +2 for executable in a suspicious directory
- +2 for hex-like executable name (`[a-f0-9]{8+}.exe`)

Produces a valid `triage.txt` without LLM access, with coarser results.

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
reasons: parent_mismatch: WINWORD.EXE->powershell.exe | encoded_ps: -Enc + Base64 | foreign_ip: 185.220.101.45:443

[PROCESS]
...
```

---

## Stage 2: Grep Pivot (`scripts/pivot_grep.py`)

### Role
Extract verbatim evidence from the 67 Volatility artifact files for each PID flagged by Agent 1. Zero LLM — pure deterministic grep with output capping.

### Why a separate grep stage?

1. **Integrity**: The grep stage reads unmodified source files. There is no risk of the LLM hallucinating evidence — Agent 2 can only cite lines that actually appear in the artifacts.
2. **Token control**: Grepping 67 files for multiple PIDs would return thousands of lines. The capping system keeps only the most relevant lines in the LLM context.

### How grepping works

For each PID from `triage.txt`:
1. Compiles a word-boundary regex: `\b3412\b` — matches `3412` as a whole token, not as part of `23412`
2. Iterates through the 20 files in `config.json`'s `pid_files`: pslist, cmdline, privileges, dlllist, envars, pstree, psscan, netscan, netstat, threads, thrdscan, malfind, malware_malfind, ldrmodules, malware_ldrmodules, vadwalk, vadinfo, malware_pebmasquerade, malware_hollowprocesses, sessions
3. For each hit: records line number and verbatim content as `L<N>: <line>`
4. Caps at `max_lines_per_file` (default 120) per file
5. Caps at `max_total_lines_per_target` (default 400) across all files for that PID

### Output: `pivot.txt`

```
=== PIVOT EVIDENCE REPORT ===
Generated: 2026-05-17T14:33:00Z

=== PID 3412 (powershell.exe, ppid=3120) ===
Cmdline: powershell.exe -Enc SQBFAFgA...

--- cmdline.txt ---
L542: 3412  powershell.exe  -Enc SQBFAFgA...

--- privileges.txt ---
L88: 3412  SeDebugPrivilege  Enabled

=== PID 3688 (a3f8c21d.exe, ppid=3412) ===
(no matching lines in any artifact file)

=== END OF PIVOT REPORT ===
```

Empty blocks (no matching lines) mean that PID appeared in no artifact files — a signal Agent 2 factors into its verdict.

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
  Agent 1 reasons: parent_mismatch: WINWORD.EXE->powershell.exe | encoded_ps
  [cmdline.txt] (1 hits, showing 1):
    L542: 3412  powershell.exe  -Enc SQBFAFgA...
  [privileges.txt] (1 hits, showing 1):
    L88: 3412  SeDebugPrivilege  Enabled
```

A per-PID line budget (`max_lines_per_target`, default 40) keeps the LLM context manageable.

### The 9 reasoning lenses

The `agent2_pivot.md` prompt instructs the LLM to reason through each PID using nine lenses:

1. **Command-line plausibility** — encoded PS, download cradles, LOLBin patterns
2. **DLL provenance** — user-writable paths, random-named DLLs, side-loading patterns
3. **Privilege footprint** — SeDebugPrivilege, SeTcbPrivilege, SeImpersonatePrivilege, SeLoadDriverPrivilege on non-system binaries
4. **Handle cross-references** — cross-process injection handles, suspicious mutexes, registry autorun handles, LSASS access
5. **Environment variables** — COR_PROFILER hijack, PYTHONPATH injection, unusual PATH prepends
6. **File/path corroboration** — presence in filescan (or absence indicating deleted file), registry Run/RunOnce keys pointing at the binary
7. **Code injection markers** — malfind RWX regions, unmapped PE headers in heap, shellcode signatures
8. **Timeline coherence** — activity after ExitTime, DLL loads before CreateTime (contradictions indicating manipulation)
9. **Group SID anomalies** — SYSTEM SID on user-context processes, unfamiliar account SIDs

**Conservative bias rules:**
- Empty grep block + weak original signal → almost always REJECTED or INCONCLUSIVE, never CONFIRMED
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

### Output: `analyst.txt`

```
================================================================
FIND_EVIL — PIVOT REPORT
Generated: 2026-05-17T14:34:00Z
Summary: Critical severity incident — encoded PS dropper confirmed with registry persistence.
Counts: confirmed=2  inconclusive=1  rejected=3
================================================================

[CONFIRMED]
----------------------------------------------------------------
PID:      3412
PPID:     3120
Image:    powershell.exe
Cmdline:  powershell.exe -Enc SQBFAFgA... [download cradle pattern]
Severity: HIGH
MITRE:    T1059.001 — PowerShell

Justification:
  Spawned from WINWORD.EXE (Office macro execution). Encoded command
  contains download cradle pattern. SeDebugPrivilege enabled, unusual
  for a macro-spawned shell. Registry Run key handle confirms persistence.

Key Evidence:
  - L542: 3412  powershell.exe  -Enc SQBFAFgA...
  - L88: 3412  SeDebugPrivilege  Enabled
----------------------------------------------------------------
```

### Fallback behavior

If the LLM fails, `_build_fallback_analyst_txt()` writes a valid `analyst.txt` with `confirmed=0` and all findings as INCONCLUSIVE with the note "LLM unavailable — manual review required."

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

This gives Agent 3 visibility across all chunks in a single pass.

---

## Stage 4: Report Writer (`scripts/report_agent.py`)

### Role
Synthesize Agent 2's validated findings into a human-readable Markdown document. Does not re-judge findings — REJECTED findings are dropped from the body (counted only). Writes CONFIRMED and INCONCLUSIVE findings into the six-section structure.

### Two operating modes

**LLM mode** (`--use-llm`)  
The LLM receives the full `aggregated_analyst.txt` and writes a cohesive narrative. Produces more natural prose and better timeline construction.

**Structured mode** (default, no flags)  
Parses `aggregated_analyst.txt` with regex to extract `[CONFIRMED]` and `[INCONCLUSIVE]` blocks, then populates a Markdown template deterministically. Output is identical every time.

### TXT parsing (structured mode)

Uses `re.findall(r'\[CONFIRMED\]\s*-{3,}\s*(.*?)-{3,}', text, re.DOTALL)` and equivalent for `[INCONCLUSIVE]`. Within each block, extracts fields with `re.search` per field name. `Key Evidence` lines (indented with `  - `) are gathered as IOC candidates.

### Report structure

Six mandatory sections:

1. **Executive Summary** — count of confirmed/inconclusive/rejected; overall severity
2. **Attack Timeline** — bullet list of CONFIRMED findings ordered by severity
3. **MITRE ATT&CK Mapping** — technique table from CONFIRMED findings (only filled where Agent 2 provided a mapping)
4. **IOCs** — first 20 verbatim `Key Evidence` lines from CONFIRMED findings
5. **Recommendations** — 3 items (immediate containment, investigation, remediation)
6. **Confidence Assessment** — confirmed/inconclusive/rejected counts and interpretation

---

## Configuration Reference

### `agentic-architecture/config.json`

| Field | Default | Description |
|---|---|---|
| `input_dir` | `"../INPUT"` | Path to chunk files (relative to `agentic-architecture/`) |
| `grep_input_dir` | `"../Grep_input"` | Path to Volatility artifact files |
| `max_lines_per_file` | 120 | Maximum grep hits per artifact file per PID |
| `max_total_lines_per_target` | 400 | Maximum grep hits across all files for one PID |
| `pid_files` | 20 files | Artifact files searched by PID (word-boundary match) |
| `path_files` | 25 files | Artifact files searched by path (case-insensitive) |
| `suspicious_keywords` | list | Command-line substrings for rule-based scoring fallback |
| `suspicious_dirs` | list | Directory fragments for elevated rule-based scoring |

The `pid_files` and `path_files` lists were verified against the actual contents of `Grep_input/`. Files listed there that did not exist in `Grep_input/` (e.g. `handles.txt`, `getsids.txt`) were excluded.

### `agentic-architecture/llm_config.json`

| Field | Description |
|---|---|
| `provider` | LLM provider: `openrouter`, `openai-compatible`, or `anthropic` |
| `api_base` | Full API endpoint URL |
| `model` | Model ID string passed to the API |
| `api_key` | API key (leave blank to use environment variable) |
| `api_key_env` | Environment variable name that overrides `api_key` |
| `temperature` | Sampling temperature (0.2 = low randomness) |
| `max_tokens` | Maximum tokens per LLM response |
| `max_retries` | Max 429 retry attempts before falling back (default: 5) |
| `verify_ssl` | Set to `false` for TLS inspection proxy environments |

---

## Shared Utilities

### `scripts/llm_client.py`

**`load_llm_config(path)`** — Parses `llm_config.json`. Checks both `api_key` and the environment variable named in `api_key_env`, with the environment variable taking priority.

**`call_chat(messages, config)`** — Dispatches to the correct provider branch:
- **`openrouter` / `openai-compatible`**: posts to the OpenAI-compatible `/chat/completions` endpoint, parses `choices[0].message.content`.
- **`anthropic`**: posts to `/v1/messages` with `x-api-key` + `anthropic-version` headers; extracts the system message from the messages list into the top-level `system` field; parses `content[0].text`.

Both branches implement automatic 429 retry: `_parse_retry_after(body)` reads `retry_after_seconds` from the response metadata (or calculates from `X-RateLimit-Reset`), then sleeps and retries up to `max_retries` times (default 5) before raising and triggering the fallback.

**`extract_json(text)`** — Handles three common ways an LLM might return JSON: raw JSON, JSON in a markdown code fence, or JSON embedded in prose (brace-counting extraction). Used only by Agent 1 (which outputs JSON internally for reliable parsing).

### `scripts/utils.py`

**`load_whitelist(path)`** — Reads `whitelist.txt` line by line, returning glob-style patterns for legitimate paths.

**`is_whitelisted_path(value, patterns)`** — Returns True if the given path matches any whitelist pattern using `fnmatch`. Used by Agent 1 to filter legitimate system DLLs before building the LLM context.

**`grep_file_for_pattern(path, pattern, max_lines)`** — Opens a file, iterates line by line, applies the compiled regex, and returns up to `max_lines` matching lines as `"L{line_number}: {content}"` strings.

---

## Intermediate File Formats

All four format specifications are documented in `agentic-architecture/schemas/`:

| File | Schema document |
|---|---|
| `chunk_N/triage.txt` | `schemas/triage_output_format.md` |
| `chunk_N/pivot.txt` | `schemas/pivot_output_format.md` |
| `chunk_N/analyst.txt` | `schemas/pivot_analyst_output_format.md` |
| `output/report.md` | `schemas/report_output_format.md` |

The `agent2_pivot.md` prompt is the ground truth for `analyst.txt` format. The schema document derives from it, not the reverse.

---

## Design Patterns Summary

**Chunk isolation**: Agents 1 and 2 run once per chunk. A process seen in chunk 3 cannot influence Agent 2's reading of chunk 1. Only Agent 3 sees the aggregated view.

**LLM JSON internal, TXT external**: Agent 1 asks the LLM to output JSON (structured, reliable) then converts it to a human-readable TXT format on disk. Agents 2 and 3 output TXT directly, as defined by their prompts.

**Read-only evidence**: No stage modifies the Volatility artifact files. All writes go to the `output/` directory. This preserves chain-of-custody integrity.

**Graceful degradation**: Agent 1 LLM fails → rule-based scoring. Agent 2 LLM fails → all INCONCLUSIVE. Agent 3 LLM fails → structured template. The pipeline always produces all output files.

**Audit trail**: The per-chunk TXT files plus `aggregated_analyst.txt` and `report.md` together constitute a complete audit trail. Any claim in the final report traces back to a specific line number in a specific Volatility artifact file.
