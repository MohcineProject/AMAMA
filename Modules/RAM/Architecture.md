# RAM Forensic Module — Architecture

## Overview

The RAM module is a component of the AMAMA multi-module forensic system. Given a Windows memory image it produces a `scan_result.json` (`ModuleScanResult` contract) consumed by the orchestrator.

It has three phases: **extraction** (Volatility 3 plugins → artifact files), **collection** (artifact files → process-forest chunks), and **analysis** (chunks → triage → pivot evidence → verdicts).

---

## Module Structure

```
RAM/
├── Architecture.md               ← this file
├── README.md                     ← user guide
├── extractor.py                  ← Volatility runner: mandatory + extended plugins
├── full_pipeline.py              ← end-to-end entry point (recommended)
│
├── RAM_image/                    ← input
│   └── evil_windows.elf
│
├── RAM_Artifacts/                ← Volatility 3 plugin outputs
│   ├── pstree.txt, psscan.txt, cmdline.txt, dlllist.txt
│   ├── netscan.txt, netstat.txt, privileges.txt, getsids.txt
│   ├── malfind.txt, malware_*.txt
│   ├── registry_*.txt
│   ├── ldrmodules.txt, modules.txt, svcscan.txt, ...
│   └── run_log.txt               ← timing log written by extractor.py
│
├── INPUT/                        ← FIND_EVIL collector output (pipeline input)
│   ├── chunk_001.txt
│   └── ...
│
├── ram-collector/                ← DFIR-Collector: turns artifacts into chunks
│   └── collector/
│       ├── __init__.py           ← public API: run_collector()
│       ├── __main__.py           ← CLI: python -m collector
│       ├── vol3_runner.py        ← Vol3 subprocess runner + TSV parser
│       ├── merge.py              ← builds ProcessRecord objects
│       ├── exclusions.py         ← 21-rule benign-process filter
│       ├── tree.py               ← DFS process-tree builder
│       ├── format_line.py        ← single-line process formatter
│       └── chunker.py            ← token-aware, subtree-safe chunk writer
│
├── ram-agentic-architecture/
│   ├── config.json               ← grep file lists, keyword lists, evidence caps
│   ├── llm_config.json           ← provider + model + fallback chain
│   ├── scripts/
│   │   ├── run_pipeline.py       ← post-extraction pipeline runner
│   │   ├── triage_agent.py       ← Agent 1: process triage
│   │   ├── pivot_grep.py         ← Stage 2: deterministic grep
│   │   ├── pivot_analyst.py      ← Agent 2: verdict assignment
│   │   ├── scan_result_emitter.py← aggregated TXT → scan_result.json
│   │   ├── entity_query.py       ← pivot-back: answers EntityQuery from orchestrator
│   │   ├── llm_client.py         ← provider abstraction (Anthropic / OpenRouter / Gemini)
│   │   └── utils.py
│   ├── prompts/
│   │   ├── agent1_triage.md
│   │   ├── agent2_pivot.md
│   │   └── agentQ_focused.md
│   ├── schemas/                  ← JSON contracts (orchestrator ↔ module)
│   │   ├── entity_query.schema.json
│   │   ├── entity_findings.schema.json
│   │   └── module_scan_result.schema.json
│   ├── tests/
│   │   ├── conftest.py
│   │   ├── test_scan_result_emitter.py
│   │   ├── test_entity_query.py
│   │   └── test_pipeline_integration.py
│   └── output/                   ← generated at runtime
│       ├── chunk_001/
│       │   ├── triage.txt
│       │   ├── pivot.txt
│       │   └── analyst.txt
│       ├── ...
│       ├── aggregated_analyst.txt
│       ├── scan_result.json
│       └── queries/              ← per-EntityQuery audit trails
│
└── COMPLETE_ARCHITECTURE/        ← orchestrator integration specs + schemas
```

---

## Component Breakdown

### `extractor.py`

Runs Volatility 3 plugins and saves raw TSV output to `RAM_Artifacts/`. Plugins are organised into three tiers:

| Tier | Plugins | Purpose |
|---|---|---|
| **Mandatory** | 9 | Required by the collector (pstree, psscan, cmdline, dlllist, handles, privileges, netscan, netstat, getsids) |
| **Fast-extended** | 15 | High-value pivot-grep targets (malfind, ldrmodules, svcscan, malware.\*, registry.printkey, …) |
| **Full-extended** | ~40 | Comprehensive sweep (kernel, VAD, full registry, extra malware variants) |

Plugins within each tier run in **parallel** via `ThreadPoolExecutor` (configurable `--workers`, default 4). A `run_log.txt` with per-plugin timing is appended to `RAM_Artifacts/` on every run.

### `full_pipeline.py`

End-to-end orchestrator. Calls `extractor.py`, the collector, and the analysis pipeline in the optimised order (see Data Flow below). This is the recommended single entry point.

### `ram-collector/`

Takes the 9 Volatility TSV files from `RAM_Artifacts/` and produces `INPUT/chunk_*.txt`. Specifically:

1. Parses plugin TSV outputs into typed dataclasses (`RawProcess`, `RawDll`, …)
2. Merges them into `ProcessRecord` objects (one per PID)
3. Applies 21 exclusion rules to drop known-benign system processes
4. Builds a DFS-ordered process tree
5. Formats each process as a single key=value line
6. Packs lines into token-safe chunks (default 8 000 tokens each), never splitting a parent from its children

### `run_pipeline.py`

Standalone pipeline runner that assumes `RAM_Artifacts/` and `INPUT/` are already populated. Useful for re-running analysis after extraction is done. Processes each chunk sequentially through the three stages.

### `triage_agent.py` — Agent 1

Reads a chunk file. Runs deterministic anomaly checks first (spawn anomalies, privilege anomalies, spawn volume). Then, if an LLM is available, sends a compact per-process context block to the LLM with `agent1_triage.md`, which walks seven detection categories (process identity, parent-child relationships, LOLBin abuse, obfuscation, DLL provenance, network, SID/privilege). Outputs `triage.txt` with per-process severity ratings.

Falls back to keyword/path scoring without LLM.

### `pivot_grep.py` — Stage 2

Zero LLM. For each PID flagged by Agent 1, greps all relevant artifact files using a word-boundary regex. Caps output at 120 lines per file and 400 lines per PID to control LLM context size. Outputs `pivot.txt` with verbatim lines and their line numbers.

### `pivot_analyst.py` — Agent 2

Reads `triage.txt` and `pivot.txt` together. Sends a structured per-PID block to the LLM with `agent2_pivot.md`, which instructs it to reason through nine evidence lenses (command-line plausibility, DLL provenance, privilege footprint, handle cross-references, environment variables, file/path corroboration, code injection markers, timeline coherence, SID anomalies). Issues a three-way verdict per PID.

Falls back to all-INCONCLUSIVE without LLM.

### `entity_query.py`

Answers a single `EntityQuery` from the orchestrator. Uses a 4-stage flow: type dispatch (0 LLM) → deterministic grep (0 LLM) → whitelist check (0 LLM) → scoped LLM interpreter (1 call if needed). Around 70–80% of queries terminate before the LLM stage.

### `scan_result_emitter.py`

No LLM. Parses `aggregated_analyst.txt` with regex and emits `scan_result.json` matching the `ModuleScanResult` schema. Always produces output regardless of what the agents found.

---

## Data Flow

### End-to-end (`full_pipeline.py`)

The key optimisation is that the collector and Agent 1 start as soon as mandatory plugins are ready, while the extended plugins continue extracting in the background:

```
Phase 1  ─── Mandatory plugins (9, parallel, blocking)
              pstree, psscan, cmdline, dlllist, [handles], privileges,
              netscan, netstat, getsids  →  RAM_Artifacts/
              ~1–2 min (bottleneck: psscan)

Phase 2  ─── Extended plugins (15 fast / ~55 full, parallel, BACKGROUND THREAD)
              malfind, ldrmodules, svcscan, malware.*, registry.*  →  RAM_Artifacts/
              ~5–10 min (fast) / ~15–25 min (full)

Phase 3  ─── Collector (reads RAM_Artifacts/ → writes INPUT/chunk_*.txt)
              Runs immediately after Phase 1, concurrently with Phase 2
              <1 min

Phase 4  ─── Per-chunk loop (sequential chunks):
  │
  ├── Agent 1 — runs immediately, no dependency on extended plugins
  │      triage.txt written
  │
  ├── Wait for extended_done event (no-op for chunks 2–N; brief wait at most for chunk 1)
  │
  ├── Pivot grep  →  pivot.txt
  │
  └── Agent 2  →  analyst.txt

Phase 5  ─── Aggregate all analyst.txt → aggregated_analyst.txt
             scan_result_emitter → scan_result.json
```

### Post-extraction only (`run_pipeline.py`)

```
INPUT/chunk_*.txt  ──┐
                     │  Per chunk: Agent 1 → pivot grep → Agent 2
RAM_Artifacts/*.txt ─┘
                     ↓
              aggregated_analyst.txt
                     ↓
              scan_result.json
```

---

## Plugin Tiers

### Mandatory (always run first)

| Plugin | Output file |
|---|---|
| `windows.pstree.PsTree` | `pstree.txt` |
| `windows.psscan.PsScan` | `psscan.txt` |
| `windows.cmdline.CmdLine` | `cmdline.txt` |
| `windows.dlllist.DllList` | `dlllist.txt` |
| `windows.handles.Handles` | `handles.txt` (skippable with `--no-handles`) |
| `windows.privileges.Privs` | `privileges.txt` |
| `windows.netscan.NetScan` | `netscan.txt` |
| `windows.netstat.NetStat` | `netstat.txt` |
| `windows.getsids.GetSIDs` | `getsids.txt` |

### Fast-extended (used in `--fast` mode, the default)

pslist, malfind, ldrmodules, modules, svcscan, driverscan, sessions, shimcachemem, malware.psxview, malware.malfind, malware.ldrmodules, malware.hollowprocesses, malware.pebmasquerade, registry.printkey, registry.hivelist

### Full-extended (added in `--full` mode)

All remaining ~40 plugins from `run_log.txt`: kernel objects (callbacks, ssdt, timers), memory (vadinfo, vadwalk, iat), additional malware variants (processghosting, suspicious_threads, directsystemcalls, …), full registry suite (amcache, hashdump, lsadump, scheduledtasks, …), driver/device tree, etc.

---

## Input Formats

### Chunk files (`INPUT/chunk_N.txt`)

One process per line, key=value format:

```
# FIND_EVIL Collector — ../RAM_Artifacts — 2026-05-31T20:02:59
pid=3412 ppid=3120 name=powershell.exe path=C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe cmd="powershell.exe -Enc SQBFAFgA..." start=2026-05-13 19:26:56.000000 UTC dlls=ntdll.dll;... nets=TCP|192.168.1.5|49832|10.10.0.1|443|ESTABLISHED;... sids=S-1-5-18|SYSTEM;... privs=SeDebugPrivilege|Enabled;... handles=
```

Indentation (2 spaces × depth) represents parent-child hierarchy. A parent process and all its descendants always appear in the same chunk.

### Volatility artifact files (`RAM_Artifacts/*.txt`)

Standard Volatility 3 TSV output: banner line, header line, then tab-separated data rows. The collector and pivot_grep.py both tolerate ragged rows and missing columns.

---

## Output Formats

### `triage.txt`

```
[PROCESS]
pid: 3412
ppid: 3120
image: powershell.exe
cmdline: powershell.exe -Enc SQBFAFgA...
severity: CRITICAL
reasons: parent_mismatch: WINWORD.EXE->powershell.exe | encoded_ps: -Enc + Base64
```

### `pivot.txt`

```
=== PID 3412 (powershell.exe, ppid=3120) ===

--- cmdline.txt ---
L542: 3412  powershell.exe  -Enc SQBFAFgA...

--- privileges.txt ---
L88: 3412  SeDebugPrivilege  Enabled
```

### `analyst.txt`

```
[CONFIRMED]
PID: 3412
Image: powershell.exe
Severity: CRITICAL
MITRE: T1059.001 | T1027
Justification: WINWORD.EXE spawned powershell.exe with a Base64-encoded command …
Key Evidence:
  - L542 cmdline.txt: powershell.exe -Enc SQBFAFgA...
  - L88 privileges.txt: SeDebugPrivilege Enabled
```

Verdict options: `[CONFIRMED]`, `[INCONCLUSIVE]`, `[REJECTED]`.

### `scan_result.json`

```json
{
  "contract_version": "1.0",
  "case_id": "test-fast",
  "module": "ram",
  "scan_started_at": "...",
  "scan_completed_at": "...",
  "summary": "9 chunk(s) processed. 2 CONFIRMED, 3 INCONCLUSIVE, 4 REJECTED.",
  "counts": { "confirmed": 2, "inconclusive": 3, "rejected": 4 },
  "findings": [
    {
      "finding_id": "ram-chunk_001-f001",
      "verdict": "CONFIRMED",
      "severity": "CRITICAL",
      "mitre": ["T1059.001"],
      "primary_entity": { "type": "pid", "value": "3412" },
      "related_entities": [...],
      "justification": "...",
      "evidence": [{ "source_file": "cmdline.txt", "line": 542, "content": "...", "verbatim": true }]
    }
  ],
  "artifacts": {
    "human_report": "output/aggregated_analyst.txt",
    "per_chunk": ["output/chunk_001/analyst.txt", ...]
  }
}
```

---

## Design Principles

**LLM-first, deterministic fallback** — Agents default to LLM reasoning. If the API is unavailable, rule-based logic takes over. The pipeline never blocks.

**Token efficiency** — Raw Volatility files can be hundreds of thousands of lines. The grep stage extracts only lines relevant to flagged PIDs, capped before they reach the LLM.

**Conservative bias** — The system prefers false negatives over false positives. Agent 2 issues CONFIRMED only when evidence is unambiguous. INCONCLUSIVE warrants human review.

**Evidence traceability** — Every finding in `scan_result.json` cites verbatim lines with exact line numbers from the source Volatility artifact files. No claim is unverifiable.

**Chunk isolation** — Each chunk is processed independently. An LLM reading chunk 3 cannot retroactively color its reading of chunk 1. Only the emitter aggregates.

**Read-only artifacts** — No stage modifies `RAM_Artifacts/`. All writes go to `output/`. Chain-of-custody is preserved.

**Graceful degradation** — Agent 1 LLM fails → keyword scoring. Agent 2 LLM fails → all INCONCLUSIVE. `scan_result_emitter` never calls LLM.

---

## Configuration Reference

### `config.json`

| Key | Default | Description |
|---|---|---|
| `input_dir` | `"../INPUT"` | Path to chunk files (relative to `ram-agentic-architecture/`) |
| `grep_input_dir` | `"../RAM_Artifacts"` | Path to Volatility artifacts |
| `max_lines_per_file` | 120 | Grep hit cap per artifact file per PID |
| `max_total_lines_per_target` | 400 | Grep hit cap across all files per PID |
| `pid_files` | 20 files | Artifact files searched by PID |
| `path_files` | 25+ files | Artifact files searched by path |
| `network_files` | 4 files | Artifact files for IP/domain queries |
| `registry_files` | 1 file | Artifact files for registry key queries |
| `sid_files` | 3 files | Artifact files for SID queries |
| `suspicious_keywords` | list | Substrings for rule-based Agent 1 scoring |
| `suspicious_dirs` | list | Directory fragments for elevated scoring |

### `llm_config.json`

| Key | Description |
|---|---|
| `provider` | Primary: `anthropic`, `openrouter`, or `openai-compatible` |
| `model` | Model ID (e.g. `claude-opus-4-6`) |
| `api_key_env` | Env var name for the API key |
| `fallback_providers` | Ordered fallback list; first provider with a key is used |
| `temperature` | 0.2 (low randomness) |
| `max_tokens` | 30 000 |
| `max_retries` | 5 (429 backoff) |
| `verify_ssl` | Set `false` for TLS-inspection proxies |
