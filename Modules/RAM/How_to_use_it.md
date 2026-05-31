# How to Use the RAM Forensic Pipeline

---

## What This Module Does

The RAM module is a component of the AMAMA multi-module forensic system. It takes a Windows memory image, extracts and chunks the process forest via the DFIR-Collector, then runs a three-stage analysis:

1. **Agent 1 (triage)** — flags suspicious processes per chunk using LLM reasoning
2. **Grep pivot** — deterministic search of all Volatility artifacts for corroborating evidence
3. **Agent 2 (analyst)** — issues CONFIRMED / INCONCLUSIVE / REJECTED verdicts

After the per-chunk loop, the pipeline produces:
- `output/aggregated_analyst.txt` — human-readable audit trail (all chunks concatenated)
- `output/scan_result.json` — machine-readable JSON for the orchestrator (`ModuleScanResult` contract)

The final human-readable report is produced by the orchestrator, not this module.

**Inputs**: `RAM/INPUT/` (collector chunks) + `RAM/RAM_Artifacts/` (Volatility plugin outputs)  
**Main outputs**: `output/scan_result.json` + `output/aggregated_analyst.txt`

---

## Module Structure

```
RAM/
├── How_to_use_it.md              ← this file
├── Detailed_explanation.md       ← technical deep-dive
├── version2.md                   ← high-level design overview
├── domain_investigation.txt      ← Volatility technique: browser domain recovery
├── registry_persistence_detection.txt  ← Volatility technique: registry persistence
├── COMPLETE_ARCHITECTURE/        ← orchestrator integration specs and JSON schemas
│
├── RAM_image/                    ← input layer
│   └── evil_windows.elf          ← Windows RAM dump (test image)
│
├── RAM_Artifacts/                ← Volatility 3 plugin outputs (67 files)
│   ├── pslist.txt, pstree.txt, psscan.txt
│   ├── cmdline.txt, dlllist.txt, netscan.txt, netstat.txt
│   ├── malfind.txt, malware_*.txt
│   ├── registry_*.txt
│   └── ...
│
├── INPUT/                        ← FIND_EVIL collector chunks (pipeline input)
│   ├── chunk_001.txt
│   └── ...
│
├── ram-collector/                ← DFIR-Collector (chunks the RAM image for the pipeline)
│   └── collector/
│
└── ram-agentic-architecture/     ← 3-stage pipeline + orchestrator integration
    ├── config.json
    ├── llm_config.json
    ├── scripts/
    │   ├── run_pipeline.py           ← main entry point
    │   ├── triage_agent.py           ← Agent 1: process triage
    │   ├── pivot_grep.py             ← deterministic grep stage
    │   ├── pivot_analyst.py          ← Agent 2: evidence validation
    │   ├── scan_result_emitter.py    ← converts aggregated TXT → scan_result.json
    │   ├── entity_query.py           ← pivot-back: answers EntityQuery from orchestrator
    │   ├── llm_client.py
    │   └── utils.py
    ├── prompts/
    │   ├── agent1_triage.md
    │   ├── agent2_pivot.md
    │   └── agentQ_focused.md         ← single-entity analyst prompt for entity_query.py
    ├── schemas/                      ← JSON contract schemas (orchestrator ↔ module)
    │   ├── entity_query.schema.json
    │   ├── entity_findings.schema.json
    │   └── module_scan_result.schema.json
    ├── tests/                        ← pytest test suite
    │   ├── conftest.py
    │   ├── fixtures/
    │   │   ├── queries/              ← sample EntityQuery JSON input files
    │   │   └── expected/             ← expected EntityFindings output files
    │   ├── test_scan_result_emitter.py
    │   ├── test_entity_query.py
    │   └── test_pipeline_integration.py
    ├── logs/
    └── output/                       ← generated at runtime
        ├── chunk_001/
        │   ├── triage.txt
        │   ├── pivot.txt
        │   └── analyst.txt
        ├── ...
        ├── aggregated_analyst.txt
        ├── scan_result.json          ← machine-readable orchestrator output
        └── queries/                  ← audit trail for each EntityQuery answered
```

---

## Step 1 — Configure the LLM API Key

Open `ram-agentic-architecture/llm_config.json`. The primary provider is Anthropic (`claude-opus-4-6`). The pipeline automatically falls back to OpenRouter, then Google Gemini, using the first provider for which a key is found.

```json
{
  "provider": "anthropic",
  "api_base": "https://api.anthropic.com/v1/messages",
  "model": "claude-opus-4-6",
  "api_key": "",
  "api_key_env": "ANTHROPIC_API_KEY",
  "fallback_providers": [
    {
      "provider": "openrouter",
      "api_base": "https://openrouter.ai/api/v1/chat/completions",
      "model": "anthropic/claude-opus-4",
      "api_key": "",
      "api_key_env": "OPENROUTER_API_KEY"
    },
    {
      "provider": "openai-compatible",
      "api_base": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
      "model": "gemini-2.5-flash",
      "api_key": "",
      "api_key_env": "GOOGLE_API_KEY"
    }
  ],
  "temperature": 0.2,
  "max_tokens": 30000,
  "max_retries": 5,
  "verify_ssl": true
}
```

**Key resolution order:**
1. `api_key` field in the primary provider block (if non-empty)
2. Environment variable named in `api_key_env` for the primary provider
3. Same two checks for each `fallback_providers` entry, in order

Set your key via environment variable (recommended):
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
# or
export OPENROUTER_API_KEY="sk-or-v1-..."
```

---

## Step 2 — (Re-)Collect from the RAM Image

Skip this step if `INPUT/` already contains `chunk_*.txt` files.

### Option A — From pre-computed Volatility files (fast, <1 min)

Use this when `RAM_Artifacts/` is already populated:

```bash
cd RAM/ram-collector
python3 -m collector \
  --from-folder ../RAM_Artifacts \
  --output-dir ../INPUT \
  --log-level INFO
```

### Option B — Directly from the RAM image (~30–60 min)

```bash
cd RAM/ram-collector
python3 -m collector \
  --image ../RAM_image/evil_windows.elf \
  --output-dir ../INPUT \
  --no-handles \
  --log-level INFO
```

> **Note:** `--image` mode runs Volatility plugins internally but does **not** write outputs to `RAM_Artifacts/`. If you also need to refresh `RAM_Artifacts/` (for the pivot_grep stage), run Volatility separately for each plugin and save outputs there.

---

## Step 3 — Run the Pipeline

```bash
cd RAM/ram-agentic-architecture
python3 scripts/run_pipeline.py --case-id <your-case-id>
```

For a quick no-API dry run:
```bash
python3 scripts/run_pipeline.py --no-llm --case-id test-001
```

### Command-Line Flags

| Flag | Description |
|---|---|
| `--case-id ID` | Case identifier embedded in `scan_result.json` (default: `local-test`) |
| `--no-llm` | Disable LLM — rule-based fallback for Agent 1, all-INCONCLUSIVE for Agent 2 |
| `--config PATH` | Path to config.json (default: `ram-agentic-architecture/config.json`) |
| `--llm-config PATH` | Path to llm_config.json (default: `ram-agentic-architecture/llm_config.json`) |
| `--out DIR` | Root output directory (default: `ram-agentic-architecture/output/`) |

The pipeline automatically:
1. Discovers all `chunk_*.txt` files in `../INPUT/`
2. Per chunk: runs Agent 1 → grep pivot → Agent 2
3. Aggregates all per-chunk analyst outputs → `aggregated_analyst.txt`
4. Emits `scan_result.json` (no LLM — pure restructuring of the analyst output)

---

## Step 4 — View the Outputs

```
ram-agentic-architecture/output/
├── chunk_001/
│   ├── triage.txt           ← Agent 1: suspicious processes with severity + reasons
│   ├── pivot.txt            ← Grep pivot: verbatim evidence from RAM_Artifacts/
│   └── analyst.txt          ← Agent 2: CONFIRMED / INCONCLUSIVE / REJECTED verdicts
├── chunk_002/ … chunk_009/
├── aggregated_analyst.txt   ← all analyst.txt files concatenated (human audit trail)
└── scan_result.json         ← ModuleScanResult JSON for the orchestrator
```

### Per-chunk intermediates

| File | Stage | What it contains |
|---|---|---|
| `triage.txt` | Agent 1 | `[PROCESS]` blocks: pid, ppid, image, cmdline, severity, reasons |
| `pivot.txt` | Grep stage | Verbatim lines from `RAM_Artifacts/` files, grouped by PID, with source filename and line number |
| `analyst.txt` | Agent 2 | `[CONFIRMED]` / `[INCONCLUSIVE]` / `[REJECTED]` blocks with justification and key evidence citations |

### scan_result.json structure

```json
{
  "contract_version": "1.0",
  "case_id": "your-case-id",
  "module": "ram",
  "scan_started_at": "2026-05-31T10:00:00Z",
  "scan_completed_at": "2026-05-31T10:05:00Z",
  "summary": "9 chunk(s) processed. 2 CONFIRMED, 3 INCONCLUSIVE, 6 REJECTED.",
  "counts": { "confirmed": 2, "inconclusive": 3, "rejected": 6 },
  "findings": [
    {
      "finding_id": "ram-chunk_001-f001",
      "verdict": "CONFIRMED",
      "severity": "CRITICAL",
      "mitre": ["T1059.001"],
      "primary_entity": { "type": "pid", "value": "3412" },
      "related_entities": [ ... ],
      "justification": "...",
      "evidence": [ ... ]
    }
  ],
  "artifacts": {
    "human_report": "output/aggregated_analyst.txt",
    "per_chunk": ["output/chunk_001/analyst.txt", ...]
  }
}
```

---

## Step 5 — Interpret the Verdicts

| Verdict | Meaning |
|---|---|
| **CONFIRMED** | Multiple independent artifact types corroborate the finding |
| **INCONCLUSIVE** | Signal present but insufficient for confirmation — warrants manual review |
| **REJECTED** | Evidence shows legitimate behavior |

The pipeline is conservative: it prefers a missed threat over a false alarm.

---

## Step 6 — Answering Orchestrator Queries (entity_query.py)

When the orchestrator sends an `EntityQuery` JSON asking the RAM module to investigate a specific entity (PID, image name, IP, domain, etc.), use:

```bash
python3 scripts/entity_query.py \
  --query /path/to/entity_query.json \
  --out   /path/to/entity_findings.json
```

Add `--no-llm` to skip the LLM stage and return raw evidence as INCONCLUSIVE.

**Supported entity types:**

| Type | Strategy | Source files |
|---|---|---|
| `pid` | word-boundary match | `pid_files` in config.json (20 files) |
| `image_name` | case-insensitive | pslist, pstree, cmdline, psscan |
| `file_path` | case-insensitive | `path_files` in config.json (25+ files) |
| `ip` / `domain` | substring | netscan, netstat, cmdline, envars |
| `url` | substring | cmdline, envars |
| `registry_key` | case-insensitive | registry_printkey |
| `user_sid` | substring | getsids, privileges, sessions |
| `mutex` | substring | handles.txt (NOT_APPLICABLE if absent) |
| `hash_md5/sha1/sha256` | — | NOT_APPLICABLE (RAM has no file hashes) |

An audit trail for each query is written to `output/queries/<query_id>.txt`.

---

## Tuning the Pipeline

Edit `ram-agentic-architecture/config.json`:

| Parameter | Default | Effect |
|---|---|---|
| `max_lines_per_file` | 120 | Max grep lines per artifact file per PID |
| `max_total_lines_per_target` | 400 | Max total grep lines per PID across all files |
| `pid_files` | 20 files | Artifact files searched by PID |
| `path_files` | 25 files | Artifact files searched by path/image name |
| `network_files` | 4 files | Artifact files for IP/domain queries |
| `registry_files` | 1 file | Artifact files for registry key queries |
| `sid_files` | 3 files | Artifact files for SID queries |
| `suspicious_keywords` | list | Command-line patterns for rule-based Agent 1 fallback |
| `suspicious_dirs` | list | Directory patterns for elevated rule-based scoring |

---

## Running the Tests

```bash
cd RAM/ram-agentic-architecture
python3 -m pytest tests/ -v
```

- `test_scan_result_emitter.py` — tests the TXT → JSON conversion (23 tests, uses fixture + real output)
- `test_entity_query.py` — tests all entity type dispatch paths (20 tests, no API key required)
- `test_pipeline_integration.py` — end-to-end pipeline run with `--no-llm` (13 tests)

All 56 tests run without an API key (`--no-llm` mode).

---

## Troubleshooting

**No chunks found**  
Ensure `RAM/INPUT/` contains files matching `chunk_*.txt`. The `input_dir` in `config.json` defaults to `../INPUT`, relative to `ram-agentic-architecture/`.

**Missing Volatility artifact files**  
The grep stage skips absent files silently. Analysis quality degrades but the pipeline completes. `grep_input_dir` in `config.json` controls where it looks (default: `../RAM_Artifacts`).

**Agent 2 marks everything INCONCLUSIVE**  
LLM call failed — the pipeline degraded gracefully. Check `llm_config.json` credentials and network connectivity. Run with `--no-llm` to confirm the rest of the pipeline works.

**scan_result.json has 0 confirmed findings with --no-llm**  
Expected. Without an LLM, Agent 2 marks all findings INCONCLUSIVE. Run with a live key to get CONFIRMED/REJECTED verdicts.

**SSL errors**  
Set `"verify_ssl": false` in `llm_config.json` for TLS-inspection proxy environments.

**handles.txt / getsids.txt missing (entity_query warning)**  
These are optional Volatility plugins. The module returns `NOT_APPLICABLE` for mutex queries if `handles.txt` is absent, and returns empty evidence for SID queries if `getsids.txt` is absent. To add them, run `windows.handles.Handles` and `windows.getsids.GetSIDs` via Vol3 and save outputs to `RAM_Artifacts/`.
