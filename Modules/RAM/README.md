# RAM Forensic Module

Windows memory forensics pipeline. Takes a RAM image, runs Volatility 3, and produces a structured `scan_result.json` with CONFIRMED / INCONCLUSIVE / REJECTED verdicts for suspicious processes.

See `Architecture.md` for how the components fit together internally.

---

## Prerequisites

- **Python 3.9+**
- **Volatility 3** — install from https://github.com/volatilityfoundation/volatility3
- **Python packages**:
  ```bash
  pip install tiktoken          # accurate token counting for the chunker (recommended)
  pip install requests          # required for LLM API calls
  ```
- **LLM API key** (optional — the pipeline runs in rule-based mode without one):
  ```bash
  export ANTHROPIC_API_KEY="sk-ant-..."     # preferred
  # or
  export OPENROUTER_API_KEY="sk-or-v1-..."
  # or
  export GOOGLE_API_KEY="AIza..."
  ```

---

## Quick Start (recommended)

Run the full end-to-end pipeline with a single command from the `RAM/` directory:

```bash
cd RAM/

python full_pipeline.py \
  --image RAM_image/evil_windows.elf \
  --vol-path /path/to/volatility3/vol.py \
  --case-id my-case-001
```

This does everything: extracts Volatility artifacts, collects process chunks, runs the three-stage analysis, and writes `scan_result.json`.

### Dry run (no API key needed)

```bash
python full_pipeline.py \
  --image RAM_image/evil_windows.elf \
  --vol-path /path/to/volatility3/vol.py \
  --case-id test \
  --no-llm
```

`--no-llm` uses rule-based fallback for Agent 1 and marks all Agent 2 findings INCONCLUSIVE. Good for verifying the pipeline works before spending API tokens.

---

## Volatility Path

`full_pipeline.py` needs to know where `vol.py` is. Provide it one of two ways:

```bash
# Option 1 — CLI flag (per-run)
python full_pipeline.py --image dump.elf --vol-path /opt/volatility3/vol.py

# Option 2 — environment variable (set once in your shell profile)
export VOL3_PATH=/opt/volatility3/vol.py
python full_pipeline.py --image dump.elf
```

---

## Extraction Modes

`full_pipeline.py` supports two extraction modes that control which Volatility plugins are run:

| Mode | Plugins | Wall time (4 workers) | Use when |
|---|---|---|---|
| `--fast` (default) | 24 (mandatory + fast-extended) | ~5–10 min | Testing, most investigations |
| `--full` | ~65 (all) | ~15–25 min | Full evidence sweep |

Both modes cover all pivot-grep file lists. `--full` adds deeper kernel, VAD, and full registry plugins.

```bash
# Fast mode (default — no flag needed)
python full_pipeline.py --image dump.elf --vol-path /path/to/vol.py

# Full mode
python full_pipeline.py --image dump.elf --vol-path /path/to/vol.py --full
```

---

## All `full_pipeline.py` Options

```
--image PATH          Path to Windows memory image  [required]
--fast                Fast mode: 24 plugins (default)
--full                Full mode: ~65 plugins
--vol-path PATH       Path to vol.py (or set VOL3_PATH env var)
--no-handles          Skip handles plugin — faster collector start, empty handle fields in chunks
--no-llm              Rule-based fallback — no API calls
--workers N           Parallel Volatility workers (default: 4)
--case-id STR         Stamped in scan_result.json (default: local-test)
--artifacts-dir DIR   Volatility output directory (default: RAM_Artifacts/)
--input-dir DIR       Collector chunk directory (default: INPUT/)
--out-dir DIR         Pipeline output root (default: ram-agentic-architecture/output/)
--config PATH         config.json path
--llm-config PATH     llm_config.json path
--log-level           DEBUG | INFO | WARNING | ERROR (default: INFO)
```

---

## Partial Runs

If you already have `RAM_Artifacts/` populated and only want to re-run the analysis:

```bash
# Re-run the full analysis pipeline (reads from RAM_Artifacts/ and INPUT/)
cd RAM/
python ram-agentic-architecture/scripts/run_pipeline.py \
  --case-id my-case-001

# With no LLM:
python ram-agentic-architecture/scripts/run_pipeline.py \
  --case-id my-case-001 \
  --no-llm
```

If you also want to re-run the collector (to regenerate chunks from existing artifacts):

```bash
cd RAM/
python -m ram-collector/collector \
  --from-folder RAM_Artifacts/ \
  --output-dir INPUT/ \
  --force
```

Or to run the collector directly from a RAM image (this also populates the mandatory artifacts):

```bash
python full_pipeline.py --image dump.elf --vol-path /path/to/vol.py
# ... the above is easier, but if you want collector-only:
cd RAM/ram-collector
python -m collector \
  --image ../RAM_image/evil_windows.elf \
  --output-dir ../INPUT/ \
  --no-handles \
  --force
```

---

## Understanding the Output

All output is written to `ram-agentic-architecture/output/` by default.

```
output/
├── chunk_001/
│   ├── triage.txt       ← Agent 1: per-process severity + reason tags
│   ├── pivot.txt        ← grep stage: verbatim evidence from RAM_Artifacts/
│   └── analyst.txt      ← Agent 2: CONFIRMED / INCONCLUSIVE / REJECTED verdicts
├── chunk_002/ … chunk_009/
├── aggregated_analyst.txt   ← full audit trail (all chunks concatenated)
└── scan_result.json         ← machine-readable output for the orchestrator
```

### Verdicts

| Verdict | Meaning |
|---|---|
| **CONFIRMED** | Multiple artifact types independently corroborate the finding |
| **INCONCLUSIVE** | Signal present but insufficient — warrants manual review |
| **REJECTED** | Evidence shows legitimate behaviour |

The pipeline is conservative: a missed threat is preferable to a false alarm.

### `scan_result.json`

The orchestrator-facing output. Structure:

```json
{
  "contract_version": "1.0",
  "case_id": "my-case-001",
  "module": "ram",
  "summary": "9 chunk(s) processed. 2 CONFIRMED, 3 INCONCLUSIVE, 4 REJECTED.",
  "counts": { "confirmed": 2, "inconclusive": 3, "rejected": 4 },
  "findings": [
    {
      "finding_id": "ram-chunk_001-f001",
      "verdict": "CONFIRMED",
      "severity": "CRITICAL",
      "mitre": ["T1059.001"],
      "primary_entity": { "type": "pid", "value": "3412" },
      "justification": "...",
      "evidence": [{ "source_file": "cmdline.txt", "line": 542, "content": "...", "verbatim": true }]
    }
  ]
}
```

All evidence citations trace back to exact line numbers in the original Volatility artifact files.

---

## Orchestrator Queries (entity_query.py)

When the orchestrator sends an `EntityQuery` JSON to investigate a specific entity:

```bash
cd RAM/ram-agentic-architecture
python scripts/entity_query.py \
  --query /path/to/entity_query.json \
  --out   /path/to/entity_findings.json
```

Supported entity types: `pid`, `image_name`, `file_path`, `ip`, `domain`, `url`, `registry_key`, `user_sid`, `mutex`. Returns `NOT_APPLICABLE` for `hash_*` (RAM carries no file hashes) and for `mutex` if `handles.txt` was not collected.

An audit trail is written to `output/queries/<query_id>.txt` for every query.

---

## LLM Configuration

Edit `ram-agentic-architecture/llm_config.json`. The primary provider is Anthropic; the pipeline falls back to OpenRouter, then Google Gemini, using the first provider for which a key is found.

```json
{
  "provider": "anthropic",
  "model": "claude-opus-4-6",
  "api_key_env": "ANTHROPIC_API_KEY",
  "fallback_providers": [
    { "provider": "openrouter", "model": "anthropic/claude-opus-4", "api_key_env": "OPENROUTER_API_KEY" },
    { "provider": "openai-compatible", "model": "gemini-2.5-flash", "api_key_env": "GOOGLE_API_KEY" }
  ],
  "temperature": 0.2,
  "max_tokens": 30000,
  "max_retries": 5
}
```

---

## Running the Tests

```bash
cd RAM/ram-agentic-architecture
python -m pytest tests/ -v
```

All 56 tests run without an API key (`--no-llm` mode is used internally):

| Test file | What it covers |
|---|---|
| `test_scan_result_emitter.py` | TXT → JSON conversion (23 tests) |
| `test_entity_query.py` | All entity type dispatch paths (20 tests) |
| `test_pipeline_integration.py` | End-to-end pipeline with `--no-llm` (13 tests) |

---

## Troubleshooting

**`FileNotFoundError: Volatility 3 not found at …`**  
Set `--vol-path /path/to/vol.py` or `export VOL3_PATH=/path/to/vol.py`.

**`No chunks found in INPUT/`**  
`INPUT/` is empty — run `full_pipeline.py` first, or populate it with the collector manually.

**`scan_result.json` has 0 CONFIRMED with `--no-llm`**  
Expected. Without an LLM, Agent 2 marks all findings INCONCLUSIVE. Add an API key and re-run without `--no-llm`.

**Agent 2 marks everything INCONCLUSIVE (with LLM enabled)**  
LLM call likely failed — check `llm_config.json` credentials and network. Re-running `run_pipeline.py` only re-runs the analysis without re-extracting.

**`tiktoken not installed` warning**  
The chunker falls back to character/4 estimation. Install `tiktoken` for accurate chunk boundaries: `pip install tiktoken`.

**SSL errors**  
Set `"verify_ssl": false` in `llm_config.json` for TLS-inspection proxy environments.

**`handles.txt` / `getsids.txt` missing**  
These are optional. `handles.txt` is skipped when `--no-handles` is used. If absent, mutex entity queries return `NOT_APPLICABLE`. Re-run with `--full` (no `--no-handles`) to collect them.

**Many "orphan" warnings from the collector**  
`34 root processes found — many orphans may indicate vol3_runner failed to collect all process base data`. This is normal for some dumps where PPID links are broken by DKOM. The collector handles it gracefully.
