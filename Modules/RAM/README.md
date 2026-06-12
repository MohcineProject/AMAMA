# RAM Forensic Module

Windows memory forensics pipeline. Takes a RAM image, runs Volatility 3, and produces a structured `scan_result.json` with CONFIRMED / INCONCLUSIVE / REJECTED verdicts for suspicious processes.

See `Architecture.md` for how the components fit together internally.

---

## Prerequisites

- **Python 3.10+**
- **Volatility 3** — install from https://github.com/volatilityfoundation/volatility3. The module shells out to `vol.py` (it does not import Volatility). There is no built-in default path: point it at your install with the `vol_path` kwarg in the orchestrator config or the `VOL3_PATH` environment variable (`VOL3_PYTHON` optionally selects the interpreter, default `python3`).
- **Python packages**:
  ```bash
  pip install tiktoken          # accurate token counting for the chunker (recommended)
  ```
  Without `tiktoken` the chunker falls back to a `len(text)/4` estimate. LLM API calls use the standard library — no extra package needed.
- **LLM API key** (optional — the pipeline runs in rule-based mode without one):
  ```bash
  export ANTHROPIC_API_KEY="sk-ant-..."     # preferred
  # or
  export OPENROUTER_API_KEY="sk-or-v1-..."
  # or
  export GOOGLE_API_KEY="AIza..."
  ```

---

## How it runs

The module is driven by the Backbone orchestrator, which loads `RamModule` (`ram-agentic-architecture/ram_module.py`) and calls its `scan()` / `query()` methods. Everything is configured from `Backbone/config/orchestrator.yaml`:

```yaml
modules:
  - class: ram_module.RamModule
    path: ../../Modules/RAM/ram-agentic-architecture
    kwargs:
      use_llm: true        # false → rule-based triage, all verdicts INCONCLUSIVE
      scan_mode: fast      # 'fast' (default) or 'full' — see Extraction Modes
      ram_image: /abs/path/to/Modules/RAM/RAM_image/memory.raw
      vol_path: /abs/path/to/volatility3/vol.py
      artifact_dir: /abs/path/to/Modules/RAM/RAM_Artifacts
```

A `scan()` then runs end-to-end: extracts Volatility artifacts into `RAM_Artifacts/`, builds process chunks (`ram-collector/` — see its README), and runs the three-stage analysis — triage → pivot grep → analyst — before emitting `scan_result.json`.

Omit `ram_image` to skip Volatility extraction and analyse the pre-collected artifacts already in `artifact_dir` (mirroring the disk module's `image_dir`). Add `reuse_analysis: true` to also skip the analysis and re-emit the previous run's `aggregated_analyst.txt` — a zero-cost re-run.

---

## Extraction Modes (`scan_mode`)

The `scan_mode` kwarg controls which Volatility plugins are run:

| Mode | Plugins | Wall time (4 workers) | Use when |
|---|---|---|---|
| `fast` (default) | 24 (mandatory + fast-extended) | ~5–10 min | Testing, most investigations |
| `full` | ~65 (all) | ~15–25 min | Full evidence sweep |

Both modes cover all pivot-grep file lists. `full` adds deeper kernel, VAD, and full registry plugins.

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

## Orchestrator Queries

When the orchestrator pivots on an entity, it calls `RamModule.query()` with an `EntityQuery` and gets back an `EntityFindings` document.

Supported entity types: `pid`, `image_name`, `file_path`, `ip`, `domain`, `url`, `registry_key`, `user_sid`, `mutex`. Returns `NOT_APPLICABLE` for `hash_*` (RAM carries no file hashes) and for `mutex` if `handles.txt` was not collected.

An audit trail is written to `output/queries/<query_id>.txt` for every query.

---

## LLM Configuration

Edit `ram-agentic-architecture/llm_config.json`. The primary provider is Anthropic; the pipeline falls back to OpenRouter, then Google Gemini, using the first provider for which a key is found.

```json
{
  "provider": "anthropic",
  "model": "claude-sonnet-4-6",
  "api_key_env": "ANTHROPIC_API_KEY",
  "fallback_providers": [
    { "provider": "openrouter", "model": "anthropic/claude-opus-4", "api_key_env": "OPENROUTER_API_KEY" },
    { "provider": "openai-compatible", "model": "gemini-2.5-flash", "api_key_env": "GOOGLE_API_KEY" }
  ],
  "temperature": 0.15,
  "max_tokens": 30000,
  "max_retries": 5
}
```

---

## Running the Tests

```bash
cd Modules/RAM/ram-agentic-architecture
python -m pytest tests/ -v
```

All 60 tests run without an API key (`--no-llm` mode is used internally):

| Test file | What it covers |
|---|---|
| `test_scan_result_emitter.py` | TXT → JSON conversion (27 tests) |
| `test_entity_query.py` | All entity type dispatch paths (20 tests) |
| `test_pipeline_integration.py` | End-to-end pipeline with `--no-llm` (13 tests) |
