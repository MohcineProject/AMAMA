# RAM Forensic Module

Windows memory forensics pipeline. Takes a RAM image, runs Volatility 3, and produces a structured `scan_result.json` with CONFIRMED / INCONCLUSIVE / REJECTED verdicts for suspicious processes.

See `Architecture.md` for how the components fit together internally.

---

## Prerequisites

- **Python 3.10+**
- **Volatility 3** — install from https://github.com/volatilityfoundation/volatility3. The module shells out to `vol.py` (it does not import Volatility). There is no built-in default path: point it at your install with the `vol_path` kwarg in the orchestrator config or the `VOL3_PATH` environment variable (`VOL3_PYTHON` optionally selects the interpreter, default `python3`).
- **Python packages**:
  After Volatility extracts the raw artifacts, the RAM collector turns the process tree into smaller `chunk_NNN.txt` files before they are sent to the LLM. This chunking step lives in `ram-collector/collector/chunker.py`: it packs whole process subtrees into each chunk so a parent process and all its descendants stay together.

  `tiktoken` is recommended for this step because it lets the chunker count tokens accurately against the LLM budget:
  ```bash
  pip install tiktoken
  ```
  Without `tiktoken`, the chunker falls back to a rough `len(text)/4` estimate. LLM API calls use the standard library — no extra package needed.
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

Volatility extraction happens in `extractor.py` and is split into three plugin tiers:

- **Mandatory (9 plugins)** — always run first. These produce the core TSV files the collector and pivot grep depend on (`pslist`, `psscan`, `cmdline`, `dlllist`, etc.).
- **Fast-extended (15 plugins)** — added in `fast` mode. These cover every Volatility artifact file that the pivot-grep stage searches, so Agent 2 has enough context without running the entire plugin catalog.
- **Full-extended (~40 more)** — added only in `full` mode. These deepen kernel, VAD, registry, and malware coverage for a broader sweep at the cost of longer wall time.

So `fast` is the default balance: everything needed for the triage → pivot → analyst pipeline. Use `full` when you want maximum Volatility coverage and can afford the extra runtime.

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

Each chunk directory mirrors one per-chunk analysis pass:

- **`triage.txt`** — output of Agent 1 (`triage_agent.py`). The LLM (or rule-based fallback) reads one collector chunk and flags suspicious processes with severity and short reason tags. DLL paths under known-good Windows locations are filtered out before triage (see [Whitelisting](#whitelisting)). This is the “what looks worth investigating?” step.
- **`pivot.txt`** — output of the **pivot grep** stage (`pivot_grep.py`). See [Pivot grep](#pivot-grep) below.
- **`analyst.txt`** — output of Agent 2 (`pivot_analyst.py`). It reads Agent 1’s reasons plus the grep evidence in `pivot.txt` and decides whether each finding is **CONFIRMED**, **INCONCLUSIVE**, or **REJECTED**.

`aggregated_analyst.txt` concatenates every chunk’s `analyst.txt` into one audit trail. `scan_result.json` is the structured summary the Backbone orchestrator ingests.

### Pivot grep

Pivot grep is the **middle stage** between triage and analyst. It does **not** call an LLM.

Agent 1 only says *which PIDs look suspicious*; the Volatility TSV files in `RAM_Artifacts/` can be huge (hundreds of thousands of lines). Sending all of that to Agent 2 would be slow, expensive, and noisy. Pivot grep instead:

1. Reads the suspicious PIDs from `triage.txt`.
2. Searches a configured list of artifact files (`config.json` → `pid_files`, e.g. `cmdline.txt`, `dlllist.txt`, `handles.txt`) under `RAM_Artifacts/`.
3. Matches each PID with a **word-boundary regex** so `4` does not false-match `4242`.
4. Copies the **verbatim matching lines** into `pivot.txt`, with caps (default: 120 lines per file, 400 per PID) so Agent 2 gets focused evidence, not the full dump.

Example `pivot.txt` shape:

```
=== PID 3412 (powershell.exe, ppid=1234) ===
Cmdline: powershell.exe -enc ...

--- cmdline.txt ---
3412	powershell.exe	-enc ...

--- dlllist.txt ---
...
```

That is why `scan_mode: fast` still matters for pivot grep: the **fast-extended** Volatility plugins populate the artifact files this stage searches. Agent 2 then judges whether Agent 1’s suspicion is supported by real cross-artifact evidence.

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
