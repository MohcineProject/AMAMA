# Cyber-Agent — Forensic Triage Pipeline

Multi-agent pipeline for Windows memory forensics. Takes pre-processed FIND_EVIL collector chunks and Volatility 3 artifact files, runs three LLM-powered agents with one deterministic grep stage, and produces a structured incident report.

## Quick Start

```bash
cd agentic-architecture

# Offline (no API key needed — rule-based fallback throughout)
python scripts/run_pipeline.py --no-llm

# With LLM (set your API key first)
python scripts/run_pipeline.py --use-llm
```

## Prerequisites

- Python 3.8+
- `pip install requests`
- Input files in place (see below)

## Input

| Path | Contents |
|---|---|
| `../INPUT/chunk_001.txt` … `chunk_009.txt` | FIND_EVIL collector chunks (one process per line) |
| `../Grep_input/*.txt` | 67 Volatility 3 artifact files |

Both folders are populated by an upstream project before running this pipeline.

## LLM Configuration

Edit `llm_config.json`:

```json
{
  "provider": "openrouter",
  "api_base": "https://openrouter.ai/api/v1/chat/completions",
  "model": "meta-llama/llama-3.3-70b-instruct:free",
  "api_key": "sk-or-v1-...",
  "api_key_env": "OPENROUTER_API_KEY",
  "temperature": 0.2,
  "max_tokens": 2000,
  "max_retries": 5,
  "verify_ssl": false
}
```

Or set the environment variable:
```bash
# PowerShell
$env:OPENROUTER_API_KEY = "sk-or-v1-..."

# Also supports Anthropic API directly (set "provider": "anthropic")
```

**Free tier note**: OpenRouter free models are rate-limited (8 req/min). The pipeline retries automatically using the `Retry-After` hint from the API. Some free models require a payment method on file at openrouter.ai even if you never spend anything.

## Pipeline Flow

```
INPUT/chunk_N.txt  +  Grep_input/*.txt
        │
        ▼  (for each chunk)
  [Agent 1]  triage_agent.py   →  output/chunk_N/triage.txt
  [Grep  ]   pivot_grep.py     →  output/chunk_N/pivot.txt
  [Agent 2]  pivot_analyst.py  →  output/chunk_N/analyst.txt
        │
        ▼  (aggregate)
  output/aggregated_analyst.txt
        │
        ▼
  [Agent 3]  report_agent.py   →  output/report.md
```

## Output

```
output/
├── chunk_001/
│   ├── triage.txt      ← Agent 1: flagged processes with severity + reasons
│   ├── pivot.txt       ← Grep: verbatim evidence lines from Volatility artifacts
│   └── analyst.txt     ← Agent 2: CONFIRMED / INCONCLUSIVE verdicts
├── chunk_002/ … chunk_009/
├── aggregated_analyst.txt
└── report.md           ← final incident report (Markdown)
```

## Flags

| Flag | Effect |
|---|---|
| `--use-llm` | Enable LLM for all stages |
| `--no-llm` | Rule-based fallback only (no API calls) |
| `--config PATH` | Path to config.json (default: `config.json`) |
| `--llm-config PATH` | Path to llm_config.json |
| `--out DIR` | Output root (default: `output/`) |

## Structure

```
agentic-architecture/
├── config.json          ← artifact file lists, grep limits, keyword lists
├── llm_config.json      ← LLM provider, model, API key, retry settings
├── scripts/
│   ├── run_pipeline.py  ← orchestrator
│   ├── triage_agent.py  ← Agent 1
│   ├── pivot_grep.py    ← deterministic grep
│   ├── pivot_analyst.py ← Agent 2
│   ├── report_agent.py  ← Agent 3
│   ├── llm_client.py    ← API client (OpenRouter + Anthropic)
│   ├── utils.py         ← shared helpers
│   └── whitelist.txt    ← legitimate path patterns (filtered from LLM context)
├── prompts/
│   ├── agent1_triage.md
│   ├── agent2_pivot.md
│   └── agent3_report.md
└── schemas/             ← format documentation for each intermediate file
```

See `How_to_use_it.md` and `Detailed_explanation.md` in the repo root for full documentation.
