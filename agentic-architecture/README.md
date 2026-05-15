# Lightweight Forensic Triage (Agentic Architecture)

This folder contains a complete, deployable multi-agent pipeline for lightweight forensic triage. It is designed to keep LLM token usage low by doing deterministic filtering and pivoting before any agent analysis.

## Quick start

1. Place the collector output JSON (blueprint-compatible) in the repo root (example: `../input.json`).
2. Ensure the raw Volatility text outputs are in the repo root (example: `../pslist.txt`, `../cmdline.txt`).
3. Run the pipeline from this folder:

```bash
python3 scripts/run_pipeline.py \
  --collector ../input.json \
  --artifact-root .. \
  --out output
```

Outputs:
- `output/triage.json`
- `output/pivot.json`
- `output/report.md`

## LLM configuration

LLM settings live in `llm_config.json`. Set your API key in the environment variable specified by `api_key_env` (default: `OPENROUTER_API_KEY`).

Run with LLM-assisted triage and reporting:

```bash
export OPENROUTER_API_KEY=your_key_here
python3 scripts/run_pipeline.py \
  --collector ../input.json \
  --artifact-root .. \
  --out output \
  --use-llm
```

## What this implements

- Deterministic triage scoring from the collector JSON
- PID and path pivoting across Volatility text outputs
- A concise report generator with a narrative outline
- Prompt templates and JSON schemas for LLM-assisted agents

## Structure

- `scripts/` runnable pipeline scripts
- `schemas/` JSON schemas for each agent stage
- `prompts/` LLM prompt templates for triage, pivot, and report agents
- `output/` generated artifacts (ignored by default)

## Notes

- The pipeline runs without external dependencies.
- LLM integration is optional. Prompts are provided to replace the rule-based agents.
- Update `config.json` and `scripts/whitelist.txt` to tune your environment.
