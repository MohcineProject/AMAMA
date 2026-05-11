# AMAMA — Multi-Agent DFIR Triage

A lightweight, multi-agent system for forensic triage of memory (RAM) images. Built around a deterministic-script + LLM-agent pipeline that keeps token usage low and reduces hallucinations by sandwiching reasoning agents between scripted, evidence-based steps.

## Project structure

```
AMAMA/
  frontend/        React + TypeScript UI for the IR analyst
  backend_dummy/   FastAPI mock backend (returns fixture data for end-to-end frontend dev)
  General_Architecturev2.pdf
```

## Pipeline (RAM triage)

1. **start** — UI: choose a case, see available files, launch analysis
2. **collector** — script: runs Volatility, produces a high-level JSON summary
3. **agent1 (triage)** — LLM: returns suspicious processes / services / paths
4. **grep** — script: PID-based and path-based grep into deeper Volatility plugins
5. **agent2 (pivot)** — LLM: confirms or downgrades each suspicion with full context
6. **agent3 (report)** — LLM: writes a 6-section incident narrative
7. **report** — UI: presents the final report

## Status

Work in progress. Built commit-by-commit; see the [plan](.cursor/plans/) for the roadmap.

## Quick start (once built)

```bash
# backend (mock)
cd backend_dummy
# see backend_dummy/README.md

# frontend
cd frontend
# see frontend/README.md
```
