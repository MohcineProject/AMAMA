# AMAMA - Multi-Agent DFIR Triage

A lightweight multi-agent system for forensic triage of memory (RAM) images. Built around a deterministic-script + LLM-agent pipeline that keeps token usage low and reduces hallucinations by sandwiching reasoning agents between scripted, evidence-based steps.

> Status: frontend + dummy backend wired end-to-end. The real DFIR pipeline (volatility runner + the three actual LLM agents) is plugged in separately.

## Project layout

```
AMAMA/
  frontend/          React + TypeScript UI (Vite + Tailwind + shadcn/ui)
  backend_dummy/     FastAPI mock backend serving fixture data + SSE stream
  General_Architecturev2.pdf
```

## Pipeline

```mermaid
flowchart LR
  start([start UI]) --> collector[collector script]
  collector --> agent1[agent1: triage LLM]
  agent1 --> grep[grep script]
  grep --> agent2[agent2: pivot LLM]
  agent2 --> agent3[agent3: report LLM]
  agent3 --> report([report UI])
```

| Stage | Type | Output |
|---|---|---|
| `start` | UI | file summary + Launch button |
| `collector` | script | image_info, plugins_run, high-level counts |
| `agent1` | LLM | suspicious processes / services / paths / tasks |
| `grep` | script | PID- and path-based pivots into deeper plugins |
| `agent2` | LLM | per-subject verdicts with confidence + evidence refs |
| `agent3` | LLM | 6-section incident narrative |
| `report` | UI | renders agent3 output |

## Quick start

You need **two terminals** running side-by-side.

### 1. Dummy backend (FastAPI)

```bash
cd backend_dummy
python -m venv .venv

# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Sanity check: <http://localhost:8000/health> -> `{"status":"ok",...}` and Swagger at <http://localhost:8000/docs>.

### 2. Frontend (Vite)

```bash
cd frontend
npm install
npm run dev   # http://localhost:5173
```

Vite proxies `/api/*` and `/health` to <http://localhost:8000>, so the frontend connects to the backend with no extra config.

### 3. Try it

1. Open <http://localhost:5173>.
2. Type a working directory that exists on your machine (the backend reads it for real). Example: `/home/analyst/DFIR_agent`.
3. The page validates the path and shows you any cases discovered under `<workdir>/cases/`. Pick one and click **Open case**.
4. The System View shows the 7-step pipeline on the left. The Start stage lists files found in the case folder.
5. Click **Launch analysis** -> watch each stage light up, progress, and produce a result. Final view is a 6-section incident report.

To experiment without real case folders, just create the structure manually:

```bash
mkdir -p /home/analyst/DFIR_agent/cases/INCIDENT_2025_08_08
echo dummy > /home/analyst/DFIR_agent/cases/INCIDENT_2025_08_08/memory.raw
```

## How the SSE pipeline works

`POST /api/cases/analyze` registers a run and returns a `run_id`. Opening `GET /api/runs/<run_id>/events` starts the run (so it's naturally bound to the subscriber). Each stage emits:

```
{ "type": "stage_start",    "stage": "collector", "kind": "script" }
{ "type": "stage_progress", "stage": "collector", "percent": 41, "message": "Plugin pslist..." }
{ "type": "stage_result",   "stage": "collector", "data": { ... } }
{ "type": "stage_complete", "stage": "collector" }
```

with `run_start` / `run_complete` bookends and an `error` event on failure. The dummy backend paces events with `asyncio.sleep` (~20s total) so the UI animates smoothly.

## Architecture decisions

- **Backend reads the real filesystem** for workspace validation, case listing, and case files. Only the analysis pipeline is faked. This lets analysts point at their actual case folders during development.
- **SSE over WebSocket** because the pipeline is one-way (server -> client). One less moving part.
- **shadcn/ui pattern** instead of a heavy component library: primitives are owned in `frontend/src/components/ui/` and can be tweaked freely.
- **Stage results typed** in `frontend/src/api/stage-results.ts` and pydantic models in `backend_dummy/app/models.py`. These are the canonical contract; the real backend just needs to emit the same shapes.

## Replacing the dummy backend

The real backend just needs to expose the same endpoints. The fixtures in `backend_dummy/app/fixtures.py` describe the exact shapes each stage must produce. The frontend never assumes anything else.

## Files of interest

- `frontend/src/hooks/useAnalysisRun.ts` - the SSE state machine
- `frontend/src/components/pipeline/PipelineStepper.tsx` - left stepper
- `frontend/src/components/pipeline/stages/*` - per-stage panels
- `backend_dummy/app/fixtures.py` - all the fake stage outputs
- `backend_dummy/app/routes/runs.py` - the SSE event emitter

## Auditing system

Every pipeline run automatically produces a self-contained audit tree under:

```
AMAMA/auditing/{case_id}/{YYYYMMDD-HHMMSS}/
```

The folder is always anchored to the repo root regardless of the working directory. A new timestamped subfolder is created on each run, so multiple runs of the same case accumulate side-by-side without overwriting each other.

### Directory structure

```
auditing/
└── {case_id}/
    └── {YYYYMMDD-HHMMSS}/
        ├── run_summary.json               ← single entry-point for the whole run
        │
        ├── backbone/
        │   ├── orchestrator_calls.jsonl   ← one record per orchestrator LLM call
        │   ├── report_call.jsonl          ← one record for the report LLM call
        │   ├── case_state.json            ← copy of the final case graph
        │   └── incident_report.md         ← copy of the generated report
        │
        ├── threat_intel/
        │   └── queries.jsonl              ← one record per VirusTotal lookup
        │
        ├── ram/
        │   ├── agent_calls.jsonl          ← one record per RAM LLM call
        │   ├── 01_chunks/                 ← memory text chunks fed to triage agent
        │   ├── 02_per_chunk_analysis/     ← triage / pivot / analyst output per chunk
        │   │   ├── chunk_001/
        │   │   │   ├── triage.txt
        │   │   │   ├── pivot.txt
        │   │   │   └── analyst.txt
        │   │   └── ...
        │   ├── aggregated_analyst.txt
        │   └── scan_result.json
        │
        └── disk/
            ├── agent_calls.jsonl          ← one record per Disk LLM call
            ├── 01_preprocess/             ← TRIAGE_INPUT_*.txt fed to triage agent
            ├── 02_triage/                 ← triage_persistence/events/mft + combined
            ├── 03_pivot/                  ← pivot.txt (grep evidence)
            ├── 04_analyst/                ← analyst.txt (Agent 2 output)
            ├── mft_audit.jsonl            ← filtered MFT entries
            └── scan_result.json
```

`ram/01_chunks/` and the `agent_calls.jsonl` files for RAM and Disk are only populated when the full LLM pipeline runs (i.e. a live memory image / disk image is provided). When reusing cached analysis (`reuse_analysis: true` or no `ram_image`), the per-chunk artifacts are still copied but no new LLM call records are written.

### `run_summary.json`

The single entry-point for a run. Key fields:

| Field | Description |
|---|---|
| `run_id` | Matches the timestamped folder name |
| `termination_reason` | `convergence` or `max_rounds_reached` |
| `execution_sequence` | Ordered list of every phase with timestamps — initial scans, TI enrichment, routing rounds, report |
| `cost_summary` | Total and per-component token counts and LLM call counts |
| `provenance` | Model ID and SHA-256 of the system prompt for orchestrator and report agents |
| `audit_files` | Relative paths to all JSONL logs in this run |
| `module_artifacts` | Relative paths to all copied pipeline artifacts |

### `agent_calls.jsonl` record schema

Every LLM call (across all agents) and every VirusTotal lookup appends one JSON line:

```json
{
  "call_id":     "uuid-v4",
  "timestamp":   "2026-06-09T08:00:30Z",
  "agent_name":  "backbone/orchestrator",
  "model":       "claude-haiku-4-5-20251001",
  "tokens_in":   2248,
  "tokens_out":  147,
  "latency_ms":  3418,
  "input_files": ["backbone/case_state.json"],
  "output_files": [],
  "query_id":    null,
  "entity":      null,
  "verdict":     null,
  "error":       null
}
```

`input_files` and `output_files` are paths relative to the run's root folder. For TI lookups, `model` is `"virustotal-api"` and tokens are `0`.

### Traceability

To trace a finding in `incident_report.md` back to its source:

1. Find the entity value in `backbone/case_state.json` → note its `query_id`
2. `grep <query_id>` in the relevant `agent_calls.jsonl` → get `input_files`
3. The `input_files` paths resolve directly within the audit folder

### `.gitignore`

The `auditing/` folder is runtime output and should not be committed:

```
auditing/
```

## License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

This project is licensed under the [MIT License](LICENSE).  
Copyright (c) 2026 Abdallah Zerkani on behalf of AMAMA team.
