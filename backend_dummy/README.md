# backend_dummy

FastAPI mock backend used to build and test the AMAMA frontend end-to-end before the real DFIR pipeline is wired up. It serves canned responses for the workspace/case endpoints and streams fake stage events over SSE for the analysis pipeline.

## Stack

- FastAPI
- Uvicorn (ASGI server)
- pydantic v2
- `sse-starlette` (for the analysis event stream, added in a later commit)

## Run

```bash
# from backend_dummy/
python -m venv .venv

# Windows (PowerShell)
.venv\Scripts\Activate.ps1
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Then check it's alive:

```bash
curl http://localhost:8000/health
# {"status":"ok","service":"amama-backend-dummy","version":"0.1.0"}
```

Interactive Swagger docs: <http://localhost:8000/docs>

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET  | `/health` | liveness probe |
| POST | `/api/workspace/validate` | validate a working directory path |
| GET  | `/api/workspace/cases` | list cases under `<workdir>/cases/` |
| GET  | `/api/cases/files` | list files inside a case folder |
| POST | `/api/cases/analyze` | start a (fake) analysis run, returns `run_id` |
| GET  | `/api/runs/{run_id}/events` | SSE stream of stage events |

### Quick tests

```bash
curl -X POST http://localhost:8000/api/workspace/validate \
  -H "Content-Type: application/json" \
  -d '{"path":"/home/analyst/DFIR_agent"}'

curl "http://localhost:8000/api/workspace/cases?path=/home/analyst/DFIR_agent"

curl "http://localhost:8000/api/cases/files?workspace=/home/analyst/DFIR_agent&case=INCIDENT_2025_08_08"

# kick off a run
curl -X POST http://localhost:8000/api/cases/analyze \
  -H "Content-Type: application/json" \
  -d '{"workspace":"/home/analyst/DFIR_agent","case":"INCIDENT_2025_08_08"}'
# -> {"run_id":"...","workspace":"...","case":"..."}

# stream events (use -N to disable buffering)
curl -N http://localhost:8000/api/runs/<run_id>/events
```

## SSE event shapes

Each SSE `data:` field is a JSON object:

| `type` | Fields | When |
|---|---|---|
| `run_start` | `run_id, workspace, case` | once at the very beginning |
| `stage_start` | `stage, kind` | when a stage begins |
| `stage_progress` | `stage, percent, message` | several times per stage |
| `stage_result` | `stage, data` | full result of a stage |
| `stage_complete` | `stage` | after the result has been sent |
| `run_complete` | `run_id` | once at the end |
| `error` | `stage?, message` | on failure |

The pipeline runs the 5 active stages in order: `collector -> agent1 -> grep -> agent2 -> agent3`.
