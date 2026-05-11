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

## Endpoints (currently implemented)

| Method | Path | Purpose |
|---|---|---|
| GET  | `/health` | liveness probe |

## Endpoints (planned, added in upcoming commits)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/workspace/validate` | validate a working directory path |
| GET  | `/api/workspace/cases` | list cases under `<workdir>/cases/` |
| GET  | `/api/cases/files` | list files inside a case folder |
| POST | `/api/cases/analyze` | start a (fake) analysis run |
| GET  | `/api/runs/{run_id}/events` | SSE stream of stage events |
