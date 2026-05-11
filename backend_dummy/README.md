# backend_dummy

FastAPI mock backend used to build and test the AMAMA frontend end-to-end before the real DFIR pipeline is wired up. It serves canned/realistic responses for the workspace/case endpoints and streams fake stage events over SSE for the analysis pipeline.

## Status

Placeholder. The skeleton (FastAPI app + `/health`) is added in the next commit.

## Planned stack

- FastAPI
- Uvicorn
- pydantic
- `sse-starlette` for the analysis event stream

## Planned endpoints

| Method | Path | Purpose |
|---|---|---|
| GET  | `/health` | sanity check |
| POST | `/api/workspace/validate` | validate working directory path |
| GET  | `/api/workspace/cases` | list cases under `<workdir>/cases/` |
| GET  | `/api/cases/files` | list files inside a case folder |
| POST | `/api/cases/analyze` | start a (fake) analysis run |
| GET  | `/api/runs/{run_id}/events` | SSE stream of stage events |

## Run (coming next commit)

```bash
python -m venv .venv
# Windows
.venv\Scripts\Activate.ps1
# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
