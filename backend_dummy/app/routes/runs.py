"""Analysis-run endpoints.

POST /api/cases/analyze    -> register a run, return run_id
GET  /api/runs/{id}/events -> SSE stream of fake stage events

The pipeline is faked here using `app.fixtures.PIPELINE`: for each stage we
emit a `stage_start`, several `stage_progress` events (with `asyncio.sleep`
pacing so the UI animates smoothly), then a `stage_result`, then a
`stage_complete`. Between stages we pause for ~800ms so the frontend's
transition animation feels deliberate.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any, AsyncIterator

from fastapi import APIRouter, HTTPException
from sse_starlette.sse import EventSourceResponse

from ..fixtures import PIPELINE
from ..models import AnalyzeRequest, AnalyzeResponse

router = APIRouter(tags=["runs"])

# In-memory run registry. Good enough for a dummy; processes restart fresh.
_RUNS: dict[str, dict[str, Any]] = {}

# Timing (seconds). Tuned so the whole pipeline takes ~20s end-to-end.
_PROGRESS_STEP_DELAY = 0.45
_BETWEEN_STAGES_DELAY = 0.8
_PRE_RUN_DELAY = 0.3


def _event(payload: dict[str, Any]) -> dict[str, str]:
    """sse-starlette expects dict events; we ship JSON in the `data` field."""
    return {"event": "message", "data": json.dumps(payload)}


@router.post("/api/cases/analyze", response_model=AnalyzeResponse)
async def start_analysis(body: AnalyzeRequest) -> AnalyzeResponse:
    """Register an analysis run and return its run_id.

    The work doesn't start here; it starts when the SSE endpoint is opened.
    That way the run is naturally bound to the (single) subscriber and there's
    no need for a background task queue in this dummy.
    """
    run_id = uuid.uuid4().hex
    _RUNS[run_id] = {"workspace": body.workspace, "case": body.case, "consumed": False}
    return AnalyzeResponse(run_id=run_id, workspace=body.workspace, case=body.case)


@router.get("/api/runs/{run_id}/events")
async def run_events(run_id: str) -> EventSourceResponse:
    """Stream the pipeline as SSE messages.

    Each event's `data` is a JSON object with shape:
      {type: "stage_start"|"stage_progress"|"stage_result"|"stage_complete"|"run_complete"|"error", ...}
    """
    run = _RUNS.get(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Unknown run_id.")

    workspace = run["workspace"]
    case = run["case"]

    async def stream() -> AsyncIterator[dict[str, str]]:
        try:
            await asyncio.sleep(_PRE_RUN_DELAY)
            yield _event(
                {"type": "run_start", "run_id": run_id, "workspace": workspace, "case": case}
            )

            for stage_def in PIPELINE:
                stage = stage_def["stage"]
                kind = stage_def["kind"]

                yield _event({"type": "stage_start", "stage": stage, "kind": kind})

                for percent, message in stage_def["progress"]:
                    await asyncio.sleep(_PROGRESS_STEP_DELAY)
                    yield _event(
                        {
                            "type": "stage_progress",
                            "stage": stage,
                            "percent": percent,
                            "message": message,
                        }
                    )

                yield _event(
                    {"type": "stage_result", "stage": stage, "data": stage_def["result"]}
                )
                yield _event({"type": "stage_complete", "stage": stage})

                await asyncio.sleep(_BETWEEN_STAGES_DELAY)

            yield _event({"type": "run_complete", "run_id": run_id})
        except asyncio.CancelledError:
            # Client closed the connection; nothing to clean up beyond the
            # registry entry, which we drop on completion below.
            raise
        finally:
            _RUNS.pop(run_id, None)

    return EventSourceResponse(stream())
