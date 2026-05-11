"""Workspace endpoints.

The frontend asks the backend to validate a typed working-directory path and
list the cases inside it. We do real filesystem lookups here (even though this
package is named "dummy") because the user expects to point at real folders
on their machine; only the analysis pipeline is faked.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query

from ..models import (
    CasesListResponse,
    ValidateWorkspaceRequest,
    ValidateWorkspaceResponse,
)

router = APIRouter(prefix="/api/workspace", tags=["workspace"])


def _resolve(path: str) -> Path:
    """Expand ~ and resolve to an absolute Path without requiring it to exist."""
    return Path(path).expanduser().resolve()


@router.post("/validate", response_model=ValidateWorkspaceResponse)
async def validate_workspace(body: ValidateWorkspaceRequest) -> ValidateWorkspaceResponse:
    """Check that the given path exists, is a directory, and contains `cases/`.

    Returns structured information instead of raising so the frontend can show
    a useful error message in the UI.
    """
    resolved = _resolve(body.path)

    if not resolved.exists():
        return ValidateWorkspaceResponse(
            valid=False,
            has_cases_dir=False,
            resolved_path=str(resolved),
            message="Path does not exist.",
        )
    if not resolved.is_dir():
        return ValidateWorkspaceResponse(
            valid=False,
            has_cases_dir=False,
            resolved_path=str(resolved),
            message="Path exists but is not a directory.",
        )

    cases_dir = resolved / "cases"
    has_cases = cases_dir.is_dir()

    return ValidateWorkspaceResponse(
        valid=True,
        has_cases_dir=has_cases,
        resolved_path=str(resolved),
        message=None if has_cases else "Workspace is valid but has no 'cases/' subfolder yet.",
    )


@router.get("/cases", response_model=CasesListResponse)
async def list_cases(
    path: str = Query(..., description="Absolute path to the analyst's working directory."),
) -> CasesListResponse:
    """List immediate subfolders of `<path>/cases/` as case names."""
    resolved = _resolve(path)
    if not resolved.is_dir():
        raise HTTPException(status_code=400, detail="Workspace path is not a directory.")

    cases_dir = resolved / "cases"
    if not cases_dir.is_dir():
        return CasesListResponse(workspace=str(resolved), cases=[])

    cases = sorted(
        entry.name for entry in cases_dir.iterdir() if entry.is_dir() and not entry.name.startswith(".")
    )
    return CasesListResponse(workspace=str(resolved), cases=cases)
