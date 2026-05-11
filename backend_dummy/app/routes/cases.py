"""Case endpoints.

Lists files inside a specific case folder so the frontend can show the user
what evidence is present before they click "Launch analysis".
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query

from ..models import CaseFile, CaseFilesResponse

router = APIRouter(prefix="/api/cases", tags=["cases"])


def _resolve(path: str) -> Path:
    return Path(path).expanduser().resolve()


def _is_inside(child: Path, parent: Path) -> bool:
    """Defense in depth: refuse case names that try to escape the cases/ dir."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


@router.get("/files", response_model=CaseFilesResponse)
async def list_case_files(
    workspace: str = Query(..., description="Absolute path to the analyst's working directory."),
    case: str = Query(..., description="Case folder name (a child of <workspace>/cases/)."),
) -> CaseFilesResponse:
    """List files (non-recursive) inside `<workspace>/cases/<case>/`."""
    ws = _resolve(workspace)
    if not ws.is_dir():
        raise HTTPException(status_code=400, detail="Workspace path is not a directory.")

    cases_dir = ws / "cases"
    if not cases_dir.is_dir():
        raise HTTPException(
            status_code=404, detail="Workspace has no 'cases/' subfolder."
        )

    case_dir = (cases_dir / case).resolve()
    if not _is_inside(case_dir, cases_dir):
        raise HTTPException(status_code=400, detail="Invalid case name.")
    if not case_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"Case '{case}' not found.")

    files: list[CaseFile] = []
    for entry in sorted(case_dir.iterdir(), key=lambda e: e.name.lower()):
        if not entry.is_file():
            continue
        try:
            size = entry.stat().st_size
        except OSError:
            continue
        files.append(CaseFile(name=entry.name, size=size))

    return CaseFilesResponse(workspace=str(ws), case=case, files=files)
