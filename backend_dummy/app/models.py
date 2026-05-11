"""Pydantic models shared across routes.

These mirror the TypeScript types the frontend uses for the API contract.
Keep them in one place so request/response shapes stay consistent.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class ValidateWorkspaceRequest(BaseModel):
    path: str = Field(
        ...,
        description="Absolute path to the analyst's working directory.",
        examples=["/home/analyst/DFIR_agent", r"D:\\dfir\\work"],
    )


class ValidateWorkspaceResponse(BaseModel):
    valid: bool = Field(..., description="True if the path exists and is a directory.")
    has_cases_dir: bool = Field(
        ...,
        description="True if a `cases/` subfolder exists inside the workspace.",
    )
    resolved_path: str = Field(
        ..., description="Absolute path the server resolved (useful for debugging)."
    )
    message: Optional[str] = Field(
        default=None,
        description="Human-readable explanation when valid is False.",
    )


class CasesListResponse(BaseModel):
    workspace: str
    cases: list[str] = Field(
        default_factory=list,
        description="Case folder names inside <workspace>/cases/, sorted alphabetically.",
    )


class CaseFile(BaseModel):
    name: str = Field(..., description="File name relative to the case folder.")
    size: int = Field(..., description="File size in bytes.")
    sha256: Optional[str] = Field(
        default=None,
        description="Optional SHA-256 hex digest. Not computed by default for speed.",
    )


class CaseFilesResponse(BaseModel):
    workspace: str
    case: str
    files: list[CaseFile] = Field(default_factory=list)


class AnalyzeRequest(BaseModel):
    workspace: str = Field(..., description="Absolute path to the analyst's working directory.")
    case: str = Field(..., description="Case folder name to analyze.")


class AnalyzeResponse(BaseModel):
    run_id: str = Field(..., description="Identifier to subscribe to via the SSE events stream.")
    workspace: str
    case: str
