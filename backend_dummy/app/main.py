"""AMAMA dummy backend.

A FastAPI app that mimics the real DFIR triage backend by returning canned
responses and streaming fake stage events. It exists so the frontend can be
built and demoed end-to-end before the real pipeline is wired up.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(
    title="AMAMA dummy backend",
    description="Mock backend for the AMAMA DFIR triage frontend.",
    version="0.1.0",
)

# The frontend dev server runs on Vite's default port (5173).
# We allow a few common dev ports to make life easy.
_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


@app.get("/health", response_model=HealthResponse, tags=["meta"])
async def health() -> HealthResponse:
    """Simple liveness probe used by the frontend and ops checks."""
    return HealthResponse(status="ok", service="amama-backend-dummy", version="0.1.0")
