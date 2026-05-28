"""Validate inbound/outbound JSON against Backbone schemas."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import jsonschema

_SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "schemas"


@lru_cache(maxsize=8)
def load_schema(name: str) -> dict[str, Any]:
    path = _SCHEMAS_DIR / name
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _validate(payload: dict[str, Any], schema_name: str) -> None:
    jsonschema.validate(payload, load_schema(schema_name))


def validate_query(payload: dict[str, Any]) -> None:
    _validate(payload, "entity_query.schema.json")


def validate_findings(payload: dict[str, Any]) -> None:
    _validate(payload, "entity_findings.schema.json")


def validate_scan_result(payload: dict[str, Any]) -> None:
    _validate(payload, "module_scan_result.schema.json")
