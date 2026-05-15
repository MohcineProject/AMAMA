#!/usr/bin/env python3
import json
import fnmatch
import os
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Tuple


def now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def write_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=False)


def read_lines(path: str) -> Iterable[Tuple[int, str]]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for idx, line in enumerate(f, start=1):
            yield idx, line.rstrip("\n")


def normalize_path(value: str) -> str:
    return value.strip().replace("/", "\\").lower()


def load_whitelist(path: str) -> List[str]:
    patterns: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            patterns.append(normalize_path(raw))
    return patterns


def is_whitelisted_path(value: str, patterns: List[str]) -> bool:
    if not value:
        return False
    norm = normalize_path(value)
    for pat in patterns:
        if fnmatch.fnmatchcase(norm, pat):
            return True
    return False


def iter_strings(obj: Any) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from iter_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from iter_strings(v)


def extract_processes(data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    procs = data.get("processes") or data.get("processes:") or {}
    if isinstance(procs, list):
        return {str(i): p for i, p in enumerate(procs, start=1) if isinstance(p, dict)}
    if isinstance(procs, dict):
        return {str(k): v for k, v in procs.items() if isinstance(v, dict)}
    return {}


def find_value_by_key_substring(obj: Dict[str, Any], needle: str) -> str:
    for key, val in obj.items():
        if needle.lower() in str(key).lower():
            if isinstance(val, str):
                return val
            if isinstance(val, (int, float)):
                return str(val)
    return ""


def pick_strings(obj: Any) -> List[str]:
    return [s for s in iter_strings(obj) if isinstance(s, str) and s.strip()]


def grep_file_for_pattern(path: str, pattern: re.Pattern, max_lines: int) -> List[str]:
    hits: List[str] = []
    for line_no, line in read_lines(path):
        if pattern.search(line):
            hits.append(f"L{line_no}: {line}")
            if len(hits) >= max_lines:
                break
    return hits
