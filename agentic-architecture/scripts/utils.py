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


def grep_file_for_pattern(path: str, pattern: re.Pattern, max_lines: int) -> List[str]:
    hits: List[str] = []
    for line_no, line in read_lines(path):
        if pattern.search(line):
            hits.append(f"L{line_no}: {line}")
            if len(hits) >= max_lines:
                break
    return hits
