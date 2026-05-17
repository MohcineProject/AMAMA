#!/usr/bin/env python3
import argparse
import json
import os
import re
from typing import Dict, List

from utils import grep_file_for_pattern, load_json, now_iso, write_json


def safe_compile_pid(pid: str) -> re.Pattern:
    return re.compile(r"\b" + re.escape(pid) + r"\b")


_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_DIR = os.path.dirname(_SCRIPTS_DIR)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--triage", required=True)
    parser.add_argument("--config", default=os.path.join(_REPO_DIR, "config.json"))
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    triage = load_json(args.triage)
    with open(args.config, "r", encoding="utf-8", errors="ignore") as f:
        config = json.load(f)

    pids = [p.get("pid") for p in triage.get("suspicious_processes", []) if p.get("pid")]
    paths = [p.get("path") for p in triage.get("suspicious_paths", []) if p.get("path")]

    by_pid: Dict[str, Dict[str, List[str]]] = {}
    by_path: Dict[str, Dict[str, List[str]]] = {}

    for pid in pids:
        by_pid[pid] = {}
        pattern = safe_compile_pid(str(pid))
        for fname in config.get("pid_files", []):
            fpath = os.path.join(args.artifact_root, fname)
            if not os.path.exists(fpath):
                continue
            hits = grep_file_for_pattern(fpath, pattern, config.get("max_lines_per_file", 100))
            if hits:
                by_pid[pid][fname] = hits

    for path in paths:
        by_path[path] = {}
        pattern = re.compile(re.escape(path), re.IGNORECASE)
        for fname in config.get("path_files", []):
            fpath = os.path.join(args.artifact_root, fname)
            if not os.path.exists(fpath):
                continue
            hits = grep_file_for_pattern(fpath, pattern, config.get("max_lines_per_file", 100))
            if hits:
                by_path[path][fname] = hits

    output = {
        "generated_at": now_iso(),
        "targets": {"pids": pids, "paths": paths},
        "by_pid": by_pid,
        "by_path": by_path,
        "notes": []
    }

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    write_json(args.out, output)


if __name__ == "__main__":
    main()
