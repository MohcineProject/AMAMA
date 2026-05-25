#!/usr/bin/env python3
"""
pivot_search.py — deterministic multi-key pivot grep.

Reads triage.txt (Agent 1 structured TXT output) and, for each [FINDING] block,
extracts search keys and greps across the full unfiltered Disk_Artifacts/*.txt.

Output: pivot.txt with verbatim line + line-number hits per finding.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Dict, Iterator, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Parse Agent 1 triage.txt output
# ---------------------------------------------------------------------------

def parse_triage(triage_text: str) -> List[Dict[str, str]]:
    """Parse structured triage.txt into a list of finding dicts."""
    findings: List[Dict[str, str]] = []
    in_block = False
    current: Dict[str, str] = {}

    for line in triage_text.splitlines():
        stripped = line.strip()

        if stripped == "[FINDING]":
            if current:
                findings.append(current)
            current = {}
            in_block = True
            continue

        if in_block and ":" in stripped and not stripped.startswith("#"):
            # Lines like "key:   value"
            colon = stripped.index(":")
            k = stripped[:colon].strip().lower().replace(" ", "_")
            v = stripped[colon + 1:].strip()
            current[k] = v

    if current:
        findings.append(current)

    return findings


# ---------------------------------------------------------------------------
# Extract search keys from a finding
# ---------------------------------------------------------------------------

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,}$")
_PATH_RE = re.compile(r"[A-Za-z]:\\")


def _classify_key(term: str) -> str:
    """Return 'path', 'ip', 'hash', or 'word' for search mode selection."""
    if _PATH_RE.search(term):
        return "path"
    if _IP_RE.match(term):
        return "ip"
    if _HASH_RE.match(term):
        return "hash"
    return "word"


def extract_search_keys(finding: Dict[str, str]) -> List[Tuple[str, str]]:
    """
    Return a list of (term, search_mode) tuples for a finding dict.
    search_mode: 'path' (substring, case-insensitive),
                 'ip'/'word'/'hash' (word-boundary regex, case-insensitive)
    """
    keys: List[Tuple[str, str]] = []
    seen: set = set()

    def add(term: str) -> None:
        if not term or len(term) < 3:
            return
        t = term.strip()
        if t in seen:
            return
        seen.add(t)
        mode = _classify_key(t)
        keys.append((t, mode))
        # For path keys, also add just the basename as a word search
        if mode == "path":
            bn = os.path.basename(t.replace("\\", "/"))
            if bn and bn not in seen and len(bn) >= 3:
                seen.add(bn)
                keys.append((bn, "word"))

    # Primary key
    add(finding.get("key", ""))

    # Secondary keys (comma-separated)
    for s in finding.get("secondary", "").split(","):
        add(s.strip())

    # If type is auth/event, extract IP from key
    if finding.get("type") in ("auth", "event", "event_summary"):
        k = finding.get("key", "")
        for part in k.split():
            if _IP_RE.match(part):
                add(part)

    return keys


# ---------------------------------------------------------------------------
# Grep a single file for a list of (term, mode) tuples
# ---------------------------------------------------------------------------

def grep_file(
    filepath: str,
    search_keys: List[Tuple[str, str]],
    max_lines: int,
) -> List[str]:
    """Return up to max_lines matching lines from filepath, with line numbers."""
    hits: List[str] = []

    # Pre-compile patterns
    patterns: List[Tuple[re.Pattern, str]] = []
    for term, mode in search_keys:
        try:
            if mode == "path":
                pat = re.compile(re.escape(term), re.IGNORECASE)
            else:
                pat = re.compile(r"\b" + re.escape(term) + r"\b", re.IGNORECASE)
            patterns.append((pat, term))
        except re.error:
            pass

    if not patterns:
        return hits

    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                if len(hits) >= max_lines:
                    break
                line_rstrip = line.rstrip("\n")
                for pat, _ in patterns:
                    if pat.search(line_rstrip):
                        hits.append(f"L{lineno}: {line_rstrip}")
                        break  # only count once per line even if multiple terms match
    except OSError:
        pass

    return hits


# ---------------------------------------------------------------------------
# Main pivot logic
# ---------------------------------------------------------------------------

def pivot_one(
    finding: Dict[str, str],
    artifact_dir: str,
    all_sources: List[str],
    max_per_file: int,
    max_total: int,
) -> str:
    """
    Run pivot search for one finding. Returns formatted evidence block text.
    """
    search_keys = extract_search_keys(finding)
    if not search_keys:
        return "(no searchable keys extracted from finding)"

    output_parts: List[str] = []
    total_hits = 0

    for filename in all_sources:
        if total_hits >= max_total:
            output_parts.append(f"--- [TRUNCATED — max_total={max_total} reached] ---")
            break

        filepath = os.path.join(artifact_dir, filename)
        if not os.path.exists(filepath):
            continue

        remaining = max_total - total_hits
        file_max = min(max_per_file, remaining)
        hits = grep_file(filepath, search_keys, file_max)

        if hits:
            output_parts.append(f"--- {filename} ({len(hits)} hits) ---")
            output_parts.extend(hits)
            total_hits += len(hits)

    if not output_parts:
        return "(no matching lines in any artifact file)"

    return "\n".join(output_parts)


def run(triage_path: str, artifact_dir: str, cfg: Dict, out_path: str) -> int:
    """Run pivot search for all findings in triage_path. Returns count of findings processed."""
    with open(triage_path, encoding="utf-8", errors="replace") as f:
        triage_text = f.read()

    findings = parse_triage(triage_text)
    if not findings:
        print(f"[pivot] No [FINDING] blocks found in {triage_path}", file=sys.stderr)
        return 0

    all_sources = cfg.get("artifact_files", {}).get("all_pivot_sources", [])
    max_per_file = int(cfg.get("max_lines_per_file", 120))
    max_total = int(cfg.get("max_total_lines_per_target", 400))

    print(f"[pivot] {len(findings)} finding(s) to pivot — searching {len(all_sources)} artifact files", file=sys.stderr)
    print(f"[pivot] caps: max_per_file={max_per_file}, max_total={max_total}", file=sys.stderr)

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)

    with open(out_path, "w", encoding="utf-8", newline="\n") as out:
        for idx, finding in enumerate(findings, 1):
            ftype = finding.get("type", "?")
            fkey = finding.get("key", "?")
            fsev = finding.get("severity", "?")

            out.write(f"{'=' * 72}\n")
            out.write(f"=== FINDING {idx}: type={ftype} severity={fsev} ===\n")
            out.write(f"=== key: {fkey} ===\n")
            out.write(f"{'=' * 72}\n")
            out.write(f"reasons:    {finding.get('reasons', '')}\n")
            out.write(f"source:     {finding.get('source', '')}\n")
            out.write(f"secondary:  {finding.get('secondary', 'none')}\n")
            out.write("\n")

            evidence = pivot_one(finding, artifact_dir, all_sources, max_per_file, max_total)
            out.write(evidence)
            out.write("\n\n")

            # Progress
            hit_count = evidence.count("\nL")
            print(f"[pivot]   finding {idx}/{len(findings)}: {ftype} / {fkey[:60]} → {hit_count} hits", file=sys.stderr)

    print(f"[pivot] Done → {out_path}", file=sys.stderr)
    return len(findings)


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

def _run_tests() -> None:
    import tempfile

    failures = 0

    def assert_true(desc, cond):
        nonlocal failures
        if not cond:
            print(f"  FAIL [{desc}]")
            failures += 1
        else:
            print(f"  PASS [{desc}]")

    def assert_eq(desc, got, expected):
        nonlocal failures
        if got != expected:
            print(f"  FAIL [{desc}]: got {got!r}, expected {expected!r}")
            failures += 1
        else:
            print(f"  PASS [{desc}]")

    print("\n--- parse_triage ---")
    sample_triage = """
=== TRIAGE REPORT ===
Generated: 2026-05-21T00:00:00Z
Summary: Two findings.

[FINDING]
type:       file
key:        C:\\Users\\nfury\\AppData\\Roaming\\loader.exe
secondary:  loader.exe, sha256:abc123def456
severity:   HIGH
reasons:    missing_zone_identifier | high_entropy:entropy=7.83
source:     mft_anomaly

[FINDING]
type:       auth
key:        213.202.233.104
secondary:  none
severity:   MEDIUM
reasons:    brute_force:count=4127
source:     auth_summary
"""
    findings = parse_triage(sample_triage)
    assert_eq("parse: two findings", len(findings), 2)
    assert_eq("parse: first key", findings[0].get("key"), "C:\\Users\\nfury\\AppData\\Roaming\\loader.exe")
    assert_eq("parse: second type", findings[1].get("type"), "auth")

    print("\n--- extract_search_keys ---")
    f1 = findings[0]
    keys1 = extract_search_keys(f1)
    terms1 = [k for k, _ in keys1]
    assert_true("path key present", any("loader.exe" in t for t in terms1))
    assert_true("basename extracted from path", "loader.exe" in terms1)
    assert_true("hash extracted from secondary", any("abc123def456" in t for t in terms1))

    f2 = findings[1]
    keys2 = extract_search_keys(f2)
    terms2 = [k for k, _ in keys2]
    assert_true("IP key present", "213.202.233.104" in terms2)
    ip_modes = [m for k, m in keys2 if k == "213.202.233.104"]
    assert_eq("IP uses word mode", ip_modes[0] if ip_modes else None, "ip")

    print("\n--- grep_file ---")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        fname = f.name
        f.write("L1: type=event id=4625 user=patrick src_ip=213.202.233.104\n")
        f.write("L2: type=event id=4624 user=admin src_ip=10.0.0.1\n")
        f.write("L3: type=file path=C:\\Users\\nfury\\AppData\\Roaming\\loader.exe\n")
        f.write("L4: type=execution path=C:\\Windows\\System32\\calc.exe\n")

    try:
        # Search for IP
        hits = grep_file(fname, [("213.202.233.104", "ip")], max_lines=10)
        assert_eq("IP grep: 1 hit", len(hits), 1)
        assert_true("IP grep: correct line", "4625" in hits[0])

        # Search for path (substring)
        hits = grep_file(fname, [("C:\\Users\\nfury\\AppData", "path")], max_lines=10)
        assert_eq("path grep: 1 hit", len(hits), 1)

        # max_lines cap
        hits = grep_file(fname, [("type=", "word")], max_lines=2)
        assert_eq("max_lines respected", len(hits), 2)

        # No match
        hits = grep_file(fname, [("nonexistent_term_xyz", "word")], max_lines=10)
        assert_eq("no match: empty", len(hits), 0)
    finally:
        os.unlink(fname)

    print("\n--- pivot_one: max_total cap ---")
    with tempfile.TemporaryDirectory() as tmp:
        for i in range(3):
            fname = os.path.join(tmp, f"art_{i}.txt")
            with open(fname, "w") as f:
                for j in range(50):
                    f.write(f"type=event user=testuser line={j}\n")

        test_cfg = {
            "artifact_files": {"all_pivot_sources": ["art_0.txt", "art_1.txt", "art_2.txt"]},
            "max_lines_per_file": 30,
            "max_total_lines_per_target": 50,
        }
        finding = {"type": "auth", "key": "testuser", "secondary": "", "severity": "LOW",
                   "reasons": "test", "source": "test"}
        evidence = pivot_one(finding, tmp, ["art_0.txt", "art_1.txt", "art_2.txt"], 30, 50)
        hit_lines = [l for l in evidence.splitlines() if l.startswith("L")]
        assert_true(f"max_total=50 respected (got {len(hit_lines)})", len(hit_lines) <= 50)
        assert_true("truncated notice present when max_total hit", "TRUNCATED" in evidence)

    print(f"\n{'PASSED' if failures == 0 else f'FAILED ({failures} failures)'} — {failures} failures")
    sys.exit(0 if failures == 0 else 1)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic multi-key pivot grep")
    parser.add_argument("--triage", required=False, default=None,
                        help="Path to triage_combined.txt (merged Agent 1 output)")
    parser.add_argument("--base-dir", default=None,
                        help="Root of disk-agentic-architecture/ (config.json at base_dir/config.json)")
    parser.add_argument("--config", required=False, default=None,
                        help="Explicit path to config.json (overrides --base-dir)")
    parser.add_argument("--artifact-dir", default=None)
    parser.add_argument("--out", default=None)
    parser.add_argument("--test", action="store_true", help="Run unit tests and exit")
    args = parser.parse_args()

    if args.test:
        _run_tests()
        return

    # Resolve config path: explicit --config > --base-dir/config.json > default sibling
    if args.config:
        config_path = args.config
    elif args.base_dir:
        config_path = os.path.join(args.base_dir, "config.json")
    else:
        config_path = os.path.join(os.path.dirname(__file__), "..", "config.json")
    config_path = os.path.normpath(config_path)

    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    base_dir = args.base_dir or os.path.dirname(config_path)
    artifact_dir = args.artifact_dir or os.path.normpath(
        os.path.join(base_dir, cfg.get("artifact_dir", "../Disk_Artifacts"))
    )
    # Read from triage_combined (merged multi-agent output), falling back to legacy triage_output
    triage_path = args.triage or os.path.normpath(
        os.path.join(base_dir, cfg.get("triage_combined", cfg.get("triage_output", "output/triage_combined.txt")))
    )
    out_path = args.out or os.path.normpath(
        os.path.join(base_dir, cfg.get("pivot_output", "output/pivot.txt"))
    )

    run(triage_path, artifact_dir, cfg, out_path)


if __name__ == "__main__":
    main()
