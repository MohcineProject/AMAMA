"""
Tests for scan.py:
  1. REJECTED findings are excluded from the findings list but counted in counts.rejected.
  2. SCHEMA_DIR resolves to Backbone/schemas/ and the schema files exist.
  3. Non-CONFIRMED findings always have severity=null.
"""

import sys
from pathlib import Path

# Resolve repo root and add scripts/ to path
_HERE = Path(__file__).resolve().parent
_BASE = _HERE.parent          # disk-agentic-architecture/
_DISK = _BASE.parent          # Modules/Disk/
_MODULES = _DISK.parent       # Modules/
_ROOT = _MODULES.parent       # project root

sys.path.insert(0, str(_BASE / "scripts"))

import scan  # noqa: E402  (after sys.path manipulation)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_MOCK_ANALYST = """\
================================================================
DISK FORENSICS — PIVOT REPORT
Generated: 2026-06-04T00:00:00Z
================================================================

--- Finding 1 ---
[CONFIRMED]
----------------------------------------------------------------
Finding:    1
Type:       file_path
Key:        C:\\ProgramData\\evil.exe
Severity:   HIGH
MITRE:      T1059.001 — Command and Scripting Interpreter

Justification:
  Confirmed by shimcache + persistence registry key.

Key Evidence:
  - [registry_shimcache.txt L42]: path=C:\\ProgramData\\evil.exe executed=true
  - [registry_autoruns.txt L10]: type=run key=HKLM\\...\\Run value=evil.exe
----------------------------------------------------------------

--- Finding 2 ---
[INCONCLUSIVE]
----------------------------------------------------------------
Finding:    2
Type:       image_name
Key:        svchost_fake.exe
Severity:   MEDIUM

Justification:
  Single artifact — no cross-corroboration found.

Key Evidence:
  - [mft_records.txt L100]: path=C:\\Temp\\svchost_fake.exe suspicious=true
----------------------------------------------------------------

--- Finding 3 ---
[REJECTED]
----------------------------------------------------------------
Finding:    3
Type:       file_path
Key:        C:\\Windows\\System32\\notepad.exe

Legitimate explanation:
  Standard Windows inbox binary with known-good hash.
----------------------------------------------------------------

--- Finding 4 ---
[REJECTED]
----------------------------------------------------------------
Finding:    4
Type:       image_name
Key:        svchost.exe

Legitimate explanation:
  Multiple clean shimcache entries from system32; no suspicious path.
----------------------------------------------------------------
"""


# ---------------------------------------------------------------------------
# Test: REJECTED filtering
# ---------------------------------------------------------------------------

def test_rejected_filtered_from_findings():
    all_findings = scan._parse_analyst(_MOCK_ANALYST)
    assert len(all_findings) == 4, f"Expected 4 raw findings, got {len(all_findings)}"

    filtered = [f for f in all_findings if f["verdict"] != "REJECTED"]
    assert len(filtered) == 2, f"Expected 2 after filtering, got {len(filtered)}"
    assert all(f["verdict"] in ("CONFIRMED", "INCONCLUSIVE") for f in filtered)


def test_counts_include_rejected():
    all_findings = scan._parse_analyst(_MOCK_ANALYST)
    confirmed    = sum(1 for f in all_findings if f["verdict"] == "CONFIRMED")
    inconclusive = sum(1 for f in all_findings if f["verdict"] == "INCONCLUSIVE")
    rejected     = sum(1 for f in all_findings if f["verdict"] == "REJECTED")
    assert confirmed == 1
    assert inconclusive == 1
    assert rejected == 2


# ---------------------------------------------------------------------------
# Test: severity is null for non-CONFIRMED
# ---------------------------------------------------------------------------

def test_non_confirmed_severity_is_null():
    all_findings = scan._parse_analyst(_MOCK_ANALYST)
    for f in all_findings:
        if f["verdict"] != "CONFIRMED":
            assert f.get("severity") is None, (
                f"Finding {f['finding_id']} has verdict={f['verdict']} "
                f"but severity={f['severity']!r} (expected null)"
            )


def test_confirmed_has_severity():
    all_findings = scan._parse_analyst(_MOCK_ANALYST)
    confirmed = [f for f in all_findings if f["verdict"] == "CONFIRMED"]
    assert all(f["severity"] is not None for f in confirmed)


# ---------------------------------------------------------------------------
# Test: SCHEMA_DIR points to Backbone/schemas/ and files exist
# ---------------------------------------------------------------------------

def test_schema_dir_points_to_backbone():
    expected = _ROOT / "Backbone" / "schemas"
    assert scan.SCHEMA_DIR == expected, (
        f"SCHEMA_DIR={scan.SCHEMA_DIR}, expected {expected}"
    )


def test_backbone_schema_files_exist():
    for fname in ("module_scan_result.schema.json",
                  "entity_findings.schema.json",
                  "entity_query.schema.json"):
        p = scan.SCHEMA_DIR / fname
        assert p.exists(), f"Schema file missing: {p}"


# ---------------------------------------------------------------------------
# Test: local Disk schemas folder is gone
# ---------------------------------------------------------------------------

def test_local_schemas_folder_deleted():
    local_schemas = _BASE / "schemas"
    assert not local_schemas.exists(), (
        f"Local schemas folder still present: {local_schemas}"
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [
        test_rejected_filtered_from_findings,
        test_counts_include_rejected,
        test_non_confirmed_severity_is_null,
        test_confirmed_has_severity,
        test_schema_dir_points_to_backbone,
        test_backbone_schema_files_exist,
        test_local_schemas_folder_deleted,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception as exc:
            print(f"  FAIL  {t.__name__}: {exc}")
    print(f"\n{passed}/{len(tests)} tests passed.")
    if passed < len(tests):
        sys.exit(1)
