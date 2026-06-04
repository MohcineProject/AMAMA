# Disk Forensics Module

A three-layer agentic framework for automated disk forensics: mounts an E01/EWF forensic image, collects Windows artifacts, then runs a multi-agent AI pipeline that produces a structured, evidence-traceable investigation report for the Backbone orchestrator.

---

## Prerequisites

- **Platform:** SIFT Workstation (Ubuntu 24.04 LTS) — most system tools come pre-installed
- **Python:** 3.10+ (use `.venv/bin/python` — never the system Python under PEP 668)
- **System tools:** `ewfmount` (from `libewf-tools`), `mmls`, `icat`, `fsstat`, `fuse3`, `ntfs-3g`
- **Optional but recommended:** .NET 9.0 SDK + Eric Zimmerman tools at `/opt/zimmermantools/` — enables deeper registry/event log/execution parsing. Python fallbacks cover all collectors if .NET is unavailable.
- **Root/sudo:** required for image mounting and artifact collection

---

## Installation

From the `Modules/Disk/` directory:

```bash
sudo bash install.sh
```

This script (idempotent — safe to re-run):
1. Installs APT system packages (`libewf-tools`, `sleuthkit`, `fuse3`, `ntfs-3g`, etc.)
2. Creates `.venv/` and installs all Python packages from `requirements.txt`
3. Optionally installs .NET 9.0 SDK from the Microsoft APT repository
4. Optionally downloads Eric Zimmerman forensic tools to `/opt/zimmermantools/`
5. Runs `--check-deps` to print a final status summary

**Flags:**
- `--no-dotnet` — skip .NET installation (Python fallbacks will be used for registry, event log, and execution collectors)
- `--no-zimmerman` — skip Zimmerman tools download

---

## Quick Start

### One-command end-to-end (recommended for testing)

```bash
sudo .venv/bin/python run_e2e.py --case-id my_case --out results/
```

Runs all four stages in sequence — mount → collect → pipeline → scan — with fast collection mode and no LLM calls (dry run) by default. Produces `results/scan_result.json`.

To enable the full AI pipeline (requires `ANTHROPIC_API_KEY`):

```bash
sudo .venv/bin/python run_e2e.py --case-id my_case --out results/ --llm
```

All parameters are optional:

| Flag | Default | Description |
|---|---|---|
| `--case-id` | timestamp (e.g. `case-20260602-143201`) | Case identifier |
| `--out` | `results/` | Output directory for `scan_result.json` |
| `--image-dir` | `Disk_image/` | Directory containing the forensic image |
| `--no-llm` / `--llm` | `--no-llm` | Dry-run or live LLM calls |
| `--fast` / `--full` | `--fast` | Fast MFT triage or full parse with PE entropy |

---

### Step-by-step (manual control)

### Step 1 — Mount the disk image

```bash
sudo .venv/bin/python disk-image-mounter/mount_image.py Disk_image/your-image.E01
```

This mounts the EWF image, identifies the Windows NTFS partition, extracts `$MFT`, and writes a complete `config.json` with zero manual editing. To unmount:

```bash
sudo .venv/bin/python disk-image-mounter/mount_image.py --umount
```

### Step 2 — Collect artifacts

```bash
# Fast mode (~13 min on a 24 GB image — recommended for initial triage):
sudo .venv/bin/python disk-collector/disk_collector.py \
    --config config.json --fast \
    --out-dir Disk_Artifacts/ \
    --summary-out Disk_Artifacts/collector_summary.json

# Full mode (complete MFT parse + PE entropy analysis — more thorough, slower):
sudo .venv/bin/python disk-collector/disk_collector.py \
    --config config.json --full \
    --out-dir Disk_Artifacts/ \
    --summary-out Disk_Artifacts/collector_summary.json
```

To collect specific artifacts only:

```bash
sudo .venv/bin/python disk-collector/disk_collector.py \
    --config config.json --only mft zregistry zevtx \
    --out-dir Disk_Artifacts/
```

### Step 3 — Run the agentic pipeline

```bash
cd disk-agentic-architecture

# Dry-run (no API calls — verify preprocessing and pipeline stages):
./../.venv/bin/python scripts/run_pipeline.py --no-llm

# Live run (requires an Anthropic API key):
export ANTHROPIC_API_KEY=sk-ant-...
./../.venv/bin/python scripts/run_pipeline.py
```

### Step 4 — Produce structured output for the orchestrator

```bash
# From disk-agentic-architecture/:
./../.venv/bin/python scripts/scan.py \
    --case-id <case_id> \
    --out <output_dir>/
# Produces: <output_dir>/scan_result.json (ModuleScanResult schema)
```

---

## What Each Step Produces

| Step | Output | Description |
|---|---|---|
| Mount | `config.json` | Mount points, partition offsets, artifact paths, tuning keys |
| Collect | `Disk_Artifacts/*.txt` | One text file per artifact type in uniform `KEY=VALUE` record format |
| Collect | `Disk_Artifacts/collector_summary.json` | Record counts, timing, collector status |
| Pipeline (preprocess) | `output/TRIAGE_INPUT_*.txt` | Noise-reduced, whitelisted input for triage agents |
| Pipeline (triage) | `output/triage_combined.txt` | Findings from 3 specialized triage agents, merged |
| Pipeline (pivot) | `output/pivot.txt` | Verbatim artifact evidence for each finding |
| Pipeline (analyst) | `output/analyst.txt` | Analyst-grade narrative with CONFIRMED/INCONCLUSIVE verdicts |
| scan.py | `scan_result.json` | Structured JSON (ModuleScanResult) for the orchestrator |

---

## Orchestrator Integration

Two CLI entry points expose the module to the Backbone orchestrator:

- **`scripts/scan.py`** (INITIAL mode) — parses `output/analyst.txt`, emits a `ModuleScanResult` JSON with confirmed/inconclusive IOCs, entity types, MITRE ATT&CK mappings, and verbatim evidence citations. Can also invoke the full pipeline with `--run-pipeline`.

- **`scripts/query.py`** (QUERY mode) — answers an `EntityQuery` from the orchestrator: looks up a specific entity (file path, hash, IP, domain, registry key, etc.) across all artifact files, optionally interprets the evidence with an LLM, and returns an `EntityFindings` JSON.

Schema contracts (shared from `Backbone/schemas/` — same files used by the RAM module):
- `module_scan_result.schema.json`
- `entity_findings.schema.json`
- `entity_query.schema.json`

---

## Performance

| Mode | Wall time (dmz-ftp-cdrive.E01, 24.6 GB) | MFT records |
|---|---|---|
| Fast | ~13 min | 53,383 (suspicious paths only, PE skipped) |
| Full | Not yet benchmarked | All ~249,845 entries with PE entropy |

Collectors run in two parallel phases: Phase 1 (persistence, browser, execution, registry) completes first and is immediately available to the triage agents while Phase 2 (MFT, event logs) continues in the background.

If .NET/Zimmerman tools are not available, Python fallbacks activate automatically. Coverage is slightly reduced (shimcache limited to Win10/11 format; event log archives skipped) but the pipeline stays fully functional.

---

## Dependency Check

To verify the environment without running a full collection:

```bash
sudo .venv/bin/python disk-collector/disk_collector.py \
    --config disk-collector/config.example.json --check-deps
```

Expected output when fully configured:
```
Mode: FULL (dotnet + Zimmerman)
```

Expected output without .NET:
```
Mode: PYTHON-FALLBACK
```

---

## Known Issues

- **Shimcache on Windows Server 2012 R2** — ~~fixed~~. The Python fallback now supports both `CACH` (Win10/11) and `\x80\x00\x00\x00` (Win8/Server 2012/2012 R2) magic. Both formats share the same 128-byte header and per-entry layout.
- **Amcache record count discrepancy** — partially mitigated. `_amcache_python()` now deduplicates by (path, hash), reducing noise. The remaining gap versus Zimmerman (which filters to unassociated files only) requires a `ProgramId`-based filter that needs verification against the actual hive — deferred.
- **`python -m disk.scan` / `python -m disk.query`** — not yet implemented. Entry points remain `python scripts/scan.py` and `python scripts/query.py`.
- **`eventlog_security.txt` may be missing** — if collecting from an image without a re-mount, regenerate by re-running the `zevtx` collector after mounting.
- **APT package name** — SIFT uses `libewf-tools` (from its PPA), not `ewf-tools`. The `install.sh` script handles this automatically.
- **sudo PATH** — on SIFT, `sudo -E PATH=...` does not override `PATH` (secure_path in sudoers). Always invoke via the full venv path: `sudo .venv/bin/python`.
