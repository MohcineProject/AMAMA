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

Schema contracts (local copies in `disk-agentic-architecture/schemas/`):
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