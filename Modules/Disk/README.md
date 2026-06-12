# Disk Forensics Module

A three-layer agentic framework for automated disk forensics: mounts an E01/EWF forensic image, collects Windows artifacts, then runs a multi-agent AI pipeline that produces a structured, evidence-traceable investigation report for the Backbone orchestrator.

---

## Prerequisites

Runs on a SIFT Workstation (Ubuntu); image mounting and artifact collection require root. The system tools (`ewfmount`, `mmls`, `icat`, `fsstat`, `fuse3`, `ntfs-3g`) and the Python dependencies (`requirements.txt`) are installed as part of the repo setup — see the [root README](../../README.md).

Optional but recommended: .NET 9.0 SDK + Eric Zimmerman tools at `/opt/zimmermantools/` — enables deeper registry/event log/execution parsing. Python fallbacks cover all collectors if .NET is unavailable.

Live LLM runs additionally require `ANTHROPIC_API_KEY` in the environment.

---

## How it runs

The module is driven by the Backbone orchestrator, which loads `DiskModule` (`disk-agentic-architecture/disk_module.py`) and calls its `scan()` / `query()` methods. Everything is configured from `Backbone/config/orchestrator.yaml`:

```yaml
modules:
  - class: disk_module.DiskModule
    path: ../../Modules/Disk/disk-agentic-architecture
    kwargs:
      use_llm: true
      image_dir: /abs/path/to/Modules/Disk/Disk_image   # mount + collect from here (omit to reuse existing artifacts)
      collect_mode: fast                                # 'fast' (default) or 'full' (full MFT parse + PE entropy)
      artifact_dir: /abs/path/to/Modules/Disk/Disk_Artifacts
```

When `image_dir` is set, a `scan()` runs all four stages end-to-end. Mounting needs root, so the orchestrator runs the mount/collect steps under `sudo -n` (passwordless sudo — the SIFT default). Omit `image_dir` to skip mount+collect and analyse whatever is already in `Disk_Artifacts/`.

### The four stages

| Stage | Component | Output |
|---|---|---|
| **Mount** | `disk-image-mounter/` | Mounts the EWF/raw image, identifies the Windows NTFS partition, extracts `$MFT`, and writes a complete `config.json` (mount points, partition offsets, artifact paths, tuning keys) |
| **Collect** | `disk-collector/` | `Disk_Artifacts/*.txt` — one file per artifact type in uniform `KEY=VALUE` record format — plus `collector_summary.json` (record counts, timing, collector status) |
| **Agentic pipeline** | `disk-agentic-architecture/` | Preprocess (`output/TRIAGE_INPUT_*.txt`, noise-reduced and whitelisted) → 3 specialized triage agents (`output/triage_combined.txt`) → pivot grep (`output/pivot.txt`, verbatim artifact evidence) → analyst (`output/analyst.txt`, CONFIRMED/INCONCLUSIVE verdicts) |
| **Scan result** | `disk-agentic-architecture/` | `scan_result.json` (`ModuleScanResult` schema) for the orchestrator |

---

## Orchestrator Integration

- **`DiskModule.scan(case_id)`** — runs the stages above and emits a `ModuleScanResult` with confirmed/inconclusive IOCs, entity types, MITRE ATT&CK mappings, and verbatim evidence citations.
- **`DiskModule.query(query)`** — answers an `EntityQuery` from the orchestrator: looks up a specific entity across all artifact files, optionally interprets the evidence with an LLM, and returns an `EntityFindings`.

Supported entity types: `file_path`, `image_name`, `hash_md5`, `hash_sha1`, `hash_sha256`, `registry_key`, `user_sid` (searched across all artifacts) plus `ip`, `domain`, `url` (best-effort — limited artifact coverage). `pid` and `mutex` return `NOT_APPLICABLE` (memory-only entities).

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

If .NET/Zimmerman tools are not available, Python fallbacks activate automatically. Coverage is slightly reduced (event log archives skipped) but the pipeline stays fully functional.
