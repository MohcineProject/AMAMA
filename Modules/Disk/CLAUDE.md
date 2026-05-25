# HOW TO BUILD: Disk Forensics Agentic Framework

> **Audience:** A Claude instance (or developer) building a DFIR pipeline for disk/filesystem analysis.
---

## 0. Current Status (as of 2026-05-25, session 7)

### What is built and tested

**Layer 1 — Disk Image Mounter** (`disk-image-mounter/mount_image.py`) — **COMPLETE & TESTED**
- Mounts EWF/E01 forensic images via `ewfmount` FUSE, identifies the Windows NTFS partition, extracts `$MFT` via `icat`, mounts the volume read-only with the kernel `ntfs3` driver, discovers browser artifact paths, writes `config.json`.
- **Plug-and-play config.json generation** (session 5): discovers the Windows username from browser paths, probes for `Amcache.hve` with both case variants (`AppCompat`/`appcompat`), and merges all tuning keys from `disk-collector/config.example.json`. Point it at any E01 and get a fully-correct `config.json` with zero manual editing.
- Tested end-to-end against `Disk_image/base-wkstn-05-cdrive.E01` (~29.5 GB, user `nfury`, computer `BASE-WKSTN-05`, domain `SHIELDBASE.LAN`).
- `--umount` path also tested and working.
- **Mount state:** NTFS mounted at `/tmp/dfir_ntfs`, EWF at `/tmp/dfir_ewf` (`base-wkstn-05-cdrive.E01`).

**Layer 2 — Disk Collector** (`disk-collector/disk_collector.py` + collectors + 3 Zimmerman wrappers) — **ALL COLLECTORS WORKING — FINAL OUTPUT IN `Disk_Artifacts/`**

| Collector | Command key | Status | Output | Records (session 4) |
|---|---|---|---|---|
| MFT | `mft` | ✅ WORKS | `mft_records.txt` | **145,628** (post filter-fix; directory filter now applied) |
| **Registry (Zimmerman)** | `zregistry` | ✅ WORKS | `registry_autoruns.txt`, `registry_misc.txt` | **19,481** (1,757 autoruns + 17,724 misc) |
| **Event logs (Zimmerman)** | `zevtx` | ✅ **NEW — WORKS** | `eventlog_security/system/application/other.txt` | **556,997** (554,970 security + 1,052 system + 967 other + 8 app) |
| **Execution (Zimmerman)** | `zexecution` | ✅ WORKS | `registry_shimcache.txt`, `amcache_records.txt` | **527 shimcache** (amcache: hive corrupt) |
| Persistence | `persistence` | ✅ WORKS | `scheduled_tasks.txt`, `wmi_subscriptions.txt` | **230** tasks + WMI |
| Browser | `browser` | ✅ WORKS | `browser_history.txt` | **309** Chrome records |

**Recommended collection command (session 4 onwards — use `zevtx` not `eventlog`):**
```bash
sudo .venv/bin/python disk-collector/disk_collector.py --config config.json \
  --only mft zregistry zevtx zexecution persistence browser \
  --out-dir Disk_Artifacts/ --summary-out Disk_Artifacts/collector_summary.json
```

**Fast triage mode (~20–30 min, suspicious files only):**
```bash
sudo .venv/bin/python disk-collector/disk_collector.py --config config.json \
  --only mft zregistry zevtx zexecution persistence browser \
  --triage-mode --out-dir Disk_Artifacts/
```

**config.json is regenerated on every mount — no manual editing required.** All tuning keys (`mft_exclude_paths`, `mft_exclude_extensions`, `zimmerman_tools`, etc.) survive remounts via `config.example.json`. To persist analyst customizations (e.g. custom `suspicious_paths`), edit `disk-collector/config.example.json` — those values take precedence over built-in defaults.

**Layer 3 — Agentic Pipeline** (`disk-agentic-architecture/`) — **COMPLETE (sessions 6–7)**

Architecture: multi-agent, 4 stages.

| Script | Status | Purpose |
|---|---|---|
| `scripts/preprocess.py` | ✅ BUILT | Noise-reduction pass; writes 3 specialized input files |
| `scripts/triage_agent.py` | ✅ BUILT | Agent 1 — `--mode persistence\|events\|mft` (required) |
| `scripts/pivot_search.py` | ✅ BUILT | Deterministic multi-key grep across all artifact files |
| `scripts/pivot_analyst.py` | ✅ BUILT | Agent 2 — validates findings against pivot evidence |
| `scripts/run_pipeline.py` | ✅ BUILT | Orchestrator — runs all 4 stages sequentially |
| `prompts/agent1_persistence.md` | ✅ BUILT | Agent 1 prompt: persistence/execution/browser domain |
| `prompts/agent1_events.md` | ✅ BUILT | Agent 1 prompt: authentication/event logs domain |
| `prompts/agent1_mft.md` | ✅ BUILT | Agent 1 prompt: MFT structural anomalies domain |

**Multi-agent architecture (session 7):**

`preprocess.py` writes **three** specialized input files
- `output/TRIAGE_INPUT_PERSISTENCE.txt` — publisher-whitelisted registry/task/shimcache/browser records
- `output/TRIAGE_INPUT_EVENTS.txt` — deduplicated event log summaries
- `output/TRIAGE_INPUT_MFT.txt` — tiered-scored MFT records + stats block

Three `triage_agent.py --mode <X>` runs produce `triage_persistence.txt`, `triage_events.txt`, `triage_mft.txt`. A merge step produces `triage_combined.txt` (findings prefixed P/E/M for traceability). `pivot_search.py` and `pivot_analyst.py` consume the combined file unchanged.

**MFT anomaly scoring (session 7):** `preprocess.py` now scores every MFT record (+4 exec ext in suspicious path, +3 high entropy, +3 SI/FN delta, +2 attack window, +2 Recycle.Bin, +2 missing Zone.Id, -5 NSRL match, +1 deep path in system dirs). Only the top-N records (default 200) by score reach the LLM. Filtered-out records go to `output/audit/mft_filtered.jsonl`. Whitelist suppression prevents trusted system files from scoring high.

**Run the pipeline:**
```bash
cd disk-agentic-architecture
# Dry-run (no API calls):
./../.venv/bin/python scripts/run_pipeline.py --no-llm

# Live run:
export ANTHROPIC_API_KEY=sk-ant-...
./../.venv/bin/python scripts/run_pipeline.py
```

Not yet built: `report_agent.py`, `nsrl_filter.py`.

### Bugs fixed — all sessions

| # | File | Description |
|---|---|---|
| 1 | `requirements.txt` | `python-registry>=1.4.0` does not exist on PyPI (max is 1.3.1). Changed to `>=1.3.0`. |
| 2 | `mount_image.py` | Bare-partition E01: skip `--sizelimit` on `losetup` when `start_sector==0` and `description=="(whole device)"`. |
| 3 | `mount_image.py` | `ntfs-3g` "last sector" error on EWF images — fall back to kernel `mount -t ntfs3`. |
| 4 | `mft_collector.py` | PE analysis called on every file (JPEGs, videos). Fix: only for PE-ext or suspicious paths. |
| 5 | `pe_analyzer.py` | Added `compute_entropy=False` mode to skip full-file read for non-suspicious PEs. |
| 6 | `eventlog_collector.py` | ET falsy-element bug — `find(...) or find(...)` returned None for leaf elements. Fixed with `_find()` helper using `is not None`. |
| 7 | `eventlog_collector.py` | 213 archive `.evtx` files (21 MB each) caused multi-hour runtime. Skip in `--max-records` mode. |
| 8 | `persistence_collector.py` | Task XML files are UTF-16 LE. Sniff missed them. Accept `\xff\xfe`/`\xfe\xff` BOM. |
| 9 | `registry_collector.py` | NK record error crashed entire collector. Per-walker try/except added. |
| 10 | `disk_collector.py` | Added `--max-records N` for quick testing. |
| 11 | `eventlog_collector.py` | **Critical:** `allow_set = set()` when `max_records` set → event ID filter OFF in test mode → 33,862 records instead of ~2k. Fixed: always apply `high_signal_event_ids`. Result: 94% reduction. |
| 12 | `config.json` | Amcache path used `AppCompat` (capital C); actual NTFS path is `appcompat` (lowercase). |
| 13 | `mount_image.py` | `config.json` lost `mft_exclude_paths`, `mft_exclude_extensions`, `zimmerman_tools` on every remount. Fixed: `build_config()` now loads `config.example.json` as a base, adds `_discover_username()` + `_find_amcache()` helpers, and constructs a complete config in one pass. |


### Environment

- SIFT Workstation, Ubuntu 24.04, kernel 6.8.0-106
- Python 3.12 — **must use `.venv/bin/python`** (PEP 668 externally-managed-environment)
- All packages installed: `pefile`, `python-registry 1.3.1`, `python-evtx`, `analyzeMFT`, `pyscca 20250915`, `pytsk3 20260418`
- System tools confirmed: `ewfmount`, `mmls`, `icat`, `fsstat`, `losetup`, `ntfs-3g`, `qemu-nbd`
- **.NET 9.0.115** installed — enables Zimmerman tools at `/opt/zimmermantools/`
- **Critical:** Always invoke Zimmerman tools via `dotnet <tool>.dll`, **not** `dotnet <tool>.exe`. The `.exe` files are Windows-only PE binaries; the `.dll` files are cross-platform .NET assemblies.

### Zimmerman tools available (`/opt/zimmermantools/`)

| Tool | DLL path | Purpose | Status |
|---|---|---|---|
| RECmd | `RECmd/RECmd.dll` | Registry parser (66 plugins, DFIRBatch.reb) | ✅ works |
| EvtxECmd | `EvtxeCmd/EvtxECmd.dll` | Event log parser (453 maps) | ✅ works (not yet integrated) |
| AppCompatCacheParser | `AppCompatCacheParser.dll` | Shimcache | ✅ works |
| AmcacheParser | `AmcacheParser.dll` | Amcache | ✅ works (image hive corrupt) |
| MFTECmd | `MFTECmd.dll` | $MFT parser | ✅ available (not yet integrated) |
| SQLECmd | `SQLECmd/SQLECmd.dll` | SQLite: Chrome/Firefox/Edge/cloud (95 maps) | ✅ available (not yet integrated) |
| LECmd | `LECmd.dll` | LNK file parser | ✅ available (not yet integrated) |
| RBCmd | `RBCmd.dll` | Recycle Bin parser | ✅ available (not yet integrated) |

**Future integration candidates:** EvtxECmd (richer event field extraction than Python), SQLECmd (replaces browser_collector — covers Edge + Firefox with 95 format maps), LECmd (LNK files not yet collected).

## 1. Executive Overview

**Goal:** Build a 4-stage multi-agent pipeline (Collector → Triage Agent → Pivot Search → Analyst Agent) that ingests parsed disk artifacts and produces an analyst-grade investigation, with every finding traceable to a verbatim line in a source artifact file.

## 2. Conservative Verdict Model: CONFIRMED / INCONCLUSIVE / REJECTED

The three-tier verdict system is forensically sound regardless of artifact type:
- **CONFIRMED** — clear corroborating evidence across at least two independent artifact types
- **INCONCLUSIVE** — some signal, but insufficient to confirm or rule out
- **REJECTED** — evidence shows legitimate behavior, OR no corroborating evidence found

The bias rule transfers verbatim: **prefer false negatives over false positives.** An analyst who trusts your CONFIRMED verdicts is your most important asset.

Single-artifact findings must never be CONFIRMED. For disk forensics this means: a suspicious file in MFT alone = INCONCLUSIVE until corroborated by prefetch/shimcache/event log/registry.

## 3. Evidence Traceability — Line Numbers, Verbatim Excerpts
Every finding in the analyst output must cite:
- The source artifact file (e.g., `mft_records.txt`)
- The line number (e.g., `L1842:`)
- The verbatim line content

This is non-negotiable. It is what separates a forensically sound report from an LLM hallucination. The report agent must only surface IOCs that appear in verbatim evidence lines.

## 4. Configuration File

under `disk-agentic-architecture/config.json`:

## 5. Critical Implementation Warnings

These are disk forensics pitfalls that commonly break pipelines built by developers familiar only with memory forensics.

### 5.1 Timestamp Timezone Hell
Windows NTFS stores timestamps as 100-nanosecond intervals since **January 1, 1601, 00:00:00 UTC**. Python's `datetime` epoch is January 1, 1970. Never do raw arithmetic between Windows timestamps and Python timestamps without converting:

```python
import datetime

EPOCH_DIFF = 116444736000000000  # 100-nanosecond intervals between 1601 and 1970

def windows_to_datetime(windows_timestamp: int) -> datetime.datetime:
    unix_ts = (windows_timestamp - EPOCH_DIFF) / 10_000_000
    return datetime.datetime.fromtimestamp(unix_ts, tz=datetime.timezone.utc)
```

Normalize every timestamp to ISO8601 UTC before storing in FIND_EVIL_DISK records.

### 5.2 Timestomping Is a False Positive Risk
Not all SI/FN timestamp differences indicate timestomping. The Windows kernel legitimately updates only $STANDARD_INFORMATION timestamps for many operations (file reads, ACL changes). Require at least **two independent corroborating signals** before an Agent 2 CONFIRMED verdict on timestomping. Acceptable corroboration pairs:
- SI/FN mismatch + USN journal creation timestamp contradicts MFT
- SI/FN mismatch + file modification timestamp predates OS install date
- SI/FN mismatch + the file appears in the Recycle Bin before its claimed creation date

Lookup time drops from minutes to microseconds.

### 5.3 Deleted Files Are Partial Records
When $MFT entries are reused, deleted file metadata may be partially overwritten. The MFT collector will produce records with `deleted=true, path=UNKNOWN` or `deleted=true, path=PARTIAL`. Handle gracefully:
- Include them in FIND_EVIL_DISK output (deleted executables are often significant)
- Mark the `path` field as `UNKNOWN` or `PARTIAL` rather than omitting the record
- Agent 1 should know: a deleted executable in a suspicious path is elevated, not ignored

### 5.4 Event Logs May Be Cleared — Check First
Before any other event log analysis, check whether events 1102 (Security log cleared) or 104 (System log cleared) are present. If they are:
- Note the clearing timestamp
- Treat the absence of other security events before that timestamp as an evidence gap, not as absence of activity
- The Confidence Assessment section of the report must explicitly state: "Security event log was cleared at [timestamp]. Events prior to this time are unavailable."
- Agent 2 must not issue REJECTED verdicts based on absence of event log evidence when the log was cleared

### 5.5 Zone.Identifier ADS as Lateral Movement Signal
Every file downloaded via a browser receives a `Zone.Identifier` Alternate Data Stream recording the source URL and zone. If a suspicious executable in `%APPDATA%` or similar has **no Zone.Identifier** but would logically have been downloaded from the internet (based on its name or functionality), this strongly suggests:
- It was transferred via SMB/RDP (lateral movement) rather than downloaded by the user
- Or it was created locally by another process (dropper)

This is one of the most actionable disk-specific signals. Implement ADS enumeration in `mft_collector.py` and flag absence of Zone.Identifier on suspicious executables in Agent 1.

*End of HOW_TO_BUILD.md*
