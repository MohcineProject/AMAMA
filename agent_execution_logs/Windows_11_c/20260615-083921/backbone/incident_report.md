# Incident Report — Windows_11_c

| Field           | Value                                              |
|-----------------|----------------------------------------------------|
| Generated       | 2026-06-15T09:01:03Z                               |
| Host            | Windows_11_c                                       |
| Modules         | ram · ti                                           |
| Pipeline result | convergence after 0 round(s)                       |

---

## 0. System Profile

| Field          | Value |
|----------------|-------|
| Hostname       | —     |
| OS             | —     |
| Network domain | —     |
| User accounts  | —     |
| Last used      | —     |
| Inferred role  | —     |

No host profile data was recovered from available artefacts; all system identity fields are unavailable for this case.

---

## 1. Executive Summary

The investigation identified **2 CONFIRMED HIGH-severity** findings from 17 total reportable entities, across 2 modules (`ram`, `ti`). Both confirmed findings relate to process hiding via Direct Kernel Object Manipulation (DKOM), where EPROCESS structures were deliberately unlinked from the active process list to conceal malicious activity. Of the remaining 15 INCONCLUSIVE entities, several exhibit overlapping privilege and parent-orphan anomalies that collectively suggest a broader intrusion footprint, though no single entity meets the confirmation threshold without additional artefacts.

---

## 2. Detailed Investigation Notes

### Defense Evasion / In-Memory Implants

#### CONFIRMED

**pid**: `8112`
- ram → CONFIRMED (HIGH): PID 8112 (`olk.exe`) is present in psscan only — absent from pslist — indicating its EPROCESS structure was unlinked from the active doubly-linked list, the hallmark of DKOM-based process hiding. Despite PPID 5556 (`explorer.exe`) being a live, resolvable process, the parent annotation is "unknown", indicating deliberate manipulation of forward/back-links. A second `olk.exe` instance (PID 5868) exists with the same parent and near-identical start time but a clean pslist entry, consistent with a process-hollowing pattern where a legitimate shell is created visibly while the injected/hollowed instance is hidden. No command line or executable path is recoverable, consistent with evasion.

**pid**: `8060`
- ram → CONFIRMED (HIGH): PID 8060 (`svchost.exe`) appears exclusively in psscan and is absent from pslist — canonical DKOM indicator. PPID 888 is absent from all process lists, severing lineage verification. No command-line data is recoverable. The process ran approximately two minutes (18:28:35–18:30:41 UTC) and then terminated, a pattern consistent with a short-lived loader, injector, or stager completing its work and exiting to reduce dwell-time visibility. The combination of psscan-only visibility, orphaned PPID, and missing command line across three independent artefact types constitutes multi-signal confirmation of process hiding.

---

#### INCONCLUSIVE

**pid**: `3088`
- ram → INCONCLUSIVE: PID 3088 (`svchost.exe`) appears exclusively in psscan, with PPID 888 absent from the process list. Ran for exactly 60 seconds (18:29:23–18:30:23 UTC) with no recoverable command line. The psscan-only visibility, missing parent, zero-length command line, and precise 60-second lifetime are suspicious but no corroborating evidence (malfind, suspicious DLLs, network connections, registry persistence) was extracted.

**pid**: `1188`
- ram → INCONCLUSIVE: `AggregatorHost.exe` at a legitimate System32 path. Three anomalies noted: PPID 3148 absent from pslist; SeTcbPrivilege, SeDebugPrivilege, and SeImpersonatePrivilege all simultaneously Present/Enabled/Default (consistent with a SYSTEM token but also with token manipulation); and an alleged non-standard DLL (`UpdateReboot.dll`) referenced by an earlier agent but not present in extracted evidence. File-hash verification of the binary and token/SID dump needed to resolve.

**pid**: `4040`
- ram → INCONCLUSIVE: `MicrosoftEdgeUpdate.exe` (PID 4040) with PPID 1524 absent from pslist. Full SYSTEM-level token (SeTcbPrivilege, SeDebugPrivilege, SeImpersonatePrivilege, SeLoadDriverPrivilege all enabled). An unresolvable DLL entry (`-`/`-`) at base 0x7fffe9120000 appears in both this process and its child (PID 8256), suggesting a shared section rather than per-process injection. No malfind hits, network connections, or registry persistence artefacts present.

**pid**: `8256`
- ram → INCONCLUSIVE: `MicrosoftEdgeUpdate.exe` child of PID 4040. All signals are derivative of the parent: inherited SYSTEM privileges, identical unresolvable DLL entry at 0x7fffe9120000, parentage from a flagged process. Command line (`/ua /installsource core`) is a standard EdgeUpdate invocation. No independent malicious signal; status contingent on resolution of PID 4040.

**pid**: `8048`
- ram → INCONCLUSIVE: `taskhostw.exe` with PPID 1524 absent from pslist. Argument `$(Arg0)` is an unexpanded placeholder. Privilege footprint (SeDebugPrivilege, SeLoadDriverPrivilege, SeRestorePrivilege, SeImpersonatePrivilege, SeBackupPrivilege, SeTakeOwnershipPrivilege, SeSystemEnvironmentPrivilege, SeManageVolumePrivilege) is more consistent with a LOCAL SYSTEM or high-integrity administrative token than a typical task-host invocation. DLLs visible are clean System32 paths; no malfind or network artefacts present.

**pid**: `7352`
- ram → INCONCLUSIVE: `taskhostw.exe` with PPID 1524 absent from pslist. GUID `{222A245B-E637-4AE9-A93F-A59CA119A75E}` is the documented COM class for .NET Runtime Optimization (NGen), which canonically spawns `ngentask.exe` children (PIDs 8432, 6388 — both consistent with legitimate NGen maintenance). Near-complete SYSTEM token is what Windows assigns for SYSTEM-context taskhostw.exe. No malfind, network, or registry persistence artefacts to confirm malice.

**pid**: `6516`
- ram → INCONCLUSIVE: `SecurityHealthService.exe` (PID 6516) with PPID 888 absent from pslist. SeTcbPrivilege, SeDebugPrivilege, and SeImpersonatePrivilege all enabled — consistent with a legitimate SYSTEM-context service. Executable path is canonical System32 location; DLLs are System32 paths. No corroborating malicious evidence. Unresolved parent relationship prevents clean rejection.

**pid**: `8616`
- ram → INCONCLUSIVE: `MicrosoftEdgeUpdate.exe` with PPID 888 absent from pslist. Full LocalSystem token (35 privileges including SeTcbPrivilege, SeDebugPrivilege, SeAssignPrimaryTokenPrivilege, SeLoadDriverPrivilege, SeImpersonatePrivilege). Binary path is canonical; `/svc` invocation is standard; DLLs (ntdll.dll, wow64.dll) are clean System32 paths consistent with a 32-bit process on a 64-bit host. SYSTEM-level token is anomalous for an update service but no malfind, network, or persistence artefacts present.

**pid**: `5348`
- ram → INCONCLUSIVE: `svchost.exe` (PID 5348) in psscan only, ExitTime 18:30:48 UTC, PPID 888 unlisted. ~2-minute lifespan consistent with both a transient legitimate service host and a short-lived malicious implant. No cmdline, DLL provenance, network activity, privilege footprint, or malfind data to resolve.

**pid**: `3340`
- ram → INCONCLUSIVE: `backgroundTask` (truncation of `BackgroundTaskHost.exe`), psscan only with ExitTime 18:30:57 UTC, PPID 576 absent from pslist. Structural signals are weak and individually benign; total absence of path/cmdline data prevents confident rejection.

**pid**: `9044`
- ram → INCONCLUSIVE: `backgroundTask` (psscan only), PPID 576, ExitTime 18:31:08 UTC. Most probable explanation is a legitimate short-lived backgroundTaskHost instance; no cmdline, DLL list, privilege data, network connections, or malfind hits recovered.

**pid**: `9168`
- ram → INCONCLUSIVE: `RuntimeBroker.` (legitimate 14-character EPROCESS truncation of `RuntimeBroker.exe`), psscan only, ~3-minute lifespan, PPID 576. No positive evidence of malice; psscan-only visibility and absent cmdline cannot be fully resolved from available evidence.

**pid**: `9460`
- ram → INCONCLUSIVE: `dllhost.exe` (psscan only), ~5-second lifetime, PPID 576 absent from pslist. No DLL list, privilege data, malfind hits, or network connections. Missing path/cmdline prevents ruling out a hollowed or injected COM surrogate.

**pid**: `9812`
- ram → INCONCLUSIVE: `backgroundTask` (psscan only), PPID 576, ~2-minute lifespan (18:29:05–18:31:10 UTC). No cmdline, image path, DLL list, privilege data, malfind hits, or network artefacts.

**pid**: `11040`
- ram → INCONCLUSIVE: `WMIADAP.exe` with PPID 3260 absent from pslist. Binary path, command-line arguments (`/F /T /R` — standard WMI adapter refresh flags), and DLL set are consistent with a legitimate scheduled WMI invocation. One residual signal: device-namespace prefix (`\\?\C:\WINDOWS\system32\wbem\WMIADAP.EXE`) on the image path is atypical for a standard system process as recorded by Volatility. No malfind data, suspicious DLLs, or registry persistence present.

---

#### Threat Intel Enrichment

No threat-intel enrichment was performed.

---

#### INCONCLUSIVE Triage Tiers

**Tier A — High-suspicion** (two or more independent signals):

- **pid 3088** (`svchost.exe`): psscan-only visibility + missing parent (PPID 888) + zero-length command line + precise 60-second lifetime. MITRE T1564.001, T1055 referenced.
- **pid 1188** (`AggregatorHost.exe`): orphaned parent (PPID 3148) + abnormally broad enabled privilege set (SeTcbPrivilege/SeDebugPrivilege/SeImpersonatePrivilege all active simultaneously) + unverifiable non-standard DLL reference (`UpdateReboot.dll`).
- **pid 4040** (`MicrosoftEdgeUpdate.exe`): orphaned parent + full SYSTEM token with SeTcbPrivilege/SeDebugPrivilege/SeImpersonatePrivilege/SeLoadDriverPrivilege enabled + unresolvable DLL entry (`-`/`-`).
- **pid 8048** (`taskhostw.exe`): orphaned parent (PPID 1524) + anomalously broad administrative token (8+ high-powered privileges including SeLoadDriverPrivilege, SeRestorePrivilege, SeTakeOwnershipPrivilege) + unexpanded `$(Arg0)` placeholder argument.
- **pid 5348** (`svchost.exe`): psscan-only + orphaned parent (PPID 888) + no cmdline/path — overlaps temporally with confirmed PIDs 8060 and 3088 sharing the same absent PPID 888.

**Tier B — Low-priority** (single weak signal; address only after higher-priority items):

- **pid 8256** (`MicrosoftEdgeUpdate.exe`): all signals derivative of parent PID 4040; no independent indicator.
- **pid 7352** (`taskhostw.exe`): orphaned parent only; spawn chain (ngentask.exe children) consistent with documented NGen task.
- **pid 6516** (`SecurityHealthService.exe`): orphaned parent only; canonical path and DLLs; SYSTEM token expected for this service.
- **pid 8616** (`MicrosoftEdgeUpdate.exe`): orphaned parent only; all DLLs clean; standard invocation.
- **pid 3340** (`backgroundTask`): psscan-only with ExitTime; orphaned parent; single weak structural signal.
- **pid 9044** (`backgroundTask`): psscan-only with ExitTime; single weak structural signal.
- **pid 9168** (`RuntimeBroker.`): psscan-only with ExitTime; truncated name is legitimate; single weak signal.
- **pid 9460** (`dllhost.exe`): psscan-only; ~5-second lifetime; single weak signal.
- **pid 9812** (`backgroundTask`): psscan-only with ExitTime; PPID 576 expected for UWP task hosts; single weak signal.
- **pid 11040** (`WMIADAP.exe`): device-namespace path prefix only; all other indicators benign.

---

## 3. Attack Timeline

- **2026-05-12 18:24:50 UTC** — PID 8112 (`olk.exe`) created under explorer.exe (PPID 5556); EPROCESS subsequently unlinked from the active process list via DKOM to hide the process. A second `olk.exe` (PID 5868) created near-simultaneously with a clean pslist entry, consistent with a process-hollowing pattern.
- **2026-05-12 18:28:35 UTC** — PID 8060 (`svchost.exe`) created under unknown parent (PPID 888, unlisted); EPROCESS unlinked from active process list via DKOM.
- **2026-05-12 18:29:33 UTC** — PID 8112 (`olk.exe`) terminates after approximately 4 minutes and 43 seconds.
- **2026-05-12 18:30:41 UTC** — PID 8060 (`svchost.exe`) terminates after approximately 2 minutes and 6 seconds.

*Note: No confirmed initial access, persistence, lateral movement, or impact artefacts are present in available evidence. The confirmed activity represents only the in-memory hiding stage; the full intrusion chain cannot be reconstructed from available artefacts.*

---

## 4. MITRE ATT&CK Mapping

| Phase                        | Technique                              | Entity / Evidence                                                                 |
|------------------------------|----------------------------------------|-----------------------------------------------------------------------------------|
| Defense Evasion              | T1564.001 — Hidden Files and Directories (Process Hiding) | pid 8112 (`olk.exe`) — psscan-only, EPROCESS unlinked |
| Defense Evasion              | T1055 — Process Injection              | pid 8112 (`olk.exe`) — dual olk.exe instances consistent with process hollowing   |
| Defense Evasion              | T1564.001 — Hidden Files and Directories (Process Hiding) | pid 8060 (`svchost.exe`) — psscan-only, EPROCESS unlinked |
| Defense Evasion              | T1055 — Process Injection              | pid 8060 (`svchost.exe`) — orphaned parent, missing cmdline, short-lived stager   |

---

## 5. Indicators of Compromise

| Category    | Indicator                                                                                                  |
|-------------|------------------------------------------------------------------------------------------------------------|
| File        | —                                                                                                          |
| Network     | —                                                                                                          |
| Registry    | —                                                                                                          |
| Behavioural | PID 8112 (`olk.exe`): EPROCESS unlinked from pslist doubly-linked list (DKOM); psscan offset 0xcd8a12eec080; active 18:24:50–18:29:33 UTC; parent PPID 5556 (explorer.exe) with unknown EPROCESS link |
| Behavioural | PID 8060 (`svchost.exe`): EPROCESS unlinked from pslist doubly-linked list (DKOM); psscan offset 0xcd8a126d2080; active 18:28:35–18:30:41 UTC; PPID 888 absent from all process lists |

---

## 6. Pipeline Metadata

| Field                   | Value                              |
|-------------------------|------------------------------------|
| Case ID                 | Windows_11_c                       |
| Report generated        | 2026-06-15T09:01:03Z               |
| Orchestrator model      | claude-haiku-4-5-20251001          |
| Report model            | claude-sonnet-4-6                  |
| Routing rounds          | 0                                  |
| Termination             | convergence                        |
| Modules                 | ram · ti                           |
| Pre-report LLM calls    | 1                                  |
| Pre-report tokens in    | 1514                               |
| Pre-report tokens out   | 9                                  |

---

## 7. Evidence Traceability Index

_Machine-generated (no LLM) — maps every finding to the tool execution that produced it. Find an entity cited above, read its `finding_id` / `query_id` and evidence `source_file:line`, then `grep` the `call_id` in the named log (`produced_by`) to reach the exact agent call (`input_files` / `output_files` / `timestamp` / tokens). The evidence column shows the first locator with `(+N more)` when a finding cites several lines; the **complete evidence list — every `source_file:line` plus its verbatim `content` — is in `backbone/traceability.json`** (this table mirrors that file)._

| Entity | finding_id / query_id | module | verdict | severity | evidence (file:line) | produced_by (agent → call_id) | log |
|---|---|---|---|---|---|---|---|
| `pid:11040` | `ram-chunk_026-f001` | ram | INCONCLUSIVE | — | `dlllist.txt:7405` (+4 more) | ram/pivot_analyst → `c22307f6-7dd8-47b3-a7e8-44c696fcda7e` | `ram/agent_calls.jsonl` |
| `pid:1188` | `ram-chunk_001-f001` | ram | INCONCLUSIVE | — | `aggregated_analyst.txt:67` (+5 more) | ram/pivot_analyst → `fba3cd03-ee5e-4770-8d1c-7ad83c21bde7` | `ram/agent_calls.jsonl` |
| `pid:3088` | `ram-chunk_002-f001` | ram | INCONCLUSIVE | — | `psscan.txt:105` | ram/pivot_analyst → `00fee5c8-ec01-48ad-ac74-2e31b4ab9b85` | `ram/agent_calls.jsonl` |
| `pid:3340` | `ram-chunk_004-f001` | ram | INCONCLUSIVE | — | `psscan.txt:175` | ram/pivot_analyst → `f4c57e3b-6939-4390-9741-d8f769526c53` | `ram/agent_calls.jsonl` |
| `pid:4040` | `ram-chunk_006-f001` | ram | INCONCLUSIVE | — | `pslist.txt:81` (+5 more) | ram/pivot_analyst → `1b62cab8-27f2-43d7-b6e7-5f29a9f0b9a7` | `ram/agent_calls.jsonl` |
| `pid:5348` | `ram-chunk_010-f001` | ram | INCONCLUSIVE | — | `psscan.txt:174` | ram/pivot_analyst → `7dd59321-9f44-4224-8a4d-e8bd213ee536` | `ram/agent_calls.jsonl` |
| `pid:6516` | `ram-chunk_013-f001` | ram | INCONCLUSIVE | — | `pslist.txt:122` (+5 more) | ram/pivot_analyst → `05dd4a40-abff-48fd-b809-f9517de1443c` | `ram/agent_calls.jsonl` |
| `pid:7352` | `ram-chunk_019-f001` | ram | INCONCLUSIVE | — | `pslist.txt:103` (+8 more) | ram/pivot_analyst → `3a5192e9-a86b-42c9-95be-d55bb88582f1` | `ram/agent_calls.jsonl` |
| `pid:8048` | `ram-chunk_021-f002` | ram | INCONCLUSIVE | — | `cmdline.txt:124` (+5 more) | ram/pivot_analyst → `8eff6142-933e-44f9-b2dd-23fbca84a536` | `ram/agent_calls.jsonl` |
| `pid:8060` | `ram-chunk_021-f001` | ram | CONFIRMED | HIGH | `psscan.txt:137` | ram/pivot_analyst → `8eff6142-933e-44f9-b2dd-23fbca84a536` | `ram/agent_calls.jsonl` |
| `pid:8112` | `ram-chunk_011-f001` | ram | CONFIRMED | HIGH | `psscan.txt:155` | ram/pivot_analyst → `a8c1238b-f254-4608-8387-19f4586b3d1b` | `ram/agent_calls.jsonl` |
| `pid:8256` | `ram-chunk_006-f002` | ram | INCONCLUSIVE | — | `pslist.txt:110` (+4 more) | ram/pivot_analyst → `1b62cab8-27f2-43d7-b6e7-5f29a9f0b9a7` | `ram/agent_calls.jsonl` |
| `pid:8616` | `ram-chunk_023-f001` | ram | INCONCLUSIVE | — | `aggregated_analyst.txt:3895` (+7 more) | ram/pivot_analyst → `cc4a9d0d-6b27-4eb5-a889-0302d78d5766` | `ram/agent_calls.jsonl` |
| `pid:9044` | `ram-chunk_024-f001` | ram | INCONCLUSIVE | — | `psscan.txt:164` | ram/pivot_analyst → `b39d1f24-ded7-48c1-b952-aeca74c09fe0` | `ram/agent_calls.jsonl` |
| `pid:9168` | `ram-chunk_024-f002` | ram | INCONCLUSIVE | — | `psscan.txt:114` | ram/pivot_analyst → `b39d1f24-ded7-48c1-b952-aeca74c09fe0` | `ram/agent_calls.jsonl` |
| `pid:9460` | `ram-chunk_025-f001` | ram | INCONCLUSIVE | — | `psscan.txt:94` | ram/pivot_analyst → `bfe10cf9-c5d4-4925-bf97-1d7d6ee32b71` | `ram/agent_calls.jsonl` |
| `pid:9812` | `ram-chunk_025-f002` | ram | INCONCLUSIVE | — | `psscan.txt:178` | ram/pivot_analyst → `bfe10cf9-c5d4-4925-bf97-1d7d6ee32b71` | `ram/agent_calls.jsonl` |
