# Incident Report — my-case-001

| Field           | Value                                              |
|-----------------|----------------------------------------------------|
| Generated       | 2026-06-16T01:20:43Z                               |
| Host            | my-case-001                                        |
| Modules         | ram · ti                                           |
| Pipeline result | convergence after 0 round(s)                       |

---

## 0. System Profile

| Field          | Value                                            |
|----------------|--------------------------------------------------|
| Hostname       | —                                                |
| OS             | —                                                |
| Network domain | —                                                |
| User accounts  | —                                                |
| Last used      | —                                                |
| Inferred role  | —                                                |

No host profile data was extracted from available artefacts; all system context fields are unavailable for this case.

---

## 1. Executive Summary

The investigation identified **CRITICAL**-severity confirmed findings across 5 confirmed entities out of 21 total reportable entities, investigated by 2 modules (ram, ti). Confirmed findings include process hollowing of a csrss.exe instance (PID 424), a masquerading svchost.exe (PID 1148), a rogue non-system binary (`coreupdater.exe`, PID 8324) placed in System32, a hollowed RuntimeBroker.exe carrying a SYSTEM-equivalent token with a tampered module list (PID 8128), and an abused WMI provider host (PID 8416) with a fully enabled SYSTEM token. Confirmed findings (5) substantially outnumber inconclusive-only entities (16), and the combined weight of CRITICAL and HIGH verdicts indicates an advanced post-exploitation implant framework is active in memory.

---

## 2. Detailed Investigation Notes

### Defense Evasion / In-Memory Implants

**pid**: `424` (csrss.exe)
- ram → CONFIRMED (CRITICAL): Four independent signals converge on process hollowing. The command line extracted from cmdline.txt and pstree.txt is entirely non-ASCII garbled/shellcode bytes rather than the structured `ObjectDirectory=\Windows SharedSection=...` string legitimate csrss.exe always carries. The `malware_pebmasquerade` plugin flagged this PID with two True values, indicating PEB image path manipulation. The privilege token is wildly over-provisioned: SeDebugPrivilege, SeTcbPrivilege, SeCreateTokenPrivilege, SeAssignPrimaryTokenPrivilege, SeLoadDriverPrivilege, and SeImpersonatePrivilege are all Present and Enabled — consistent with a SYSTEM-level implant that has absorbed the full token. The on-disk path (`\Device\HarddiskVolume3\Windows\System32\csrss.exe`) is legitimate, confirming the hollowing pattern: the binary shell is real, the content is not.
- **MITRE**: T1055.012 (Process Hollowing)

**pid**: `1148` (svchost.exe)
- ram → CONFIRMED (HIGH): Three independent signals converge. The command-line field is absent ("-") — every legitimate svchost.exe carries a `-k <ServiceGroup>` argument; its absence is a reliable indicator of process hollowing or masquerade. Parent PID 616 is not present in the process list, indicating spawning outside normal SCM lineage. Most decisively, the privilege token is a near-complete SYSTEM-level set: SeDebugPrivilege, SeTcbPrivilege, SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege, SeLoadDriverPrivilege, and SeCreateTokenPrivilege are all present and several actively enabled. The binary path resolves to System32 (legitimate on disk), confirming a hollowed or impersonated svchost used as a post-exploitation host process.
- **MITRE**: T1036.005 (Masquerading: Match Legitimate Name or Location)

**pid**: `8128` (RuntimeBroker.exe)
- ram → CONFIRMED (CRITICAL): Legitimate RuntimeBroker.exe runs in user context with a minimal privilege set. PID 8128 instead carries a near-complete Windows privilege assignment including SeCreateTokenPrivilege, SeTcbPrivilege, SeDebugPrivilege, SeLoadDriverPrivilege, SeImpersonatePrivilege, SeBackupPrivilege, and SeRestorePrivilege — consistent only with a SYSTEM-level or manipulated token. The DLL module list contains only three entries: the executable itself, one unnamed/unparseable entry (name and path both '-'), and a third entry with a non-page-aligned base address (`0x6bf5fb7fff0c`), an implausible size of ~103 MB (`0x6886903` bytes), and a load count of 4253 — all structurally impossible for a legitimate loaded module, consistent with injected shellcode or a tampered InMemoryOrderModuleList. A healthy RuntimeBroker instance loads dozens of system DLLs; the near-empty list indicates the legitimate module list has been replaced or the process has been hollowed. The benign-looking cmdline (`-Embedding`) is the standard COM activation argument, suggesting the attacker preserved it to evade cmdline-based detection while manipulating process internals.
- **MITRE**: T1134 (Access Token Manipulation), T1055.012 (Process Hollowing)

### Execution / Persistence

**pid**: `8324` (coreupdater.exe)
- ram → CONFIRMED (HIGH): `coreupdater.exe` is not a recognised Windows system binary, yet it was placed in `\Windows\System32\` — a classic masquerade-by-location technique. The process ran for approximately 2 minutes 21 seconds with zero active threads at capture time. Its command line is suppressed ("-") and its parent (PPID 4008) is absent from every process listing, indicating the parent either exited after spawning it or was deliberately hidden. The privilege token is SYSTEM-equivalent: SeDebugPrivilege and SeImpersonatePrivilege are Present and Enabled; SeLoadDriverPrivilege, SeBackupPrivilege, and SeRestorePrivilege are Present. The `malware_pebmasquerade` plugin independently flagged this binary. The convergence of masquerade path, orphaned parent, hidden cmdline, zero threads, and a SYSTEM-class token across multiple artefact types makes this a high-confidence finding.
- **MITRE**: T1036.005 (Masquerading: Match Legitimate Name or Location)

**pid**: `8416` (WmiPrvSE.exe)
- ram → CONFIRMED (HIGH): Although WmiPrvSE.exe resides at its legitimate path (`\Windows\System32\wbem\WmiPrvSE.exe`), its token is wholly inconsistent with any legitimate WMI provider host. SeTcbPrivilege, SeDebugPrivilege, SeAuditPrivilege, SeCreatePermanentPrivilege, and SeLockMemoryPrivilege are all Present, Enabled, and set as Default — describing a fully enabled SYSTEM token rather than the NETWORK SERVICE or LOCAL SERVICE token WmiPrvSE legitimately receives. This strongly indicates token manipulation via a malicious WMI provider DLL or direct token replacement by a prior-stage implant. The dlllist entry for this PID contains an anomalous negative-sized module record (-28140), consistent with a tampered or injected in-memory module. The command line is suppressed.
- **MITRE**: T1047 (Windows Management Instrumentation)

---

#### Threat Intel Enrichment

No threat-intel enrichment was performed. While the `ti` module was listed in the scanned modules, no `ti` findings appear in the entity data for this case.

---

**Tier A — High-suspicion** (two or more independent signals):

- **pid `508`** (unknown process, 6-second lifetime): Orphaned parent (PPID 1380 absent), 6-second runtime immediately before spawning persistent child powershell.exe (PID 3316) — classic dropper/launcher pattern. No cmdline recoverable (process already exited at dump time).
- **pid `3316`** (powershell.exe, child of PID 508): Orphaned grandparent chain (PPID 1380 absent), persistent at dump time with no recoverable cmdline, anomalous dlllist entry (base `0x2e00740073`, size `0x0`, no module path) indicating potentially injected/partially-unmapped region.
- **pid `2952`** (dllhost.exe): Three converging signals — absent cmdline (missing `/Processid:{CLSID}` argument that all legitimate COM Surrogate instances carry), orphaned parent (PPID 616 absent), SYSTEM-class token (SeAssignPrimaryTokenPrivilege, SeTcbPrivilege, SeDebugPrivilege, SeImpersonatePrivilege). Additionally, `bcrypt.dll` appears in ldrmodules with all three loader-list flags False, indicating possible manual DLL mapping.
- **pid `6456`** (winlogon.exe): Orphaned parent (PPID 4084 absent; legitimate winlogon instances are children of smss.exe), suppressed cmdline, and a privilege set far broader than a standard winlogon token (SeTcbPrivilege, SeDebugPrivilege, SeImpersonatePrivilege all Present/Enabled/Default). Consistent with token manipulation.
- **pid `4096`** (unnamed): Appears twice in pslist with two different parent PIDs (1070858240 and 2079404032) and two distinct EPROCESS addresses (`0xbe8e7607f080`, `0xbe8e78a40080`) — structurally impossible for a single legitimate process, consistent with DKOM. Both entries carry epoch-zero timestamps (1601-01-01), indicating CreateTime/ExitTime fields were zeroed or never initialised. Both PPIDs are implausibly large values absent from any process list.
- **pid `3708`** (SearchIndexer.exe): Orphaned parent, SeTcbPrivilege atypical for SearchIndexer.exe specifically, missing cmdline (legitimate SearchIndexer shows `/Embedding`). Most notable: child PID 8984 (SearchFilterHost) appears twice in psscan at two distinct EPROCESS addresses while absent from pslist — a known DKOM indicator.
- **pid `1576`** (svchost.exe): SeTcbPrivilege (Present,Enabled,Default) combined with SeImpersonatePrivilege (Present,Enabled,Default) and orphaned parent. SeTcbPrivilege is held by a small set of legitimate Windows processes; its combination with an orphaned parent is the strongest signal cluster in the lower-suspicion svchost group.
- **pid `1608`** (svchost.exe): Same SeTcbPrivilege-plus-SeImpersonatePrivilege profile as PID 1576, with the additional anomaly of starting approximately four minutes after the main svchost cluster (01:28:10 UTC vs. 01:24:08–09 UTC). Only 3 threads — lightweight service host with elevated privileges.
- **pid `2188`** (spoolsv.exe): Orphaned parent, SYSTEM-class token (SeTcbPrivilege, SeAssignPrimaryTokenPrivilege, SeImpersonatePrivilege all Present/Enabled), and an unresolved DLL entry at `0x7ffd749d0000` (0x1f4000 bytes, name and path both '-') — may indicate a manually mapped PE or reflectively loaded module.

**Tier B — Low-priority** (single weak signal; address only after higher-priority items):

- **pid `1136`** (svchost.exe): Orphaned parent (PPID 616 absent) and missing `-k` cmdline, but binary path is legitimate, privilege token is consistent with a SYSTEM-context service host, and there is only a single benign UDP 0.0.0.0:0 socket. PID reuse after services.exe recycled its PID is the more parsimonious explanation.
- **pid `1192`** (svchost.exe): Orphaned parent only; no masquerade detected, SeImpersonatePrivilege is normal for SYSTEM/Network Service context, no corroborating signals.
- **pid `1408`** (svchost.exe): Same orphaned-parent pattern as PID 1192; SeImpersonatePrivilege, SeCreateGlobalPrivilege, and SeAuditPrivilege are all normal for a Network/Local Service svchost token.
- **pid `2060`** (svchost.exe): Orphaned parent only; privilege profile (SeImpersonatePrivilege, SeCreateGlobalPrivilege, SeAssignPrimaryTokenPrivilege, SeAuditPrivilege) is consistent with Network Service or Local Service. No corroborating signals.
- **pid `2904`** (dllhost.exe): Orphaned parent (PPID 764 absent — COM surrogate parents can exit normally), missing cmdline, and an unresolvable DLL entry at `0x7ffd749d0000`. Low-privilege user-context token; no malfind, network, or registry evidence.
- **pid `3344`** (ctfmon.exe, child of confirmed-suspicious PID 1148): Parent-chain contamination is real, but ctfmon.exe binary path is legitimate, privilege token is low-privilege user context, and the single ldrmodules hit (CoreMessaging.dll from System32) is a normal dependency. Missing cmdline is a shared anomaly with its parent.
- **pid `4092`** (svchost.exe): Orphaned parent, missing `-k` cmdline, and broad privilege set (SeTcbPrivilege, SeDebugPrivilege, SeImpersonatePrivilege all Present/Enabled/Default), but no masquerade detected and no malfind, network, or DLL corroboration. Warrants DLL enumeration before it can be cleared.

---

## 3. Attack Timeline

Chronological reconstruction from CONFIRMED findings only. Precise timestamps are available from evidence artefacts for PIDs 1148 and 8324; other confirmed PIDs do not carry recoverable timestamps in the extracted evidence.

- **2020-09-19 01:24:08 UTC** — PID 1148 (`svchost.exe`) started under an orphaned parent (PPID 616 absent), with no `-k` argument and a SYSTEM-equivalent token. This hollow svchost instance was established very early in the system session alongside the legitimate svchost cluster, suggesting it was planted at or shortly after system boot/logon. *(T1036.005)*

- **[time not recovered]** — PID 424 (`csrss.exe`) was hollowed: the binary shell at `\Device\HarddiskVolume3\Windows\System32\csrss.exe` is legitimate, but the runtime content was replaced with shellcode (non-ASCII garbled command line, PEB image path manipulated, SYSTEM-class privilege token). PEB masquerade confirmed by `malware_pebmasquerade` plugin. *(T1055.012)*

- **[time not recovered]** — PID 8324 (`coreupdater.exe`) executed from `\Windows\System32\` for approximately 2 minutes 21 seconds with zero threads at dump time, a suppressed cmdline, and a SYSTEM-class token. The `malware_pebmasquerade` plugin flagged this binary. This non-system binary masquerading in System32 likely represents a dropper or staging tool. *(T1036.005)*

- **[time not recovered]** — PID 8416 (`WmiPrvSE.exe`) was abused as a post-exploitation host: a malicious WMI provider DLL or direct token replacement elevated the process to a fully enabled SYSTEM token (SeTcbPrivilege, SeDebugPrivilege, SeAuditPrivilege, SeCreatePermanentPrivilege, SeLockMemoryPrivilege all enabled). An anomalous negative-sized module record in dlllist is consistent with an injected in-memory module. *(T1047)*

- **[time not recovered]** — PID 8128 (`RuntimeBroker.exe`) was hollowed or had its module list tampered: a near-empty DLL list, one structurally impossible module entry (non-page-aligned base `0x6bf5fb7fff0c`, ~103 MB size, load count 4253), and a SYSTEM-class token replacing the expected user-context token. The standard `-Embedding` cmdline was preserved to evade detection. *(T1134, T1055.012)*

*Note: A precise chronological ordering of the confirmed implants (PIDs 424, 8128, 8324, 8416) relative to each other cannot be determined from the available artefacts, as timestamps are absent from the extracted evidence for those processes. The timeline above reflects logical attack progression based on technique relationships rather than confirmed clock ordering.*

*Note: Initial access and lateral movement phases cannot be reconstructed — no confirmed artefacts establish how the attacker gained initial entry to this host.*

---

## 4. MITRE ATT&CK Mapping

| Phase                        | Technique                                    | Entity / Evidence                                        |
|------------------------------|----------------------------------------------|----------------------------------------------------------|
| Defense Evasion / In-Memory  | T1055.012 — Process Hollowing                | pid 424 (csrss.exe) — shellcode cmdline, PEB manipulation, SYSTEM token |
| Defense Evasion / In-Memory  | T1055.012 — Process Hollowing                | pid 8128 (RuntimeBroker.exe) — tampered module list, impossible DLL entry |
| Defense Evasion / In-Memory  | T1134 — Access Token Manipulation            | pid 8128 (RuntimeBroker.exe) — SYSTEM-class token in user-context process |
| Execution / Persistence      | T1036.005 — Masquerading: Match Legitimate Name or Location | pid 1148 (svchost.exe) — hollow svchost, no -k arg, SYSTEM token |
| Execution / Persistence      | T1036.005 — Masquerading: Match Legitimate Name or Location | pid 8324 (coreupdater.exe) — non-system binary placed in System32 |
| Execution / Persistence      | T1047 — Windows Management Instrumentation  | pid 8416 (WmiPrvSE.exe) — abused WMI provider host, SYSTEM token, anomalous DLL record |

---

## 5. Indicators of Compromise

| Category    | Indicator                                                                                          |
|-------------|----------------------------------------------------------------------------------------------------|
| File        | `\Windows\System32\coreupdater.exe` (non-system binary masquerading in System32; PID 8324)        |
| Network     | —                                                                                                  |
| Registry    | —                                                                                                  |
| Behavioural | PID 424 (csrss.exe): shellcode bytes in command line; PEB image path manipulated; SeDebugPrivilege, SeTcbPrivilege, SeCreateTokenPrivilege, SeAssignPrimaryTokenPrivilege, SeLoadDriverPrivilege, SeImpersonatePrivilege all Present and Enabled |
| Behavioural | PID 1148 (svchost.exe): missing `-k` argument; orphaned parent PPID 616; SeTcbPrivilege, SeDebugPrivilege, SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege, SeLoadDriverPrivilege, SeCreateTokenPrivilege Present/Enabled |
| Behavioural | PID 8128 (RuntimeBroker.exe): DLL entry at `0x6bf5fb7fff0c` with size `0x6886903` bytes and load count 4253 (structurally impossible); unnamed mapped region at `0x7ffd749d0000`; SYSTEM-class token including SeCreateTokenPrivilege, SeTcbPrivilege, SeDebugPrivilege, SeLoadDriverPrivilege, SeImpersonatePrivilege |
| Behavioural | PID 8416 (WmiPrvSE.exe): SeTcbPrivilege, SeDebugPrivilege, SeAuditPrivilege, SeCreatePermanentPrivilege, SeLockMemoryPrivilege all Present/Enabled/Default; negative-sized module record in dlllist; suppressed cmdline |
| Behavioural | PID 8324 (coreupdater.exe): zero threads at capture; suppressed cmdline; SYSTEM-class token (SeDebugPrivilege, SeImpersonatePrivilege Enabled); flagged by malware_pebmasquerade |

---

## 6. Pipeline Metadata

| Field                   | Value                          |
|-------------------------|--------------------------------|
| Case ID                 | my-case-001                    |
| Report generated        | 2026-06-16T01:20:43Z           |
| Orchestrator model      | claude-haiku-4-5-20251001      |
| Report model            | claude-sonnet-4-6              |
| Routing rounds          | 0                              |
| Termination             | convergence                    |
| Modules                 | ram · ti                       |
| Pre-report LLM calls    | 1                              |
| Pre-report tokens in    | 1505                           |
| Pre-report tokens out   | 9                              |

---

## 7. Evidence Traceability Index

_Machine-generated (no LLM) — maps every finding to the tool execution that produced it. Find an entity cited above, read its `finding_id` / `query_id` and evidence `source_file:line`, then `grep` the `call_id` in the named log (`produced_by`) to reach the exact agent call (`input_files` / `output_files` / `timestamp` / tokens). The evidence column shows the first locator with `(+N more)` when a finding cites several lines; the **complete evidence list — every `source_file:line` plus its verbatim `content` — is in `backbone/traceability.json`** (this table mirrors that file)._

| Entity | finding_id / query_id | module | verdict | severity | evidence (file:line) | produced_by (agent → call_id) | log |
|---|---|---|---|---|---|---|---|
| `pid:1136` | `ram-chunk_002-f001` | ram | INCONCLUSIVE | — | `pstree.txt:74` (+4 more) | ram/pivot_analyst → `df1ac9ba-e39b-4a3d-9cd9-7696f97f64bf` | `ram/agent_calls.jsonl` |
| `pid:1148` | `ram-chunk_003-f001` | ram | CONFIRMED | HIGH | `pslist.txt:22` (+7 more) | ram/pivot_analyst → `b71e9e76-4725-4a26-89dc-bd102d2050ae` | `ram/agent_calls.jsonl` |
| `pid:1192` | `ram-chunk_005-f001` | ram | INCONCLUSIVE | — | `pslist.txt:29` (+2 more) | ram/pivot_analyst → `5ed9b204-c380-47f1-82aa-35c06c5c47c2` | `ram/agent_calls.jsonl` |
| `pid:1408` | `ram-chunk_005-f002` | ram | INCONCLUSIVE | — | `pslist.txt:23` (+3 more) | ram/pivot_analyst → `5ed9b204-c380-47f1-82aa-35c06c5c47c2` | `ram/agent_calls.jsonl` |
| `pid:1576` | `ram-chunk_005-f003` | ram | INCONCLUSIVE | — | `pslist.txt:24` (+3 more) | ram/pivot_analyst → `5ed9b204-c380-47f1-82aa-35c06c5c47c2` | `ram/agent_calls.jsonl` |
| `pid:1608` | `ram-chunk_005-f004` | ram | INCONCLUSIVE | — | `pslist.txt:45` (+3 more) | ram/pivot_analyst → `5ed9b204-c380-47f1-82aa-35c06c5c47c2` | `ram/agent_calls.jsonl` |
| `pid:2060` | `ram-chunk_005-f005` | ram | INCONCLUSIVE | — | `pslist.txt:30` (+2 more) | ram/pivot_analyst → `5ed9b204-c380-47f1-82aa-35c06c5c47c2` | `ram/agent_calls.jsonl` |
| `pid:2188` | `ram-chunk_007-f001` | ram | INCONCLUSIVE | — | `dlllist.txt:380` (+4 more) | ram/pivot_analyst → `7770bbbc-6919-4f76-a8c9-5af0c1b307cb` | `ram/agent_calls.jsonl` |
| `pid:2904` | `ram-chunk_009-f001` | ram | INCONCLUSIVE | — | `dlllist.txt:956` (+2 more) | ram/pivot_analyst → `52042f00-4fbd-4436-b952-ee2dd81d2e57` | `ram/agent_calls.jsonl` |
| `pid:2952` | `ram-chunk_010-f001` | ram | INCONCLUSIVE | — | `pslist.txt:37` (+7 more) | ram/pivot_analyst → `f5077561-9a70-4513-925a-fad55921442e` | `ram/agent_calls.jsonl` |
| `pid:3316` | `ram-chunk_001-f003` | ram | INCONCLUSIVE | — | — | ram/pivot_analyst → `37a59860-850e-416d-b448-b2f9cc9e9853` | `ram/agent_calls.jsonl` |
| `pid:3344` | `ram-chunk_003-f002` | ram | INCONCLUSIVE | — | `cmdline.txt:75` (+3 more) | ram/pivot_analyst → `b71e9e76-4725-4a26-89dc-bd102d2050ae` | `ram/agent_calls.jsonl` |
| `pid:3708` | `ram-chunk_013-f001` | ram | INCONCLUSIVE | — | — | ram/pivot_analyst → `47682791-a190-4dc6-915a-e3f30431e9c8` | `ram/agent_calls.jsonl` |
| `pid:4092` | `ram-chunk_014-f001` | ram | INCONCLUSIVE | — | `pslist.txt:46` (+6 more) | ram/pivot_analyst → `a5b00bd6-fcec-45c2-a1aa-f33530b6f466` | `ram/agent_calls.jsonl` |
| `pid:4096` | `ram-chunk_014-f002` | ram | INCONCLUSIVE | — | `pslist.txt:60` (+6 more) | ram/pivot_analyst → `a5b00bd6-fcec-45c2-a1aa-f33530b6f466` | `ram/agent_calls.jsonl` |
| `pid:424` | `ram-chunk_001-f001` | ram | CONFIRMED | CRITICAL | — | ram/pivot_analyst → `37a59860-850e-416d-b448-b2f9cc9e9853` | `ram/agent_calls.jsonl` |
| `pid:508` | `ram-chunk_001-f002` | ram | INCONCLUSIVE | — | — | ram/pivot_analyst → `37a59860-850e-416d-b448-b2f9cc9e9853` | `ram/agent_calls.jsonl` |
| `pid:6456` | `ram-chunk_017-f001` | ram | INCONCLUSIVE | — | `pslist.txt:50` (+4 more) | ram/pivot_analyst → `a82c37c1-7f37-4d58-a5d9-faf9eab4907c` | `ram/agent_calls.jsonl` |
| `pid:8128` | `ram-chunk_021-f001` | ram | CONFIRMED | CRITICAL | `privileges.txt:2180` (+6 more) | ram/pivot_analyst → `30c5ada3-a0fe-4f89-a38c-7b1f71aa7c81` | `ram/agent_calls.jsonl` |
| `pid:8324` | `ram-chunk_022-f001` | ram | CONFIRMED | HIGH | — | ram/pivot_analyst → `4aa521d4-e8ae-4af5-a374-5e7e3fb20951` | `ram/agent_calls.jsonl` |
| `pid:8416` | `ram-chunk_022-f002` | ram | CONFIRMED | HIGH | — | ram/pivot_analyst → `4aa521d4-e8ae-4af5-a374-5e7e3fb20951` | `ram/agent_calls.jsonl` |
