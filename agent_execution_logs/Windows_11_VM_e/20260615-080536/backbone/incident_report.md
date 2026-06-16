# Incident Report — Windows_11_VM_e

| Field           | Value                                              |
|-----------------|----------------------------------------------------|
| Generated       | 2026-06-15T08:23:18Z                               |
| Host            | Windows_11_VM_e                                    |
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

No host profile data was recovered from available artefacts. The presence of a `kali` user account path (`C:\Users\kali\AppData\...`) in process command-line evidence suggests the machine may be a penetration-testing or adversary-controlled workstation, but this cannot be confirmed from the profile fields alone.

---

## 1. Executive Summary

The investigation identified **CRITICAL**-severity confirmed compromise on this host, with 6 of 12 total reportable entities CONFIRMED malicious across 2 modules (`ram`, `ti`). The confirmed findings document a complete multi-stage dropper chain terminating in a persistent .NET implant (`Client.exe`) running from a user-writable AppData path under a SYSTEM-equivalent privilege token. The remaining 6 INCONCLUSIVE entities include a suspicious `svchost.exe` with null command-line arguments (consistent with process hollowing) and a token-abusing `AggregatorHost.exe`, alongside lower-priority orphaned processes; confirmed findings outnumber inconclusive by 6 to 6.

---

## 2. Detailed Investigation Notes

### Execution / Persistence

---

**pid**: `376` — `Client.exe`
- ram → CONFIRMED (CRITICAL): Client.exe executes from `C:\Users\kali\AppData\Roaming\SubDir\` — a user-writable path with no legitimate software association. It is the sole surviving (non-exited) process in the dropper chain, with no ExitTime while all ancestors have already terminated, establishing it as the persistent implant. Its privilege token is SYSTEM-equivalent: SeDebugPrivilege, SeTcbPrivilege, SeImpersonatePrivilege, SeLoadDriverPrivilege, SeCreateTokenPrivilege, SeAssignPrimaryTokenPrivilege, SeBackupPrivilege, SeRestorePrivilege, and SeAuditPrivilege are all present — no legitimate user-context binary should carry this set. The self-referential DLL list entry (the `.exe` appearing as its own loaded module at `0xb50000`) combined with `MSCOREE.DLL` is consistent with a .NET assembly loaded reflectively or via the CLR host.

---

**pid**: `5568` — `cmd.exe` (root dropper)
- ram → CONFIRMED (HIGH): This cmd.exe is the root of the confirmed dropper chain. Its parent PID 560 is absent from both pslist and psscan (orphaned), strongly indicating injection, PID reuse, or a self-cleaning launcher. Within approximately 10 seconds it spawned both `PING.EXE` (PID 5608, used as a sleep/delay substitute) and `Client.exe` (PID 5836). The orphaned parentage, multi-child scripted spawning, and short lifespan are consistent with a batch-based dropper script executing a staged payload sequence. No command line was recovered — the process was psscan-only, indicating it had already exited before the live list was walked.

---

**pid**: `5836` — `Client.exe` (first-stage payload)
- ram → CONFIRMED (HIGH): First-stage Client.exe spawned by the orphaned root `cmd.exe` (PID 5568). It lived approximately 7 seconds and its sole observable action was spawning `cmd.exe` (PID 7980), the next wrapper in the chain, before exiting. No DLL or cmdline evidence was recovered (psscan-only). The behaviour — a short-lived no-artifact payload whose only function is to re-execute a second copy of `Client.exe` under a fresh cmd.exe wrapper — is a classic staged re-execution pattern used to obscure the original launch context and inherit a cleaner process tree.

---

**pid**: `7980` — `cmd.exe` (second wrapper)
- ram → CONFIRMED (HIGH): Second cmd.exe wrapper, spawned by `Client.exe` PID 5836 and itself spawning both `PING.EXE` (PID 7552) and the persistent `Client.exe` (PID 376) from `AppData\Roaming\SubDir` before exiting after approximately 10 seconds. The pstree evidence confirms the full device path of the child it launched (`\Device\HarddiskVolume4\Users\kali\AppData\Roaming\SubDir\Client.exe`), corroborating the AppData path seen in cmdline.txt for PID 376. The mirror of the root cmd.exe (PID 5568) behaviour — cmd spawning PING alongside a payload — indicates a templated dropper script was executed at least twice across the chain.

---

**pid**: `2380` — `cmd.exe` (stager with named batch file)
- ram → CONFIRMED (HIGH): Command line directly invokes a randomly-named batch file (`EMwLtc9FBmME.bat`) from `C:\Users\kali\AppData\Local\Temp\` — a classic dropper/stager pattern. Parent PID 4240 is absent from the process list, consistent with a dropper that spawned this shell and then terminated. The privilege token contains the near-complete Windows privilege set including SeTcbPrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, and SeDebugPrivilege — privileges that would not appear even as non-enabled entries on a standard user token, strongly indicating execution under a SYSTEM or highly elevated token. The child process `PING.EXE` (PID 7284) is a well-known sleep-substitute used in batch-based stagers.

---

### Defense Evasion / In-Memory Implants

---

**pid**: `1708` — `AggregatorHost.exe`
- ram → CONFIRMED (HIGH): Three converging anomalies. First, declared parent PID 2600 is absent from the process list — a common indicator of process injection, hollowing, or a manually spawned implant with a spoofed non-existent parent. Second, the privilege token is grossly over-privileged for this binary: SeTcbPrivilege, SeDebugPrivilege, and SeImpersonatePrivilege are all simultaneously Present, Enabled, and Default — characteristic of a SYSTEM-level token obtained via token theft or impersonation, not a legitimately assigned token for AggregatorHost (which normally runs with a far narrower privilege set). Third, a non-standard DLL (`C:\WINDOWS\SYSTEM32\UpdateReboot.dll`) was identified in the load list by initial analysis; while it could not be verbatim confirmed from the truncated 3-of-28 dlllist lines provided, it cannot be dismissed. The combination of orphaned parent and fully enabled SeTcbPrivilege+SeDebugPrivilege+SeImpersonatePrivilege on a non-SYSTEM-class binary is sufficient for CONFIRMED HIGH independently of the DLL signal.

---

#### Threat Intel Enrichment

No threat-intel enrichment was performed. (The `ti` module was listed as scanned but no `ti` findings appear on any entity in the input.)

---

**Tier A — High-suspicion** (two or more independent signals):

- **pid `5964`** (`svchost.exe`): Four independent signals — (1) null command line (`-`), which is structurally abnormal for svchost since every legitimate instance carries `-k <ServiceGroupName>`, consistent with process hollowing where injected code did not inherit the argument string; (2) orphaned parent PID 896 absent from the process list, preventing verification against `services.exe`; (3) near-complete SYSTEM token with SeTcbPrivilege, SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege, SeBackupPrivilege, SeRestorePrivilege, and SeDebugPrivilege — atypical even for elevated svchost groups; (4) process lived exactly four minutes before exiting, consistent with a task-completion payload. Binary path resolves cleanly to System32 (no masquerade), but malfind, full dlllist, netscan, and handles analysis are required to resolve verdict. MITRE T1055 flagged.

- **pid `6420`** (`taskhostw.exe`): Three independent signals — (1) orphaned parent PID 2168 absent from process list, cannot be anchored to the Task Scheduler svchost; (2) command line retains the literal placeholder `$(Arg0)` unexpanded, atypical for a legitimately scheduled taskhostw invocation and may indicate launch outside the normal Task Scheduler code path; (3) extraordinarily broad privilege set (SeDebugPrivilege, SeLoadDriverPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeImpersonatePrivilege, SeTakeOwnershipPrivilege, SeSecurityPrivilege all Present) consistent with LOCAL SYSTEM rather than a standard interactive user token. DLL evidence points only to System32 paths; no malfind, network, or registry persistence artefacts available. MITRE T1134 flagged.

- **pid `2388`** (`cmd.exe`): Two independent signals — (1) orphaned parent PID 6956 absent from process list; (2) SYSTEM-equivalent token identical to confirmed PID 2380 (SeTcbPrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeDebugPrivilege present). Command line not captured (`-`), which prevents confirmation. Short lifespan (19:26:14–19:26:23 UTC, 9 seconds). Batch or script recovery would likely resolve to CONFIRMED.

**Tier B — Low-priority** (single weak signal):

- **pid `4644`** (`MicrosoftEdgeUpdate.exe`): Runs from the canonical installation path (`C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`) in session 0 with a standard `/c` invocation. Primary residual concern is SeTcbPrivilege being Present,Enabled,Default — unusual even for LOCAL SYSTEM user-space updater binaries. Orphaned parent PID 2168 is a weak secondary signal common in Task Scheduler/COM activation. No malfind hits, suspicious DLLs, network connections, or encoded arguments present.

- **pid `4276`** (`sihost.exe`): Sole signal is orphaned parent PID 1924 — a common benign artefact as the legitimate parent (winlogon.exe or UserManager svchost) may exit before the memory image is captured. Binary path is canonical System32, child processes (ShellHost.exe PID 5112, CrossDeviceRes PID 5144) are expected descendants, and enabled privileges are limited to the standard interactive-session shell profile. No malfind, suspicious DLLs, or network evidence.

- **pid `5608`** (`PING.EXE`): Spawned by confirmed-malicious cmd.exe (PID 5568) alongside `Client.exe` (PID 5836); a second PING.EXE (PID 7552) was similarly spawned by cmd.exe (PID 7980). Repeated co-spawning with payload binaries strongly suggests use as a timing delay. However, PING.EXE is a legitimate Windows binary and without the command-line arguments (not recovered), specific abuse cannot be confirmed. Recovery of ping arguments would likely resolve to CONFIRMED MEDIUM.

---

## 3. Attack Timeline

- **2026-05-13 19:15:18 UTC** — `AggregatorHost.exe` (PID 1708) starts with orphaned parent PID 2600 and a fully enabled SYSTEM-equivalent token (SeTcbPrivilege, SeDebugPrivilege, SeImpersonatePrivilege). Represents the earliest confirmed malicious process in the image; likely the token-theft or privilege escalation stage.

- **2026-05-13 19:26:14 UTC** — Suspicious `cmd.exe` (PID 2388, INCONCLUSIVE) starts with orphaned parent PID 6956 and SYSTEM-equivalent token; exits at 19:26:23 UTC (9-second lifespan). Context overlaps with dropper chain initiation.

- **2026-05-13 19:26:26 UTC** — Root dropper `cmd.exe` (PID 5568) starts with orphaned parent PID 560. Immediately spawns `PING.EXE` (PID 5608) as a timing delay and first-stage `Client.exe` (PID 5836).

- **2026-05-13 19:26:36 UTC** — Root `cmd.exe` (PID 5568) and its `PING.EXE` (PID 5608) both exit. First-stage `Client.exe` (PID 5836) spawns second wrapper `cmd.exe` (PID 7980).

- **2026-05-13 19:26:43 UTC** — Second wrapper `cmd.exe` (PID 7980) spawns `PING.EXE` (PID 7552) and persistent `Client.exe` (PID 376) from `C:\Users\kali\AppData\Roaming\SubDir\`. First-stage `Client.exe` (PID 5836) exits.

- **2026-05-13 19:26:53 UTC** — Second wrapper `cmd.exe` (PID 7980) and its `PING.EXE` (PID 7552) both exit. Persistent `Client.exe` (PID 376) remains running — this is the terminal implant, a .NET assembly with a SYSTEM-equivalent token, with no ExitTime recorded.

- **2026-05-13 19:26:56 UTC** — Stager `cmd.exe` (PID 2380) starts, invoking `C:\Users\kali\AppData\Local\Temp\EMwLtc9FBmME.bat` under a SYSTEM-equivalent token with orphaned parent PID 4240. Spawns `PING.EXE` (PID 7284). This batch-based stager may represent a parallel or follow-on execution path.

*Note: The initial vector that granted the SYSTEM-equivalent token to AggregatorHost.exe (PID 1708) at 19:15:18 UTC cannot be determined from available artefacts. There is an approximately 11-minute gap between the earliest confirmed malicious process and the dropper chain execution. Intermediate activity cannot be reconstructed from RAM artefacts alone.*

---

## 4. MITRE ATT&CK Mapping

| Phase                          | Technique                                    | Entity / Evidence                                              |
|--------------------------------|----------------------------------------------|----------------------------------------------------------------|
| Defense Evasion / Privilege Esc. | T1134 — Access Token Manipulation           | pid 1708: AggregatorHost.exe with SeTcbPrivilege+SeDebugPrivilege+SeImpersonatePrivilege all Enabled,Default |
| Execution / Persistence        | T1543 — Create or Modify System Process      | pid 376: Client.exe persisting from AppData\Roaming\SubDir     |
| Defense Evasion / Privilege Esc. | T1134 — Access Token Manipulation           | pid 376: Client.exe with full SYSTEM-equivalent token          |
| Execution                      | T1059.003 — Windows Command Shell            | pid 376: Client.exe spawned via cmd.exe dropper chain          |
| Execution                      | T1059.003 — Windows Command Shell            | pid 2380: cmd.exe invoking EMwLtc9FBmME.bat from Temp          |
| Execution                      | T1059.003 — Windows Command Shell            | pid 5568: root orphaned cmd.exe dropper chain                  |
| Execution                      | T1059.003 — Windows Command Shell            | pid 5836: Client.exe first-stage re-execution wrapper          |
| Execution                      | T1059.003 — Windows Command Shell            | pid 7980: cmd.exe second wrapper spawning persistent implant   |

---

## 5. Indicators of Compromise

| Category    | Indicator                                                                 |
|-------------|---------------------------------------------------------------------------|
| File        | `C:\Users\kali\AppData\Roaming\SubDir\Client.exe`                         |
| File        | `C:\Users\kali\AppData\Local\Temp\EMwLtc9FBmME.bat`                       |
| File        | `C:\WINDOWS\System32\AggregatorHost.exe` (PID 1708, token-abused instance)|
| Network     | —                                                                         |
| Registry    | —                                                                         |
| Behavioural | SeTcbPrivilege + SeDebugPrivilege + SeImpersonatePrivilege all Present,Enabled,Default on non-SYSTEM-class binaries (PIDs 1708, 2380, 376) |
| Behavioural | .NET implant (`MSCOREE.DLL`) loaded by `Client.exe` (PID 376) from user-writable AppData path |
| Behavioural | PING.EXE used as sleep/delay substitute in dropper chain (PIDs 5608, 7552, 7284) |
| Behavioural | Multi-hop dropper chain: cmd.exe (PID 5568) → Client.exe (PID 5836) → cmd.exe (PID 7980) → Client.exe (PID 376) |

---

## 6. Pipeline Metadata

| Field                   | Value                              |
|-------------------------|------------------------------------|
| Case ID                 | Windows_11_VM_e                    |
| Report generated        | 2026-06-15T08:23:18Z               |
| Orchestrator model      | claude-haiku-4-5-20251001          |
| Report model            | claude-sonnet-4-6                  |
| Routing rounds          | 0                                  |
| Termination             | convergence                        |
| Modules                 | ram · ti                           |
| Pre-report LLM calls    | 1                                  |
| Pre-report tokens in    | 1,219                              |
| Pre-report tokens out   | 9                                  |

---

## 7. Evidence Traceability Index

_Machine-generated (no LLM) — maps every finding to the tool execution that produced it. Find an entity cited above, read its `finding_id` / `query_id` and evidence `source_file:line`, then `grep` the `call_id` in the named log (`produced_by`) to reach the exact agent call (`input_files` / `output_files` / `timestamp` / tokens). The evidence column shows the first locator with `(+N more)` when a finding cites several lines; the **complete evidence list — every `source_file:line` plus its verbatim `content` — is in `backbone/traceability.json`** (this table mirrors that file)._

| Entity | finding_id / query_id | module | verdict | severity | evidence (file:line) | produced_by (agent → call_id) | log |
|---|---|---|---|---|---|---|---|
| `pid:1708` | `ram-chunk_001-f001` | ram | CONFIRMED | HIGH | `pslist.txt:65` (+6 more) | ram/pivot_analyst → `97f8632f-94f6-4a4d-b719-2ed51d03ee2d` | `ram/agent_calls.jsonl` |
| `pid:2380` | `ram-chunk_003-f001` | ram | CONFIRMED | HIGH | `cmdline.txt:138` (+5 more) | ram/pivot_analyst → `69ff3fe4-29cf-4a9d-8ecf-21eec3856929` | `ram/agent_calls.jsonl` |
| `pid:2388` | `ram-chunk_003-f002` | ram | INCONCLUSIVE | — | `cmdline.txt:133` (+4 more) | ram/pivot_analyst → `69ff3fe4-29cf-4a9d-8ecf-21eec3856929` | `ram/agent_calls.jsonl` |
| `pid:376` | `ram-chunk_018-f001` | ram | CONFIRMED | CRITICAL | `pslist.txt:137` (+8 more) | ram/pivot_analyst → `6fd565ce-16c4-4101-89dd-703347b582c9` | `ram/agent_calls.jsonl` |
| `pid:4276` | `ram-chunk_009-f001` | ram | INCONCLUSIVE | — | `pslist.txt:70` (+5 more) | ram/pivot_analyst → `d196d574-15f9-4284-b5d2-fb370899a50f` | `ram/agent_calls.jsonl` |
| `pid:4644` | `ram-chunk_012-f001` | ram | INCONCLUSIVE | — | `aggregated_analyst.txt:2495` (+7 more) | ram/pivot_analyst → `67d6ab77-91ba-4948-b5eb-153db8b2d82d` | `ram/agent_calls.jsonl` |
| `pid:5568` | `ram-chunk_018-f002` | ram | CONFIRMED | HIGH | `psscan.txt:114` (+2 more) | ram/pivot_analyst → `6fd565ce-16c4-4101-89dd-703347b582c9` | `ram/agent_calls.jsonl` |
| `pid:5608` | `ram-chunk_018-f005` | ram | INCONCLUSIVE | — | `psscan.txt:134` (+1 more) | ram/pivot_analyst → `6fd565ce-16c4-4101-89dd-703347b582c9` | `ram/agent_calls.jsonl` |
| `pid:5836` | `ram-chunk_018-f003` | ram | CONFIRMED | HIGH | `psscan.txt:142` (+1 more) | ram/pivot_analyst → `6fd565ce-16c4-4101-89dd-703347b582c9` | `ram/agent_calls.jsonl` |
| `pid:5964` | `ram-chunk_021-f001` | ram | INCONCLUSIVE | — | — | ram/pivot_analyst → `bcff28bf-1e68-4a0d-8cf4-fdcad83906de` | `ram/agent_calls.jsonl` |
| `pid:6420` | `ram-chunk_022-f001` | ram | INCONCLUSIVE | — | `pslist.txt:104` (+7 more) | ram/pivot_analyst → `2047060a-fe35-452e-bc74-2e623e0e0726` | `ram/agent_calls.jsonl` |
| `pid:7980` | `ram-chunk_018-f004` | ram | CONFIRMED | HIGH | `psscan.txt:104` (+3 more) | ram/pivot_analyst → `6fd565ce-16c4-4101-89dd-703347b582c9` | `ram/agent_calls.jsonl` |
