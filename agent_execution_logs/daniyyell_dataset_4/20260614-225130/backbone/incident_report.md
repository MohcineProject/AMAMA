# Incident Report — daniyyell_dataset_4

| Field           | Value                                              |
|-----------------|----------------------------------------------------|
| Generated       | 2026-06-14T23:10:43Z                               |
| Host            | daniyyell_dataset_4                                |
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

No host profile data was recovered from available artefacts.

---

## 1. Executive Summary

The investigation of case daniyyell_dataset_4 identified **HIGH**-severity confirmed malicious activity across 4 of 12 total reportable entities, investigated by 2 modules (ram, ti). All 4 confirmed entities carry HIGH severity findings; there are no CRITICAL findings. Confirmed entities (4) exceed inconclusive-only entities (8), reflecting meaningful forensic signal from memory analysis, though a substantial number of additional processes require follow-up to resolve their status.

---

## 2. Detailed Investigation Notes

### Defense Evasion / In-Memory Implants

**pid**: `5348` (MicrosoftEdgeUpdate.exe)
- ram → CONFIRMED (HIGH): PPID 1320 is absent from the active process list, indicating a spoofed or hollowed parent. The process carries a full NT AUTHORITY\SYSTEM token with SeTcbPrivilege, SeDebugPrivilege, SeAssignPrimaryTokenPrivilege, SeCreateTokenPrivilege, and SeLoadDriverPrivilege all Present,Enabled,Default — far exceeding what any update helper binary legitimately requires and consistent with token duplication or theft. An additional unnamed, path-less DLL mapped at `0x7fff5f6f0000` (no image name, no path) may indicate a manually mapped or injected module.

**pid**: `6056` (RuntimeBroker.exe)
- ram → CONFIRMED (HIGH): The process carries near-complete NT AUTHORITY\SYSTEM privileges (SeCreateTokenPrivilege, SeAssignPrimaryTokenPrivilege, SeTcbPrivilege, SeDebugPrivilege, SeLoadDriverPrivilege, SeImpersonatePrivilege, SeBackupPrivilege, SeRestorePrivilege, SeAuditPrivilege), none of which belong in a legitimate RuntimeBroker token. PPID 860 is absent from pslist. The command line is unreadable. A single ldrmodules entry shows all three PEB loader-list flags as False, indicating at least one mapped region is hidden from the Windows loader — consistent with injected or manually mapped code.

**pid**: `8336` (backgroundTask)
- ram → CONFIRMED (HIGH): Four independent signals converge. (1) Both image path and command line are absent ("-"), consistent with process hollowing or a manually mapped PE. (2) The name "backgroundTask" does not match any known Windows system process truncation ("backgroundTaskHost.exe" would truncate to "backgroundTaskH"). (3) The process ran in interactive Session 1 rather than Session 0. (4) Two outbound TCP connections to `23.192.26.3:80` carry timestamps (19:47:09 UTC) that predate the EPROCESS creation time (19:48:25 UTC) by over a minute, suggesting PID reuse or inherited connection objects.

**pid**: `8552` (audiodg.exe)
- ram → CONFIRMED (HIGH): Legitimate audiodg.exe runs under a restricted LOCAL SERVICE token; this instance instead holds a near-complete SYSTEM-equivalent token (SeCreateTokenPrivilege, SeAssignPrimaryTokenPrivilege, SeTcbPrivilege, SeDebugPrivilege, SeLoadDriverPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeImpersonatePrivilege). PPID 2220 is absent from both pslist and psscan, consistent with PPID spoofing or a short-lived launcher. The executable path and PEB masquerade check are clean, suggesting token manipulation or execution-context replacement of the legitimate binary.

---

#### Threat Intel Enrichment

No threat-intel enrichment was performed.

---

**Tier A — High-suspicion** (two or more independent signals):

- **pid `684`** (svchost.exe): Appears in psscan only (absent from pslist) with a "Disabled" EPROCESS list-link — consistent with DKOM-based process concealment. PPID 716 is not present anywhere in the process list; legitimate svchost.exe is always spawned by services.exe. Two independent signals: psscan-only visibility + untraceable parent.

- **pid `2972`** (taskhostw.exe): Three signals converge. (1) Orphaned parent (PPID 1320 absent). (2) Extraordinarily elevated privilege set (SeTcbPrivilege, SeAssignPrimaryTokenPrivilege, SeLoadDriverPrivilege, SeDebugPrivilege, SeImpersonatePrivilege all Present,Enabled) — highly unusual for a process that normally runs under user or LOCAL SERVICE context. (3) CLOSED TCPv4 connection to public IP `150.171.27.10:443` from taskhostw.exe, which does not ordinarily initiate public outbound connections.

- **pid `5684`** (ctfmon.exe): Runs in interactive Session 1 but carries a full SYSTEM-level privilege set (SeTcbPrivilege, SeCreateTokenPrivilege, SeAssignPrimaryTokenPrivilege, SeDebugPrivilege, SeLoadDriverPrivilege, SeImpersonatePrivilege, SeBackupPrivilege, SeRestorePrivilege). Legitimate ctfmon.exe runs under a restricted user token with only a handful of standard user privileges. A SYSTEM token in Session 1 on this binary is abnormal and could indicate token manipulation or process hollowing. Orphaned PPID 5592 provides a secondary weaker signal.

- **pid `6804`** (SearchApp.exe): UWP application expected to run in an AppContainer with a highly restricted token. Instead, the token contains the full NT privilege set (SeDebugPrivilege, SeTcbPrivilege, SeLoadDriverPrivilege, SeImpersonatePrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege) — indicating it was created from a highly privileged base token rather than an AppContainer token. Two signals: anomalous token origin + orphaned PPID 860.

**Tier B — Low-priority** (single weak signal):

- **pid `2036`** (MsMpEng.exe): Standard Windows Defender engine at a known-legitimate path with appropriate SYSTEM privileges and System32-only DLL loads. Sole concern is orphaned PPID 716, most likely a memory-snapshot timing artefact. All other signals are benign.

- **pid `4892`** (svchost.exe): SeTcbPrivilege Present,Enabled,Default is anomalous for svchost.exe, but binary path resolves to legitimate System32, no PEB masquerade detected, no network connections, no malfind hits. Short lifespan (19:38:38–19:40:45 UTC, ~2 minutes) and missing command line add minor suspicion but insufficient for confirmation.

- **pid `4580`** (svchost.exe): Appears only in psscan with no ExitTime (suggestive of DKOM concealment), but the entire evidence block consists of a single psscan line with no cmdline, DLL, privilege, malfind, or network data. Single signal only.

- **pid `5832`** (explorer.exe): Flagged for an outbound ESTABLISHED TCP connection to `192.168.135.57:8070` (port associated with C2/proxy frameworks), but no verbatim netscan line was recovered in the evidence; the anomaly was reported by the upstream agent rather than captured in artefacts. Process tree, cmdline, and privilege set are otherwise normal. Requires full netscan output and malfind review.

---

## 3. Attack Timeline

All timestamps are UTC; source host is `192.168.135.59`.

- **2025-08-07 19:36:30 UTC** — pid `8552` (audiodg.exe) created with SYSTEM-equivalent token under orphaned PPID 2220; token manipulation or execution-context replacement of the legitimate audio daemon.
- **2025-08-07 19:36:30 UTC** — pid `5348` (MicrosoftEdgeUpdate.exe) active with SYSTEM token including SeCreateTokenPrivilege, SeDebugPrivilege, and an unnamed path-less DLL mapped in its address space; consistent with token theft and possible manual PE mapping.
- **2025-08-07 19:47:09 UTC** — pid `8336` (backgroundTask) records two outbound TCP connections to `23.192.26.3:80` (CLOSED); connection timestamps precede process creation by over one minute, suggesting PID reuse or inherited connection objects.
- **2025-08-07 19:48:25 UTC** — pid `8336` (backgroundTask) created in Session 1 with absent image path and command line; process runs until 19:53:20 UTC (~5 minutes active).
- **2025-08-07 19:48:25 UTC** — pid `6056` (RuntimeBroker.exe) created under orphaned PPID 860 with full SYSTEM token and a PEB loader-list entry showing all three flags False, indicating hidden mapped code.
- **2025-08-07 19:53:20 UTC** — pid `8336` (backgroundTask) exits.

*Note: No confirmed initial access artefact is available from the analysed modules. The chain begins at an already-elevated in-memory stage; how the attacker first gained access cannot be determined from the available artefacts. The disk module was not scanned.*

---

## 4. MITRE ATT&CK Mapping

| Phase                          | Technique                        | Entity / Evidence                                                      |
|--------------------------------|----------------------------------|------------------------------------------------------------------------|
| Defense Evasion / Privilege Esc. | T1134 — Access Token Manipulation | pid 5348 (MicrosoftEdgeUpdate.exe): SYSTEM token, SeCreateTokenPrivilege |
| Defense Evasion / Privilege Esc. | T1134 — Access Token Manipulation | pid 6056 (RuntimeBroker.exe): full SYSTEM token, unreadable cmdline     |
| Defense Evasion / Privilege Esc. | T1134 — Access Token Manipulation | pid 8552 (audiodg.exe): SYSTEM-equivalent token, orphaned PPID 2220     |
| Defense Evasion / In-Memory    | T1055 — Process Injection        | pid 8336 (backgroundTask): absent image path/cmdline, Session 1, anomalous network timestamps |

---

## 5. Indicators of Compromise

| Category    | Indicator                                                                                              |
|-------------|--------------------------------------------------------------------------------------------------------|
| File        | Process image: `backgroundTask` (non-standard name; no backing image path recovered)                  |
| Network     | `23.192.26.3:80` — outbound TCP (CLOSED) from pid 8336 (backgroundTask), 2025-08-07 19:47:09 UTC     |
| Registry    | —                                                                                                      |
| Behavioural | SeTcbPrivilege + SeCreateTokenPrivilege + SeDebugPrivilege + SeLoadDriverPrivilege enabled on pid 5348 (MicrosoftEdgeUpdate.exe), pid 6056 (RuntimeBroker.exe), pid 8552 (audiodg.exe); unnamed path-less DLL at 0x7fff5f6f0000 in pid 5348; all PEB ldrmodules flags False for pid 6056; absent image path and cmdline for pid 8336 |

---

## 6. Pipeline Metadata

| Field                   | Value                              |
|-------------------------|------------------------------------|
| Case ID                 | daniyyell_dataset_4                |
| Report generated        | 2026-06-14T23:10:43Z               |
| Orchestrator model      | claude-haiku-4-5-20251001          |
| Report model            | claude-sonnet-4-6                  |
| Routing rounds          | 0                                  |
| Termination             | convergence                        |
| Modules                 | ram · ti                           |
| Pre-report LLM calls    | 1                                  |
| Pre-report tokens in    | 1284                               |
| Pre-report tokens out   | 9                                  |

---

## 7. Evidence Traceability Index

_Machine-generated (no LLM) — maps every finding to the tool execution that produced it. Find an entity cited above, read its `finding_id` / `query_id` and evidence `source_file:line`, then `grep` the `call_id` in the named log (`produced_by`) to reach the exact agent call (`input_files` / `output_files` / `timestamp` / tokens). The evidence column shows the first locator with `(+N more)` when a finding cites several lines; the **complete evidence list — every `source_file:line` plus its verbatim `content` — is in `backbone/traceability.json`** (this table mirrors that file)._

| Entity | finding_id / query_id | module | verdict | severity | evidence (file:line) | produced_by (agent → call_id) | log |
|---|---|---|---|---|---|---|---|
| `pid:2036` | `ram-chunk_002-f001` | ram | INCONCLUSIVE | — | `pslist.txt:143` (+7 more) | ram/pivot_analyst → `cbf8c56c-06d5-447b-b2f9-e7cf704447b4` | `ram/agent_calls.jsonl` |
| `pid:2972` | `ram-chunk_005-f001` | ram | INCONCLUSIVE | — | `privileges.txt:5120` (+6 more) | ram/pivot_analyst → `c6277d8f-df40-4fbe-9582-5f1debc94d8b` | `ram/agent_calls.jsonl` |
| `pid:4580` | `ram-chunk_008-f002` | ram | INCONCLUSIVE | — | `psscan.txt:170` | ram/pivot_analyst → `5985d6a1-568b-4fb7-aa9a-20a25eac8f28` | `ram/agent_calls.jsonl` |
| `pid:4892` | `ram-chunk_008-f001` | ram | INCONCLUSIVE | — | `pslist.txt:123` (+5 more) | ram/pivot_analyst → `5985d6a1-568b-4fb7-aa9a-20a25eac8f28` | `ram/agent_calls.jsonl` |
| `pid:5348` | `ram-chunk_013-f001` | ram | CONFIRMED | HIGH | `aggregated_analyst.txt:2635` (+5 more) | ram/pivot_analyst → `a5703041-d90b-4001-88ec-6837e8ac472d` | `ram/agent_calls.jsonl` |
| `pid:5684` | `ram-chunk_014-f001` | ram | INCONCLUSIVE | — | `privileges.txt:2775` (+7 more) | ram/pivot_analyst → `d36aa30e-4ccb-4efc-984a-87f07984f64c` | `ram/agent_calls.jsonl` |
| `pid:5832` | `ram-chunk_015-f001` | ram | INCONCLUSIVE | — | `pslist.txt:86` (+1 more) | ram/pivot_analyst → `437d1201-914b-4478-bccb-2db48fd19a03` | `ram/agent_calls.jsonl` |
| `pid:6056` | `ram-chunk_017-f001` | ram | CONFIRMED | HIGH | `privileges.txt:5085` (+10 more) | ram/pivot_analyst → `c084f91c-e8e5-4e2b-86ac-7b2bc375ac38` | `ram/agent_calls.jsonl` |
| `pid:6804` | `ram-chunk_021-f001` | ram | INCONCLUSIVE | — | `pstree.txt:85` (+8 more) | ram/pivot_analyst → `fa75234e-2e98-43bc-80f3-f11cdbf7a190` | `ram/agent_calls.jsonl` |
| `pid:684` | `ram-chunk_001-f001` | ram | INCONCLUSIVE | — | `psscan.txt:29` | ram/pivot_analyst → `f186114d-db16-4933-b3cc-904a64c9a855` | `ram/agent_calls.jsonl` |
| `pid:8336` | `ram-chunk_026-f001` | ram | CONFIRMED | HIGH | `pslist.txt:150` (+5 more) | ram/pivot_analyst → `bdc7c29c-de6b-4bb7-98b4-25775583269c` | `ram/agent_calls.jsonl` |
| `pid:8552` | `ram-chunk_027-f001` | ram | CONFIRMED | HIGH | `privileges.txt:3650` (+6 more) | ram/pivot_analyst → `a4c6add7-2fa6-43ad-8fea-f740b956eaaa` | `ram/agent_calls.jsonl` |
