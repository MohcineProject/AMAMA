# Incident Report — ROCBA-2026-2

| Field           | Value                                              |
|-----------------|----------------------------------------------------|
| Generated       | 2026-06-13T14:17:43Z                               |
| Host            | SRL-FORGE                                          |
| Modules         | ram · disk · ti                                    |
| Pipeline result | convergence after 2 round(s)                       |

---

## 0. System Profile

| Field          | Value                                            |
|----------------|--------------------------------------------------|
| Hostname       | SRL-FORGE                                        |
| OS             | Windows 10 Pro 20H2 (build 19042)                |
| Network domain | shieldbase.lan                                   |
| User accounts  | Administrator, Guest, DefaultAccount, WDAGUtilityAccount, srl-h, fredr |
| Last used      | fredr                                            |
| Inferred role  | Domain-joined workstation                        |

SRL-FORGE is a domain-joined Windows 10 Pro workstation in the shieldbase.lan network; the primary interactive user appears to be srl-h (RID 1001), while fredr (RID 1002) is the last interactively logged-on account and the focal point of the confirmed intrusion activity.

---

## 1. Executive Summary

The investigation of SRL-FORGE reveals a **CRITICAL**-severity, multi-stage intrusion: external threat actors conducted sustained RDP/SMB brute-force and password spray campaigns beginning 2020-11-01, successfully compromising the `fredr` account by 2020-11-14, and subsequently leveraging that access for kernel-mode driver installation, lateral movement to a second domain (`shieldbase.lan`), in-memory process hollowing, and targeted secure deletion of evidence. Of 52 total reportable entities, 16 are CONFIRMED across 3 modules (ram, disk, ti), with 6 CRITICAL and 10 HIGH findings; 36 entities remain INCONCLUSIVE and require follow-on investigation. The confirmed-to-inconclusive ratio of 16:36 reflects a broad attacker footprint where corroborating artifacts were partially destroyed by the attacker's own anti-forensics activity.

---

## 2. Detailed Investigation Notes

### 1. Initial Access / Credential Attacks

**ip**: `193.93.62.32`
- disk → CONFIRMED (CRITICAL): High-volume brute-force campaign from the 193.93.62.x subnet targeting the ADMINISTRATOR account via LogonType 3 (network/SMB). Hundreds of event 4625 failures recorded across archived Security event logs spanning 2020-11-01 through 2020-11-03. At least 30+ distinct source IPs observed in the same campaign; the Remmina RDP client string was identified in log entries (L716), indicating deliberate RDP-targeted tooling. SAM registry entry confirms Administrator (RID 500) was last modified 2020-11-01T22:15Z — coinciding with the campaign onset.
- ti → NOT_FOUND: 0/91 VT engines; Geolocation: LV.

**ip**: `85.14.242.76`
- disk → CONFIRMED (CRITICAL): High-volume automated password spray targeting dozens of distinct usernames in rapid succession (~1 attempt per 1.5–2 seconds) on 2020-11-13T23:12–23:15Z. Attacker rotated at least nine distinct RDP client type strings (Windows2019, Remmina, Windows8, Windows2012, Windows7, mstsc, Rdesktop, Windows10, FreeRDP, Windows2016) from a single source IP — a hallmark of spray tooling designed to evade detection. Approximately 31,000 failures attributed to this IP.
- ti → NOT_FOUND: 0/91 VT engines; Geolocation: DE, AS=WIIT AG, ASN=24961.

**ip**: `213.202.233.90`
- disk → CONFIRMED (CRITICAL): Sustained brute-force against the Administrator account across archived Security logs spanning 2020-11-01 through 2020-11-02; Remmina RDP client string corroborates spray-tool activity. Approximately 18,000 failures attributed to this IP.
- ti → NOT_FOUND: 0/91 VT engines; Geolocation: DE, AS=WIIT AG, ASN=24961.

**ip**: `213.202.233.104`
- disk → CONFIRMED (CRITICAL): Multi-day password spray targeting at least seven distinct usernames (OWNER, NIDEK, PAULINE, OSPITE, MJOHNSON, MMILLER, ONCALL, OPC) across archived Security logs spanning 2020-11-01 through 2020-11-07. MFT record for `Users\fredr\AppData\LocalLow\Temp\Microsoft\OPC` — a directory matching one of the targeted usernames — was created 2020-11-14T05:13:08Z during the attack window, providing a second artifact type.
- ti → NOT_FOUND: 0/91 VT engines; Geolocation: DE, AS=WIIT AG, ASN=24961.

**ip**: `194.61.54.121`
- disk → CONFIRMED (HIGH): High-volume credential-stuffing/brute-force from 194.61.54.121 via SMB (LogonType 3) beginning 2020-11-06T00:58Z. Targets cycled sequentially through 50+ alphabetically enumerated usernames (EMILY, BARBARA, REBECCA, DONNA, DCADMIN, QUICKBOOKS, etc.) at approximately 15-second intervals — unambiguously automated. 10,310 failures attributed to this IP.
- ti → NOT_FOUND: 0/91 VT engines; Geolocation: PL, AS=NETH LTD, ASN=198362.

**ip**: `141.98.83.187`
- disk → CONFIRMED (HIGH): 7,137 event 4625 failures across approximately 1.5 hours (16:47–18:29 UTC on 2020-11-13). Username targets progress sequentially and alphabetically (A0, B0, C0 … through DP0) — an unambiguous automated enumeration/brute-force pattern.
- ti → INCONCLUSIVE: 1/91 VT engines flagged as malicious; Geolocation: PA, AS=Flyservers S.A., ASN=209588.

**ip**: `201.193.188.114`
- disk → CONFIRMED (HIGH): 12,804 failures against the ADMINISTRATOR account attributed to this IP per the Agent 1 triage digest, corroborated by Security event log archives and SAM registry confirmation of the targeted account (Administrator, RID 500, last modified 2020-11-01T22:15Z).
- ti → NOT_FOUND: 0/91 VT engines; Geolocation: CR, AS=Instituto Costarricense de Electricidad y Telecom., ASN=11830.

**ip**: `91.241.19.97`
- disk → CONFIRMED (MEDIUM): Confirmed participation in the sustained brute-force campaign against the Administrator account via the same archived event log window (2020-11-01–2020-11-02). SAM entry corroborates the targeted account was valid. Remmina client string visible in co-occurring log entries indicates coordinated tooling.
- ti → INCONCLUSIVE: 2/91 VT engines flagged as malicious; Geolocation: RU, AS=Bratinov Oleg Vyacheslavovich, ASN=47550.

**ip**: `52.249.198.56`
- disk → CONFIRMED (CRITICAL): Multiple independent artifact types confirm a successful external compromise of the `fredr` account. A 4648 explicit-credential logon event shows IP `cobra (52.249.198.56)` authenticating as `SRL-FORGE\fredr` via LogonType 3 at 2020-11-14T03:42:40Z, followed immediately by a LogonType 7 (interactive unlock) event for `MicrosoftAccount\fred.rocba@outlook.com` from the same external IP — anomalous since all prior LogonType 7 events show loopback/local source. A 4672 event immediately assigns `SeDebugPrivilege`, `SeLoadDriverPrivilege`, `SeBackupPrivilege`, and `SeRestorePrivilege` to the account. Registry confirms `fredr` as `LastUsedUsername` (modified 2020-11-16T02:29:37Z). OneDrive sync root mapped to `C:\Users\fredr\Stark Research Labs\SRL-Projects - Airwolf` confirms access to sensitive corporate research data. MFT shows `fred.rocba@outlook.com.ost` modified 2020-11-14T14:11:49Z and `Firefox Recovery Key.txt` created 2020-11-03 — consistent with credential harvesting.
- disk → CONFIRMED (LOW): Sequence of two failed logon attempts from `cobra (52.249.198.56)` targeting `fred.rocba@outlook.com`, followed by successful LogonType 3 network logon as `SRL-FORGE\fredr`, then immediate LogonType 7 unlock session with admin privilege assignment — all sourced to the same external IP within seconds.
- ti → NOT_FOUND: 0/91 VT engines; Geolocation: US, AS=Microsoft Corporation, ASN=8075.

---

### 2. Execution / Persistence

**image_name (account context)**: `fredr`
- disk → CONFIRMED (HIGH): Event 4697 confirms `SRL-FORGE\fredr` installed a kernel-mode file system driver named `googledrivefs3229` (`system32\DRIVERS\googledrivefs3229.sys`) on 2020-11-10T14:12:18Z — a name mimicking Google Drive file system drivers but bearing an anomalous numeric suffix. The service installation by a non-system account is corroborated by 12 event 4672 privilege-assignment records confirming `fredr` held `SeLoadDriverPrivilege`, `SeDebugPrivilege`, `SeBackupPrivilege`, and `SeRestorePrivilege`. The type-3 network logon from `52.249.198.56` immediately preceding the privilege assignments establishes remote operator context.

**file_path**: `Users\srl-h\Downloads\sdelete64.exe`
- disk → CONFIRMED (MEDIUM): MFT record shows sdelete64.exe present in srl-h's Downloads folder without a Zone.Identifier ADS (not browser-downloaded); SI modified timestamp (~2 hours) predates the created timestamp. UserAssist registry entry confirms execution by user `srl-h` on 2020-11-01T22:17:08Z. Prefetch file `SDELETE64.EXE-B0C2AF3F.pf` in `Windows.old` corroborates prior execution, constituting two independent artifact types confirming deliberate use of the secure-deletion tool.

---

### 3. Defense Evasion / In-Memory Implants

**pid**: `17316` (`svchost.exe`)
- ram → CONFIRMED (HIGH): Four independent artifact types converge on process hollowing. (1) pstree.txt marks the process with a double-asterisk orphan prefix — PPID 828 is absent from the active process list; legitimate svchost must descend from a live services.exe. (2) cmdline.txt records a bare dash — every legitimate svchost invocation carries `-k <ServiceGroupName>`; its absence indicates the process was not launched through the normal service-hosting path. (3) dlllist.txt returns a single disabled/empty entry (base 0x0, size 0, path N/A) — a hallmark of a hollowed process whose PEB module list was wiped or never populated. (4) Privilege token is full SYSTEM-class with `SeTcbPrivilege` and `SeImpersonatePrivilege` both `Present,Enabled,Default`. Binary path resolves to legitimate `\Windows\System32\svchost.exe`, reinforcing the hollow-process interpretation.

**pid**: `21836` (`RuntimeBroker.` — masquerade)
- ram → CONFIRMED (HIGH): Three independent anomalies confirm masquerade/execution. (1) Parent PID 740 is absent from both pslist and psscan — ghost PPID, consistent with PPID spoofing. (2) Both command-line and image path fields are inaccessible (`-`), whereas legitimate RuntimeBroker.exe always runs from System32 with a known `-Embedding` argument; inaccessible path fields indicate the image backing was unlinked or never mapped from a real on-disk file. (3) The process spawned PID 29656 (LocalBridge.exe), a non-Windows binary hidden from pslist via DKOM unlinking. The `malware_pebmasquerade` entry with blank path fields corroborates the PEB does not point to a legitimate on-disk image.

**pid**: `29656` (`LocalBridge.ex`)
- ram → CONFIRMED (HIGH): Appears in psscan but is entirely absent from pslist — canonical signature of Direct Kernel Object Manipulation (DKOM) process hiding; EPROCESS unlinked from `ActiveProcessLinks`. This technique does not occur in legitimate Windows operation. Binary name `LocalBridge.exe` is not a known Windows component. Process lived exactly one second (02:31:19–02:31:20 UTC), consistent with a stager or dropper completing a single task then exiting. Parent is the confirmed malicious masquerading RuntimeBroker PID 21836, completing a two-stage chain.

**pid**: `26768` (`backgroundTask`)
- ram → CONFIRMED (HIGH): Appears exclusively in psscan, absent from pslist — DKOM `ActiveProcessLinks` unlinking confirmed. Image name `backgroundTask` is not a recognised Windows system process. Parent PID 740 is also absent from the process list. Process ran for approximately 61 seconds (02:31:19–02:32:20 UTC), consistent with a dropper or stager that completed its task and terminated. The DKOM signal is self-evidencing from the psscan/pslist discrepancy alone.

---

### 4. Lateral Movement

**image_name (account context)**: `fredr` (RDP lateral movement)
- disk → CONFIRMED (CRITICAL): Two event 4648 records confirm `SRL-FORGE\fredr` explicitly supplied `SHIELDBASE\frocba` credentials targeting `base-rd-08.shieldbase.lan` at 2020-11-14T05:00:49Z and again at 05:05:37Z — constituting cross-domain credential use. The RDP client operational log independently records two event 1102 multi-transport connection initiations to `172.16.6.18` at timestamps matching the 4648 events to within one second, providing corroboration across two independent artifact types. The actor's external foothold via `52.249.198.56` (cobra) in the hours immediately preceding these events establishes the operational context.

**image_name (account context)**: `fredr` (admin share access)
- disk → CONFIRMED (HIGH): Event 5140 records confirm `SRL-FORGE\fredr` accessed both `IPC$` and `C$` administrative shares from loopback addresses (`::1`) on 2020-11-03 and 2020-11-14. On 2020-11-14, these share accesses immediately follow the type-3 network logon from external IP `52.249.198.56`, establishing that C$ access occurred within a session initiated from an external host. Combined with the cross-domain credential use toward `base-rd-08.shieldbase.lan` confirmed in the same session, the evidence spans three independent event log record types (5140, 4624, 4648).

---

### 5. Impact / Anti-Forensics

**image_name**: `SDELETE.EXE`
- disk → CONFIRMED (HIGH): Two distinct prefetch records (`SDELETE.EXE-0E837E93.pf`, run_count=5; `SDELETE.EXE-2BD91720.pf`, run_count=2) confirm SDELETE.EXE executed at least 7 times in a tight 5-minute window on 2020-11-14 (13:42:30Z–13:47:10Z). MFT entries for both prefetch files have consistent SI and FN timestamps, ruling out timestomping of the prefetch records. Two distinct hashes indicate invocation with different argument sets — consistent with targeted secure deletion of specific files or directories. Timing immediately precedes a REGSVR32 burst at 13:50Z, forming a coherent anti-forensics sequence: secure-delete evidence → uninstall cloud sync → execute additional payloads.

---

### Threat Intel Enrichment

8 IOCs were queried against VirusTotal:

- 1 of 8 returned one or more detections (`141.98.83.187`: 1/91 engines; `91.241.19.97`: 2/91 engines — both low-confidence)
- **WIIT AG clustering**: Three brute-force/spray source IPs share ASN 24961 (WIIT AG, DE): `85.14.242.76`, `213.202.233.90`, and `213.202.233.104`. This clustering suggests coordinated infrastructure or shared hosting used by the threat actor for the spray campaign.
- **`52.249.198.56`** (confirmed account takeover IP): Geolocated to US, AS=Microsoft Corporation, ASN=8075. This is a Microsoft Azure cloud IP — the attacker used Azure-hosted infrastructure for the successful `fredr` account compromise, which may assist attribution and suggests deliberate use of cloud egress to blend with legitimate Microsoft traffic.
- **`141.98.83.187`**: 1/91 VT detection; Geolocation: PA, AS=Flyservers S.A., ASN=209588 — a hosting provider associated with bulletproof services.
- **`91.241.19.97`**: 2/91 VT detections; Geolocation: RU, AS=Bratinov Oleg Vyacheslavovich, ASN=47550 — small Russian ASN with low but non-zero VT signal.
- Remaining confirmed attack IPs (`193.93.62.32`, `213.202.233.90`, `213.202.233.104`, `194.61.54.121`, `201.193.188.114`) all returned 0/91 VT detections, indicating the attacking infrastructure is not yet broadly flagged in commercial threat intelligence.

---

**Tier A — High-suspicion** (two or more independent signals):

- **pid 1676** (`dllhost.exe`): psscan-only (DKOM indicator, T1055/T1564.001 cited), orphaned PPID 740, null cmdline, 8-second lifespan. Three convergent signals — strongest inconclusive process entry.
- **pid 4420** (`SearchFilterHost`): psscan-only (DKOM), orphaned PPID 11968 absent from process list, legitimate name used for masquerade. Two structural signals.
- **pid 7900** (`svchost.exe`): Two distinct EPROCESS structures at different physical offsets for the same PID (T1014 cited) — neither in pslist. Duplicate EPROCESS is a recognised DKOM indicator. Single structural signal but highly anomalous.
- **pid 17316** (svchost.exe hollow): Already CONFIRMED — included here for completeness; excluded from inconclusive tiers.
- **pid 19348** (`smartscreen.ex`): pstree path confirms System32 binary, but dlllist is zeroed out (module list unreadable), cmdline absent, and SYSTEM-level privilege set far exceeds what SmartScreen requires. Three signals (unreadable module list, null cmdline, over-privileged token).
- **pid 30216** (`svchost.exe`): Orphaned PPID 828, null cmdline (svchost must have `-k` argument), and SeTcbPrivilege/SeDebugPrivilege/SeImpersonatePrivilege all `Present,Enabled,Default` simultaneously. Three signals; countervailed only by clean path resolution and no DKOM.
- **pid 8172** (`msedge.exe`): Null cmdline for a browser process, SYSTEM-level token (highly abnormal for any browser subprocess), orphaned PPID 22700, 2-minute lifespan. Three signals.
- **pid 9836** (`svchost.exe`): Orphaned PPID 828, null cmdline, SeTcbPrivilege and SeImpersonatePrivilege both `Present,Enabled,Default` (T1134 cited). Three signals; clean path and masquerade check prevent confirmation.
- **file_path** `Users\fredr\AppData\Local\Temp\f4136dbd-be88-4a99-8fb9-c70f12760e2b.bat`: GUID-named batch script (105 bytes) dropped in Temp on 2020-11-10T14:12:21Z (same minute as confirmed `googledrivefs3229` service installation); no Zone.Identifier. Programmatic drop pattern + timing correlation with confirmed activity.
- **image_name `VSSADMIN.EXE`**: Confirmed executed three times on 2020-11-14 (12:49Z, 13:16Z, 14:03Z) — the 14:03Z execution falls within the SDELETE/anti-forensics window. Two artifact types (prefetch + MFT). No argument evidence to confirm shadow deletion.

**Tier B — Low-priority** (single weak signal; address only after higher-priority items):

- **pid 800** (`csrss.exe`): Inflated privilege set (SeDebugPrivilege, SeTcbPrivilege enabled) for a process that should carry a narrow SYSTEM token; orphaned PPID is expected for csrss. Single token-anomaly signal.
- **pid 1004** (`svchost.exe`): Orphaned PPID, null cmdline, zero threads, 6-second lifespan. Multiple signals but no injection markers; may be a process that exited before full snapshot capture.
- **pid 29440** (`MRC.exe`): Non-Windows binary from `D:\Tools`, elevated privilege token, orphaned PPID 7464. Could be legitimate remote-control software; no network/persistence evidence.
- **pid 8728** (`SecurityHealthService`): Three high-risk privileges simultaneously enabled; orphaned parent; missing cmdline cross-reference. Partially explicable by SYSTEM-context operation.
- **pid 9488** (`ctfmon.exe`): Near-complete SYSTEM-level token but most privileges disabled; orphaned PPID. Low concern given privilege disabled states.
- **pid 28864** (`svchost.exe`): Null cmdline only; clean path, no DKOM, no anomalous privileges beyond standard SYSTEM svchost set.
- **pid 25508** (`RuntimeBroker.`): Broad but disabled privilege set; clean cmdline (`-Embedding`), clean path; orphaned PPID is common for RuntimeBroker.
- **pid 14028** (`RuntimeBroker.`): Broad privilege set all disabled; clean cmdline, DLL paths; orphaned PPID artefact.
- **pid 9964** (`RuntimeBroker.`): Near-complete SYSTEM token (present but not enabled); clean `-Embedding` cmdline. Token inheritance from SYSTEM-level parent plausible.
- **pid 11392** (`chrome.exe`): SYSTEM-level token (all disabled except SeChangeNotifyPrivilege); clean path; already exited; orphaned PPID.
- **pid 16824** (`TabTip.exe`): SYSTEM-context token consistent with known Windows 10 IMM behavior; orphaned PPID; passes masquerade check.
- **pid 19436** (`SearchApp.exe`): Broad token almost entirely disabled; canonical Cortana activation cmdline; clean DLLs. Standard UWP host behaviour.
- **pid 8156/8164** (`GoogleCrashHan`): Co-spawned sibling pair; legitimate Google Update path; Volatility WOW64 artefact explains unresolved DLL entry; SYSTEM token plausibly explained by crash-handler design.
- **pid 9644** (`HxTsr.exe`): Legitimate WindowsApps path; passes masquerade check; SYSTEM token and null cmdline are residual concerns for a 2-second-lived UWP transient.
- **pid 30012** (`WinStore.App.e`): UWP process with SYSTEM-level token (all disabled except SeChangeNotifyPrivilege); AppContainer SID not verified; canonical path and cmdline.
- **image_name `RUNDLL32.EXE`**: Five prefetch hashes; most runs attributed to scheduled tasks with known Windows DLLs; only one hash (171F7F04, 14:01Z) is proximate to the incident window but lacks argument evidence.
- **image_name `MSIEXEC.EXE`**: Two distinct prefetch hashes on 2020-11-14 within the incident window; timing correlates with Dropbox uninstall; no payload path or argument evidence.
- **image_name `REGSVR32.EXE`**: 9 executions in a 2-second burst (13:50:16–13:50:18Z) with two distinct hashes; timing follows SDELETE cluster; consistent with legitimate Dropbox uninstaller batching.
- **file_path** `C:\Users\fredr\AppData\Local\Temp\GUMF3B9.tmp\GoogleUpdateSetup.exe`: Executed from GUID-named Temp path; consistent with legitimate Google Update self-extraction; companion GoogleUpdate.exe executed=No weakens dropper hypothesis.
- **file_path** `Users\fredr\AppData\Local\Temp\~nsu.tmp\Au_.exe`: Two execution signals (prefetch + BAM registry); SI/FN mismatch; consistent with NSIS auto-updater stub; no persistence or network evidence.
- **file_path** `ProgramData\Package Cache\{7f51bdb9...}\vcredist_x64.exe` and `{ce085a78...}\vcredist_x86.exe`: Near-identical ~4.7-year SI/FN mismatch pair; plausibly legitimate installer metadata; single MFT artifact each.
- **file_path** `ProgramData\Adobe\Setup\{AC76BA86-...}\setup.exe`: ~45-day SI/FN mismatch; known Adobe Reader installer GUID; no execution evidence.
- **ip `81.19.209.101`**: Attributed to brute-force campaign by triage digest but no direct event log lines visible in pivot evidence for this specific IP.
- **ip `185.202.1.123`**: Same pivot evidence gap — IP does not appear in returned log lines; plausible within broader spray context but unconfirmed.
- **ip `174.196.200.9`**: No event log lines referencing this IP in pivot evidence; UserAssist entry for sdelete64.exe from srl-h's Downloads warrants separate investigation.

---

## 3. Attack Timeline

- **2020-11-01T22:15:32Z** — SAM registry entry for Administrator (RID 500) modified, coinciding with the onset of brute-force activity. User `srl-h` executes `sdelete64.exe` at 22:17:08Z (UserAssist).
- **2020-11-01T22:22Z – 2020-11-02T00:06Z** — Sustained brute-force / password spray campaign against the Administrator account from multiple external IPs including `193.93.62.32`, `213.202.233.90`, `213.202.233.104`, `201.193.188.114`, and `91.241.19.97`. Hundreds of event 4625 LogonType 3 failures recorded across archived Security logs; Remmina RDP client string identified in co-occurring entries.
- **2020-11-06T00:58Z** — `194.61.54.121` begins credential-stuffing campaign; 50+ distinct usernames targeted sequentially at ~15-second intervals (10,310 total failures).
- **2020-11-13T16:47Z – 18:29Z** — `141.98.83.187` performs automated alphabetical username enumeration (A0 through DP0), 7,137 failures.
- **2020-11-13T23:12Z – 23:15Z** — `85.14.242.76` executes high-speed password spray (~31,000 failures), rotating nine distinct RDP client strings from a single IP.

*Note: ~10-day gap between external spray campaigns (2020-11-03 through 2020-11-09) — intermediate activity cannot be fully determined from available artifacts.*

- **2020-11-10T14:12:18Z** — `SRL-FORGE\fredr` installs kernel-mode file system driver `googledrivefs3229` (`system32\DRIVERS\googledrivefs3229.sys`) — a name mimicking legitimate Google Drive drivers. A GUID-named batch script (`f4136dbd-be88-4a99-8fb9-c70f12760e2b.bat`, 105 bytes) is dropped to `Users\fredr\AppData\Local\Temp\` at 14:12:21Z, within the same minute.
- **2020-11-14T03:42:14Z** — External IP `52.249.198.56` (hostname "cobra", Azure/Microsoft ASN 8075, US) initiates failed logon attempts against `fred.rocba@outlook.com`.
- **2020-11-14T03:42:40Z** — `cobra (52.249.198.56)` achieves successful LogonType 3 network logon as `SRL-FORGE\fredr`. Within 12 seconds, a LogonType 7 (interactive unlock) session for `MicrosoftAccount\fred.rocba@outlook.com` is established from the same external IP — anomalous for an external source. Event 4672 immediately assigns `SeDebugPrivilege`, `SeLoadDriverPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`.
- **2020-11-14T05:00:49Z** — `SRL-FORGE\fredr` uses explicit credentials for `SHIELDBASE\frocba` targeting `base-rd-08.shieldbase.lan`; RDP client log records multi-transport connection to `172.16.6.18` at 05:00:50Z. Repeated at 05:05:37Z.
- **2020-11-14T12:44:27Z** — `SRL-FORGE\fredr` accesses `C$` administrative share via loopback within the remote-origin session.
- **2020-11-14T13:42:30Z – 13:47:10Z** — `SDELETE.EXE` executed at least 7 times across two distinct argument sets (prefetch hashes `0E837E93` and `2BD91720`), performing targeted secure deletion of files/directories.
- **2020-11-14T13:50:04Z** — `Au_.exe` executed from `Users\fredr\AppData\Local\Temp\~nsu.tmp\` (prefetch; NSIS-pattern binary).
- **2020-11-14T13:50:16Z – 13:50:18Z** — `REGSVR32.EXE` burst (9 invocations in 2 seconds, two distinct DLL argument sets). `MSIEXEC.EXE` executions begin at 13:50:30Z and continue through 14:19Z.
- **2020-11-14T14:11:49Z** — `fred.rocba@outlook.com.ost` (Outlook email store) last modified — consistent with email access or exfiltration.
- **2020-11-16T02:29:37Z** — `LastUsedUsername` registry key updated to `fredr` — confirms continued active session on this date.
- **2020-11-16T02:29:37Z – 02:32:50Z** — In-memory execution cluster: masquerading `RuntimeBroker.` (PID 21836, PPID spoofed, unlinked image) spawns `LocalBridge.exe` (PID 29656, DKOM-hidden, 1-second lifespan) at 02:31:19Z; `backgroundTask` (PID 26768, DKOM-hidden, ~61 seconds) runs 02:31:19Z–02:32:20Z; hollowed `svchost.exe` (PID 17316) active from 02:29:37Z onward.

---

## 4. MITRE ATT&CK Mapping

| Phase                          | Technique                                         | Entity / Evidence                                                      |
|--------------------------------|---------------------------------------------------|------------------------------------------------------------------------|
| Initial Access / Credential    | T1110.001 — Brute Force: Password Guessing        | ip: `193.93.62.32` — sustained 4625 failures against ADMINISTRATOR      |
| Initial Access / Credential    | T1110.003 — Brute Force: Password Spraying        | ip: `85.14.242.76` — multi-client-string spray, 31,000 failures         |
| Initial Access / Credential    | T1110.001 — Brute Force: Password Guessing        | ip: `213.202.233.90` — ~18,000 failures against ADMINISTRATOR           |
| Initial Access / Credential    | T1110.003 — Brute Force: Password Spraying        | ip: `213.202.233.104` — multi-username spray across 7+ accounts         |
| Initial Access / Credential    | T1110.001 — Brute Force: Password Guessing        | ip: `194.61.54.121` — sequential username enumeration, 10,310 failures  |
| Initial Access / Credential    | T1110 — Brute Force                               | ip: `141.98.83.187` — alphabetical username enumeration, 7,137 failures |
| Initial Access / Credential    | T1110 — Brute Force                               | ip: `201.193.188.114` — 12,804 failures against ADMINISTRATOR           |
| Initial Access / Credential    | T1110.003 — Brute Force: Password Spraying        | ip: `91.241.19.97` — coordinated spray against ADMINISTRATOR            |
| Initial Access / Credential    | T1078 — Valid Accounts                            | ip: `52.249.198.56` — successful LogonType 3 + LogonType 7 as `fredr`  |
| Execution / Persistence        | T1543.003 — Create/Modify System Process: Windows Service | image_name: `fredr` — installed `googledrivefs3229` kernel driver     |
| Lateral Movement               | T1021.001 — Remote Services: RDP                  | image_name: `fredr` — 4648 events targeting `base-rd-08.shieldbase.lan`|
| Lateral Movement               | T1021.002 — Remote Services: SMB/Windows Admin Shares | image_name: `fredr` — 5140 events for `IPC$` and `C$`              |
| Defense Evasion / In-Memory    | T1055.012 — Process Injection: Process Hollowing  | pid: `17316` (svchost.exe) — empty PEB module list, null cmdline       |
| Defense Evasion / In-Memory    | T1036.005 — Masquerading: Match Legitimate Name   | pid: `21836` (RuntimeBroker. masquerade) — unlinked image, ghost PPID  |
| Defense Evasion / In-Memory    | T1014 — Rootkit                                   | pid: `29656` (LocalBridge.ex) — psscan-only, DKOM process hiding       |
| Defense Evasion / In-Memory    | T1014 — Rootkit                                   | pid: `26768` (backgroundTask) — psscan-only, DKOM process hiding       |
| Impact / Anti-Forensics        | T1485 — Data Destruction                          | image_name: `SDELETE.EXE` — 7 executions in 5-minute window            |
| Impact / Anti-Forensics        | T1070.004 — Indicator Removal: File Deletion      | image_name: `SDELETE.EXE` — two distinct argument sets                  |
| Impact / Anti-Forensics        | T1070.004 — Indicator Removal: File Deletion      | file_path: `Users\srl-h\Downloads\sdelete64.exe` — confirmed execution  |

---

## 5. Indicators of Compromise

| Category    | Indicator                                                                                          |
|-------------|-----------------------------------------------------------------------------------------------------|
| File        | `system32\DRIVERS\googledrivefs3229.sys` — kernel-mode driver installed by `fredr` (event 4697, 2020-11-10T14:12:18Z) |
| File        | `Users\fredr\AppData\Local\Temp\f4136dbd-be88-4a99-8fb9-c70f12760e2b.bat` — GUID-named batch script (105 bytes, 2020-11-10T14:12:21Z) |
| File        | `Users\srl-h\Downloads\sdelete64.exe` — sdelete64, no Zone.Identifier, confirmed execution 2020-11-01T22:17:08Z |
| File        | `SDELETE.EXE` — prefetch hashes `0E837E93` and `2BD91720`; 7 executions 2020-11-14T13:42:30Z–13:47:10Z |
| File        | `LocalBridge.exe` (EPROCESS truncated `LocalBridge.ex`, PID 29656) — DKOM-hidden, unknown binary, 1-second lifespan 2020-11-16T02:31:19Z |
| File        | `backgroundTask` (PID 26768) — DKOM-hidden, unknown binary, 61-second lifespan 2020-11-16T02:31:19Z |
| Network     | `52.249.198.56` (hostname: cobra) — successful account takeover of `fredr`; Azure/Microsoft ASN 8075, US; 0/91 VT |
| Network     | `85.14.242.76` — password spray, ~31,000 failures, 9 RDP client strings; WIIT AG ASN 24961, DE; 0/91 VT |
| Network     | `213.202.233.90` — brute-force against ADMINISTRATOR; WIIT AG ASN 24961, DE; 0/91 VT              |
| Network     | `213.202.233.104` — password spray, multi-username; WIIT AG ASN 24961, DE; 0/91 VT                |
| Network     | `193.93.62.32` — brute-force against ADMINISTRATOR and MMARTIN; country=LV; 0/91 VT               |
| Network     | `194.61.54.121` — credential stuffing, 10,310 failures; NETH LTD ASN 198362, PL; 0/91 VT          |
| Network     | `141.98.83.187` — alphabetical username enumeration, 7,137 failures; Flyservers S.A. ASN 209588, PA; 1/91 VT |
| Network     | `201.193.188.114` — 12,804 failures against ADMINISTRATOR; Instituto Costarricense ASN 11830, CR; 0/91 VT |
| Network     | `91.241.19.97` — password spray against ADMINISTRATOR; Bratinov Oleg ASN 47550, RU; 2/91 VT       |
| Network     | `172.16.6.18` — RDP lateral movement destination (base-rd-08.shieldbase.lan), event 1102 records  |
| Registry    | `Sam\ROOT\SAM\Domains\Account\Users` — Administrator (RID 500) modified 2020-11-01T22:15:32Z      |
| Registry    | `googledrivefs3229` — service name; `ServiceFileName: system32\DRIVERS\googledrivefs3229.sys`; `ServiceType: File System Driver` |
| Registry    | `Software\ROOT\Microsoft\Windows NT\CurrentVersion\Winlogon` — `LastUsedUsername: fredr`, modified 2020-11-16T02:29:37Z |
| Behavioural | `SRL-FORGE\fredr` presenting `SHIELDBASE\frocba` credentials to `base-rd-08.shieldbase.lan` (cross-domain explicit credential use, event 4648) |
| Behavioural | LogonType 7 (interactive unlock) from external IP `52.249.198.56` — anomalous; all prior LogonType 7 for this account are loopback/local |
| Behavioural | `SeDebugPrivilege`, `SeLoadDriverPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege` assigned to `fredr` at 2020-11-14T03:42:40Z (event 4672) |
| Behavioural | PID 17316 (`svchost.exe`): hollow process — empty PEB module list (dlllist base 0x0, size 0x0), null cmdline, orphaned PPID, SYSTEM token |
| Behavioural | PIDs 29656 and 26768 absent from pslist but present in psscan — DKOM ActiveProcessLinks unlinking confirmed |

---

## 6. Pipeline Metadata

| Field                   | Value                          |
|-------------------------|--------------------------------|
| Case ID                 | ROCBA-2026-2                   |
| Report generated        | 2026-06-13T14:17:43Z           |
| Orchestrator model      | claude-haiku-4-5-20251001      |
| Report model            | claude-sonnet-4-6              |
| Routing rounds          | 2                              |
| Termination             | convergence                    |
| Modules                 | ram · disk · ti                |
| Pre-report LLM calls    | 2                              |
| Pre-report tokens in    | 4963                           |
| Pre-report tokens out   | 227                            |

---

---

## 7. Evidence Traceability Index

_Machine-generated (no LLM) — maps every finding to the tool execution that produced it. Find an entity cited above, read its `finding_id` / `query_id` and evidence `source_file:line`, then `grep` the `call_id` in the named log (`produced_by`) to reach the exact agent call (`input_files` / `output_files` / `timestamp` / tokens). The evidence column shows the first locator with `(+N more)` when a finding cites several lines; the **complete evidence list — every `source_file:line` plus its verbatim `content` — is in `backbone/traceability.json`** (this table mirrors that file)._

| Entity | finding_id / query_id | module | verdict | severity | evidence (file:line) | produced_by (agent → call_id) | log |
|---|---|---|---|---|---|---|---|
| `file_path:C:\Users\fredr\AppData\Local\Temp\GUMF3B9.tmp\GoogleUpdateSetup.exe` | `disk-scan-f005` | disk | INCONCLUSIVE | — | `registry_shimcache.txt:19` (+2 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `file_path:ProgramData\Adobe\Setup\{AC76BA86-7AD7-1033-7B44-AC0F074E4100}\setup.exe` | `disk-scan-f028` | disk | INCONCLUSIVE | — | `mft_records.txt:56827` | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `file_path:ProgramData\Package Cache\{7f51bdb9-ee21-49ee-94d6-90afc321780e}\vcredist_x64.exe` | `disk-scan-f025` | disk | INCONCLUSIVE | — | `mft_records.txt:12610` | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `file_path:ProgramData\Package Cache\{ce085a78-074e-4823-8dc1-8a721b94b76d}\vcredist_x86.exe` | `disk-scan-f026` | disk | INCONCLUSIVE | — | `mft_records.txt:12628` | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `file_path:Users\fredr\AppData\Local\Temp\f4136dbd-be88-4a99-8fb9-c70f12760e2b.bat` | `disk-scan-f030` | disk | INCONCLUSIVE | — | `mft_records.txt:122230` | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `file_path:Users\fredr\AppData\Local\Temp\~nsu.tmp\Au_.exe` | `disk-scan-f032` | disk | INCONCLUSIVE | — | `mft_records.txt:36472` (+2 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `file_path:Users\srl-h\Downloads\sdelete64.exe` | `disk-scan-f029` | disk | CONFIRMED | MEDIUM | `mft_records.txt:33968` (+2 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `image_name:MSIEXEC.EXE` | `disk-scan-f007` | disk | INCONCLUSIVE | — | `prefetch_records.txt:83` (+4 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `image_name:REGSVR32.EXE` | `disk-scan-f002` | disk | INCONCLUSIVE | — | `prefetch_records.txt:110` (+3 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `image_name:RUNDLL32.EXE` | `disk-scan-f003` | disk | INCONCLUSIVE | — | `prefetch_records.txt:112` (+4 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `image_name:SDELETE.EXE` | `disk-scan-f001` | disk | CONFIRMED | HIGH | `prefetch_records.txt:131` (+3 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `image_name:VSSADMIN.EXE` | `disk-scan-f004` | disk | INCONCLUSIVE | — | `prefetch_records.txt:186` (+1 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `image_name:fredr` | `disk-scan-f013` | disk | CONFIRMED | CRITICAL | `eventlog_security.txt:449717` (+4 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `image_name:fredr` | `disk-scan-f019` | disk | CONFIRMED | HIGH | `eventlog_security.txt:406216` (+2 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `image_name:fredr` | `disk-scan-f020` | disk | CONFIRMED | HIGH | `eventlog_security.txt:163546` (+4 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `ip:141.98.83.187` | `disk-scan-f016` | disk | CONFIRMED | HIGH | `eventlog_security.txt:432782` (+3 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `ip:141.98.83.187` | `104ec4eb-2353-4688-9da0-ba5d41b4bcc0` | ti | INCONCLUSIVE | — | — | threat_intel/vt_lookup → `cf773f63-dd08-4ab0-8d2e-87aface2b515` | `threat_intel/queries.jsonl` |
| `ip:174.196.200.9` | `disk-scan-f014` | disk | INCONCLUSIVE | — | `registry_misc.txt:17973` (+3 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `ip:174.196.200.9` | `afe85599-ee06-48af-bee7-1b313556dcdf` | ti | NOT_FOUND | — | — | threat_intel/vt_lookup → `077eef02-fe09-4160-ae10-bc371ac8a2d5` | `threat_intel/queries.jsonl` |
| `ip:185.202.1.123` | `disk-scan-f023` | disk | INCONCLUSIVE | — | `eventlog_security.txt:302` (+2 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `ip:185.202.1.123` | `2ba3e125-d218-4ee1-94b6-ea26998a26a3` | ti | NOT_FOUND | — | — | threat_intel/vt_lookup → `99cd8981-f95d-4e62-a30c-1a50a1bf0830` | `threat_intel/queries.jsonl` |
| `ip:193.93.62.32` | `disk-scan-f008` | disk | CONFIRMED | CRITICAL | `eventlog_security.txt:302` (+3 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `ip:193.93.62.32` | `2502f433-adf0-43e3-b7b7-5ffa1423b11c` | ti | NOT_FOUND | — | — | threat_intel/vt_lookup → `162c8b2b-816d-4975-b201-e2693cef8a9a` | `threat_intel/queries.jsonl` |
| `ip:194.61.54.121` | `disk-scan-f015` | disk | CONFIRMED | HIGH | `eventlog_security.txt:132512` (+4 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `ip:194.61.54.121` | `00bb0485-10c5-4c79-b464-59ab2936543a` | ti | NOT_FOUND | — | — | threat_intel/vt_lookup → `d4a6ff2f-f4a2-448f-9a82-06e8676b8bed` | `threat_intel/queries.jsonl` |
| `ip:201.193.188.114` | `disk-scan-f017` | disk | CONFIRMED | HIGH | `eventlog_security.txt:302` (+2 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `ip:201.193.188.114` | `5987f5ce-c464-4fb0-b0a4-8f371707e57c` | ti | NOT_FOUND | — | — | threat_intel/vt_lookup → `a46cbed5-1b39-403d-b69c-236fec2c181d` | `threat_intel/queries.jsonl` |
| `ip:213.202.233.104` | `disk-scan-f011` | disk | CONFIRMED | CRITICAL | `eventlog_security.txt:626` (+5 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `ip:213.202.233.104` | `d41c77d2-5372-4150-b89c-0b84e9ef0051` | ti | NOT_FOUND | — | — | threat_intel/vt_lookup → `349bc95d-7ad0-4aaf-bfc3-baee87669ed3` | `threat_intel/queries.jsonl` |
| `ip:213.202.233.90` | `disk-scan-f010` | disk | CONFIRMED | CRITICAL | `eventlog_security.txt:302` (+2 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `ip:213.202.233.90` | `b46be1c3-cfdc-4a7b-a4be-9ee613cefba8` | ti | NOT_FOUND | — | — | threat_intel/vt_lookup → `d05111ea-6c7d-4322-acb8-a80db68d1919` | `threat_intel/queries.jsonl` |
| `ip:52.249.198.56` | `disk-scan-f012` | disk | CONFIRMED | CRITICAL | `eventlog_security.txt:19` (+4 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `ip:52.249.198.56` | `disk-scan-f024` | disk | CONFIRMED | LOW | `eventlog_security.txt:446812` (+5 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `ip:52.249.198.56` | `86f513d6-08ca-474d-b4c4-725c2bc885a2` | ti | NOT_FOUND | — | — | threat_intel/vt_lookup → `0f3a3fae-0497-4fdb-ba80-0ecfc27775f1` | `threat_intel/queries.jsonl` |
| `ip:81.19.209.101` | `disk-scan-f018` | disk | INCONCLUSIVE | — | `eventlog_security.txt:302` (+1 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `ip:81.19.209.101` | `830351de-958f-4abb-b52f-00af1a02e524` | ti | NOT_FOUND | — | — | threat_intel/vt_lookup → `84c0f267-a523-47ec-8a98-e184f74b3d77` | `threat_intel/queries.jsonl` |
| `ip:85.14.242.76` | `disk-scan-f009` | disk | CONFIRMED | CRITICAL | `eventlog_security.txt:435661` (+5 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `ip:85.14.242.76` | `0f7fc1ba-1d96-4fc3-87ca-3bfcfba4c259` | ti | NOT_FOUND | — | — | threat_intel/vt_lookup → `f505c43a-b87b-43ba-a037-455a9bad0ed9` | `threat_intel/queries.jsonl` |
| `ip:91.241.19.97` | `disk-scan-f022` | disk | CONFIRMED | MEDIUM | `eventlog_security.txt:302` (+3 more) | disk/pivot_analyst → 11 calls (see log): `57183b3d-40fe-4e59-8a20-5f80cf008b44`, `bb0cae37-2ba2-419e-8078-f06291e11521`, `1ba5569c-9e56-4dad-92fd-081c17ea5284`, `0bc1bf8d-eadd-4125-a4a7-1120a1076ea0`, `6893e7d0-7463-4ce3-9338-c296f667ab37`, `7afaf363-1e12-4da6-b96f-90054cabda83`, `dd8423e7-ca88-4b43-9f2f-4dc3a47b17da`, `6596978e-ebbc-4c43-9caa-bf239334384b`, `07e7f1aa-fdea-4adb-ad28-47ea17c96246`, `08daa6c3-d0a7-4dab-b4c3-15c2529b3176`, `0c9892b5-8a49-488a-87de-bb6137ee1aa2` | `disk/agent_calls.jsonl` |
| `ip:91.241.19.97` | `18fbbbbc-310f-480a-b75c-f599f490e230` | ti | INCONCLUSIVE | — | — | threat_intel/vt_lookup → `770168b6-3620-46be-a764-59fbaef37d87` | `threat_intel/queries.jsonl` |
| `pid:1004` | `ram-chunk_003-f001` | ram | INCONCLUSIVE | — | `aggregated_analyst.txt:174` (+6 more) | ram/pivot_analyst → `8b7e75e3-e46f-461a-a255-c91fc9806e06` | `ram/agent_calls.jsonl` |
| `pid:11392` | `ram-chunk_031-f001` | ram | INCONCLUSIVE | — | `aggregated_analyst.txt:1407` (+7 more) | ram/pivot_analyst → `b73e06d9-ff59-45c2-9dce-b13372c1bfd0` | `ram/agent_calls.jsonl` |
| `pid:14028` | `ram-chunk_036-f001` | ram | INCONCLUSIVE | — | `pslist.txt:154` (+7 more) | ram/pivot_analyst → `be0554ec-d34f-4db5-9d08-a3aa028213bf` | `ram/agent_calls.jsonl` |
| `pid:1676` | `ram-chunk_004-f001` | ram | INCONCLUSIVE | — | `psscan.txt:184` | ram/pivot_analyst → `d9b81fac-060e-433d-8790-d323333b6a35` | `ram/agent_calls.jsonl` |
| `pid:16824` | `ram-chunk_040-f001` | ram | INCONCLUSIVE | — | `privileges.txt:49500` (+4 more) | ram/pivot_analyst → `4ad9db86-9b85-4e49-8364-c9727e5f955a` | `ram/agent_calls.jsonl` |
| `pid:17316` | `ram-chunk_041-f001` | ram | CONFIRMED | HIGH | `pstree.txt:220` (+6 more) | ram/pivot_analyst → `572ed567-a9a5-4a21-9ec1-2aabc8b83d44` | `ram/agent_calls.jsonl` |
| `pid:19348` | `ram-chunk_042-f001` | ram | INCONCLUSIVE | — | `pstree.txt:100` (+6 more) | ram/pivot_analyst → `7617770c-c954-4e10-b80d-e68ef73baf93` | `ram/agent_calls.jsonl` |
| `pid:19436` | `ram-chunk_043-f001` | ram | INCONCLUSIVE | — | `pslist.txt:1395` (+6 more) | ram/pivot_analyst → `b0efe017-d0a7-4063-8bbf-c926f88b94eb` | `ram/agent_calls.jsonl` |
| `pid:21836` | `ram-chunk_046-f001` | ram | CONFIRMED | HIGH | `pslist.txt:2189` (+3 more) | ram/pivot_analyst → `0e886e25-ae8c-41de-a378-afe2b5de3152` | `ram/agent_calls.jsonl` |
| `pid:25508` | `ram-chunk_048-f001` | ram | INCONCLUSIVE | — | `aggregated_analyst.txt:70290` (+6 more) | ram/pivot_analyst → `e353c509-10a8-43d6-8c77-a216888e8639` | `ram/agent_calls.jsonl` |
| `pid:26768` | `ram-chunk_050-f001` | ram | CONFIRMED | HIGH | `psscan.txt:2162` | ram/pivot_analyst → `b7543f65-8bd7-493b-9fb0-990f1f30e255` | `ram/agent_calls.jsonl` |
| `pid:28864` | `ram-chunk_053-f001` | ram | INCONCLUSIVE | — | `cmdline.txt:2180` (+3 more) | ram/pivot_analyst → `9cd73b62-2127-4a5f-b56f-efc211b93e5c` | `ram/agent_calls.jsonl` |
| `pid:29440` | `ram-chunk_002-f001` | ram | INCONCLUSIVE | — | `pslist.txt:2188` (+5 more) | ram/pivot_analyst → `bf93b009-98f3-47af-a0fa-cacc5eb583a9` | `ram/agent_calls.jsonl` |
| `pid:29656` | `ram-chunk_046-f002` | ram | CONFIRMED | HIGH | `psscan.txt:1669` | ram/pivot_analyst → `0e886e25-ae8c-41de-a378-afe2b5de3152` | `ram/agent_calls.jsonl` |
| `pid:30012` | `ram-chunk_054-f001` | ram | INCONCLUSIVE | — | `privileges.txt:76240` (+7 more) | ram/pivot_analyst → `aa85045b-753f-45ed-892b-b609d6e55ff0` | `ram/agent_calls.jsonl` |
| `pid:30216` | `ram-chunk_055-f001` | ram | INCONCLUSIVE | — | `pslist.txt:2186` (+6 more) | ram/pivot_analyst → `c575532b-4423-433b-b338-4bfb419c253e` | `ram/agent_calls.jsonl` |
| `pid:4420` | `ram-chunk_006-f001` | ram | INCONCLUSIVE | — | `psscan.txt:50` | ram/pivot_analyst → `85a11a93-1ea4-4e17-a749-dec0c02af7d9` | `ram/agent_calls.jsonl` |
| `pid:7900` | `ram-chunk_015-f001` | ram | INCONCLUSIVE | — | `psscan.txt:1678` (+1 more) | ram/pivot_analyst → `9e9e02af-81a1-479d-b7e2-add6e428fbdf` | `ram/agent_calls.jsonl` |
| `pid:800` | `ram-chunk_001-f001` | ram | INCONCLUSIVE | — | `privileges.txt:185` (+6 more) | ram/pivot_analyst → `de362726-1de6-4e5c-bda9-aad980138661` | `ram/agent_calls.jsonl` |
| `pid:8156` | `ram-chunk_016-f001` | ram | INCONCLUSIVE | — | `privileges.txt:3685` (+3 more) | ram/pivot_analyst → `f584a9cf-473f-409e-b7bd-dbc497d33c39` | `ram/agent_calls.jsonl` |
| `pid:8164` | `ram-chunk_016-f002` | ram | INCONCLUSIVE | — | `privileges.txt:3720` (+4 more) | ram/pivot_analyst → `f584a9cf-473f-409e-b7bd-dbc497d33c39` | `ram/agent_calls.jsonl` |
| `pid:8172` | `ram-chunk_017-f001` | ram | INCONCLUSIVE | — | `pslist.txt:1194` (+7 more) | ram/pivot_analyst → `37424b94-e175-480e-9294-2884f030c47c` | `ram/agent_calls.jsonl` |
| `pid:8728` | `ram-chunk_020-f001` | ram | INCONCLUSIVE | — | `privileges.txt:4350` (+3 more) | ram/pivot_analyst → `25f1acc9-d08f-428f-a546-28e4a217eb89` | `ram/agent_calls.jsonl` |
| `pid:9488` | `ram-chunk_024-f001` | ram | INCONCLUSIVE | — | `pslist.txt:1163` (+6 more) | ram/pivot_analyst → `32efee52-b14f-46c2-8bff-1a4dbd1e88c0` | `ram/agent_calls.jsonl` |
| `pid:9644` | `ram-chunk_025-f001` | ram | INCONCLUSIVE | — | `pstree.txt:116` (+5 more) | ram/pivot_analyst → `7d332137-426a-454a-b8d6-62f6c33cd512` | `ram/agent_calls.jsonl` |
| `pid:9836` | `ram-chunk_027-f001` | ram | INCONCLUSIVE | — | `pslist.txt:124` (+5 more) | ram/pivot_analyst → `2b084bb4-c04e-4328-a22e-9338e881fcf5` | `ram/agent_calls.jsonl` |
| `pid:9964` | `ram-chunk_028-f001` | ram | INCONCLUSIVE | — | `pslist.txt:125` (+7 more) | ram/pivot_analyst → `734fcccb-a82b-4e55-9156-a2342322e05a` | `ram/agent_calls.jsonl` |
