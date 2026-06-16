# Accuracy Report

## A. Nature of this document and methodology

This is a **self-assessment**. Its goal is to evaluate AMAMA's findings against ground truth,
stating where the tool is right, where it is unsure, and where there is room to improve. The
assessment is metric-driven rather than anecdotal, so results can be compared across datasets.

The document is modular: a methodology section, then one accuracy section per dataset, an
evidence-integrity section, and a cross-dataset summary. New cases can be appended in the same
template.

### Ground-truth basis

Each assessment is scored against the best ground truth we could obtain for that source:

- **ROCBA**: the SANS Hackathon-2026 "Standard Forensic Case" briefing
  (<https://sansorg.egnyte.com/fl/HhH7crTYT4JK#folder-link/HACKATHON-2026/Standard%20Forensic%20Case>).
- **Clean Windows 11**: known-clean by construction
  (<https://drive.google.com/drive/folders/1CLuyib651DgSv24-JyiIgw5gdcWYvj3x>).
- **NimPlantv2**: the scenario description published with the daniyyell dataset
  (<https://daniyyell.com/datasets/Memory-Forensics-Attack-Simulation-Dataset/>).
- **QuasarRAT**: known malware behaviour for the executed sample (RAM-only capture; same
  Google-Drive location as the clean image).
- **Stolen Szechuan Sauce (Case001)**: the published DFIR Madness case answers
  (<https://dfirmadness.com/answers-to-szechuan-case-001/>; case:
  <https://dfirmadness.com/the-stolen-szechuan-sauce/>).

Objective ground truth varies by source: public datasets disclose different levels of detail, and
self-built images carry the ground truth recorded while building them. The scoring below reflects
the best available reference for each case.

### Verdict and scoring model

AMAMA assigns each entity one of three verdicts: **CONFIRMED**, **INCONCLUSIVE**, or
**REJECTED**. We score these as follows:

- On the **clean** image, **any CONFIRMED finding is a false positive**. This is the specificity
  test.
- On **malicious** images:
  - a CONFIRMED finding that matches ground truth counts as a **true positive**; one that does
    not counts as an **over-claim / false positive**;
  - a ground-truth element absent from the report counts as a **missed artifact / false
    negative**;
  - any claim not supported by the cited verbatim evidence counts as a **hallucination**.

A central design property worth measuring is **confirmation discipline**, meaning how readily the
pipeline escalates an anomaly to CONFIRMED versus parking it at INCONCLUSIVE. A trustworthy
triage tool should confirm aggressively on real intrusions and stay quiet on clean data.

### Key metrics (all cases)

| # | Dataset | Modules | Confirmed | Inconclusive | Total | Confirm-rate | Confirmed:Inconclusive | Confirmed severity |
|---|---------|---------|-----------|--------------|-------|--------------|------------------------|--------------------|
| 1 | ROCBA (disk+RAM) | ram·disk·ti | 16 | 36 | 52 | 31% | 0.44 | 6 CRITICAL, 10 HIGH |
| 2 | Clean Win11 (RAM) | ram·ti | 2 | 15 | 17 | **12%** | **0.13** | 2 HIGH |
| 3 | NimPlantv2 (RAM) | ram·ti | 4 | 8 | 12 | 33% | 0.50 | 4 HIGH |
| 4 | QuasarRAT (RAM) | ram·ti | 6 | 6 | 12 | 50% | 1.00 | 1 CRITICAL, 5 HIGH |
| 5 | Szechuan Sauce (RAM) | ram·ti | 5 | 16 | 21 | 24% | 0.31 | 2 CRITICAL, 3 HIGH |

**The clean image has by far the lowest confirmation rate and the lowest
confirmed-to-inconclusive ratio.** That is exactly the desired ordering: the pipeline confirms
least on the one image where there is nothing to confirm.

---

## B. Per-dataset accuracy

Each section follows the same shape: ground truth, what it got right, what it missed, false
positives, hallucination check, and per-case metrics.

### B.1 ROCBA workstation

**Ground truth (from the case briefing).** An IP-theft and espionage case in which **Fred Rocba
is the victim, not the perpetrator**. Fred is a newly hired engineer at Stark Research Labs (SRL).
He received an SRL-issued Windows 10 Surface and worked from home via RDP and SaaS. He left for a
Disney vacation on 2020-11-10, and on the **evening of 2020-11-13 (EDT)** an intruder physically
broke into his home and used his SRL system, which was left powered on and logged in, to steal SRL
intellectual property. The briefing poses five questions: (1) what key projects did Fred have
access to, (2) what was stolen, (3) **where was it transferred to**, (4) how was it stolen, and
(5) when did the activity occur.

**What it got right (true positives).**
- **Identified the focal compromised account and system**: `fredr` (`fred.rocba@outlook.com`) on
  Fred's machine, the correct centre of gravity for the investigation.
- **Answered Q1 (projects accessed)**: surfaced the **OneDrive "Stark Research Labs /
  SRL-Projects - Airwolf"** project folder, naming the key SRL project (**Airwolf**) the actor
  reached, plus access to the user's **Outlook `.ost` email store** (`fred.rocba@outlook.com.ost`).
- **Answered Q5 (when)**: placed the key activity at roughly **2020-11-14T03:42 UTC**, which is
  the **evening of 2020-11-13 EDT** and matches the break-in window in the briefing once time
  zones are normalised. This is a strong corroboration.
- **Partially answered Q4 (how)**: reconstructed plausible mechanisms, including the kernel-mode
  driver install `googledrivefs3229`, RDP/SMB lateral movement, **SDelete** secure-deletion
  anti-forensics, and an in-memory process-hollowing cluster, with a coherent MITRE ATT&CK
  mapping.

**What it missed or got partially wrong.**
- **Q3, "where was it transferred to?", is unanswered.** This is the single most material gap.
  The report surfaces access to the email store and the Airwolf folder and notes timing
  "consistent with exfiltration", but never establishes the exfiltration destination.
- **Q2, "what was stolen?", is only partially answered.** It identifies what was accessed
  (Airwolf project data, the `.ost`) but does not conclusively establish what left the system.
- **Vector framing (worth noting).** The briefing frames the intrusion as physical access to a
  logged-in machine, whereas the agent's evidence-led narrative emphasises remote activity: a
  brute-force/spray campaign and a logon from the Azure IP `52.249.198.56` ("cobra") with a
  `MicrosoftAccount` LogonType-7 unlock, all backed by real log events. The two are not mutually
  exclusive, since a physically present intruder can still drive remote and cloud sessions, but
  the agent did not explicitly reconcile its remote-takeover framing with the physical-access
  scenario in the briefing. Tightening attack-vector attribution is a useful next step.

**Hallucination check.** Findings are tied to verbatim artifact lines via the traceability index.
Spot-checks of the key claims (the Airwolf/OneDrive and `.ost` access, the `googledrivefs3229`
driver, the SDelete runs) resolve to cited evidence. The point above is one of interpretation and
attribution (remote versus physical vector), not fabricated evidence.

**Per-case metrics.** 16 CONFIRMED (6 CRITICAL, 10 HIGH) / 36 INCONCLUSIVE / 52 total. The high
inconclusive count is partly explained by the actor's own SDelete anti-forensics, which destroyed
corroborating artifacts and legitimately holds many entities below the confirmation threshold.

### B.2 Clean Windows 11, the specificity control

**Ground truth.** Nothing malicious. The ideal result is **zero** confirmed findings.

**What it got right.** **15 of 17 entities were correctly held at INCONCLUSIVE** rather than
confirmed, including several processes carrying the same orphaned-parent and broad-privilege
signals that, on the malicious images, contributed to confirmations. The pipeline kept its
confirmation discipline on benign data.

**Confirmation discipline.** The confirmation rate here is **12%** with a
confirmed-to-inconclusive ratio of **0.13**, far below every true-positive case (0.44, 0.50,
1.00). The agent does **not** escalate on the slightest anomaly: it reserves CONFIRMED for
stronger signals and parks the rest.

**Where it can improve.** Two entities were confirmed HIGH as DKOM process-hiding — PID 8112
(`olk.exe`) and PID 8060 (`svchost.exe`) — both "psscan-only, orphaned-parent" reads. These
patterns can occur naturally when a process or its parent exits just before capture, so tightening
the DKOM heuristic against snapshot-timing effects is a clear refinement for this control.

**Per-case metrics.** 2 CONFIRMED / 15 INCONCLUSIVE / 17 total, a confirmation rate of roughly
**12%** — the lowest of any dataset.

### B.3 NimPlantv2 process-injection

**Ground truth.** Hard process injection with **NimPlant v2**, **scheduled-task** persistence,
**outbound C2 suspected**, and code running inside a legitimate process.

**What it got right.**
- Caught the "code in a legitimate process" theme: SYSTEM-equivalent token theft on legitimate
  binaries, namely `MicrosoftEdgeUpdate.exe` (PID 5348), `RuntimeBroker.exe` (PID 6056), and
  `audiodg.exe` (PID 8552), with `RuntimeBroker` also showing PEB loader-list flags all false
  (hidden mapped code).
- Surfaced an **outbound C2 candidate**: `backgroundTask` (PID 8336) to `23.192.26.3:80`,
  confirmed HIGH. Additional outbound connections were flagged at INCONCLUSIVE, including an
  internal **`192.168.135.57:8070`** (a port associated with C2/proxy frameworks) from
  `explorer.exe`.
- Produced a MITRE mapping (T1055 / T1134) and a coherent timeline.

**Scope notes.**
- It did not name the implant family (NimPlant) — attribution-level naming was out of scope for
  this run.
- Scheduled-task persistence was not surfaced, as expected for a RAM-only run with no disk module
  to read scheduled-task artifacts.
- The internal-C2 indicator (`explorer.exe` to `192.168.135.57:8070`) was held at **INCONCLUSIVE**
  because the underlying `netscan` line was not captured verbatim — a direct consequence of the
  strict "no verbatim evidence, no confirmation" rule that keeps confirmations trustworthy.

**False positives.** The 4 confirmations all sit on genuinely anomalous in-memory state for this
attack scenario; none reads as a clear over-claim against ground truth.

**Hallucination check.** Confirmed findings cite verbatim privilege and network lines. The one
place where a signal outran its evidence (the explorer C2 connection) was correctly demoted to
inconclusive rather than asserted, which is the opposite of hallucination.

**Per-case metrics.** 4 CONFIRMED HIGH / 8 INCONCLUSIVE / 12 total.

### B.4 QuasarRAT infection

**Ground truth.** A live QuasarRAT (.NET RAT) infection. Expected signatures include the implant
at **`%APPDATA%\SubDir\Client.exe`**, **`HKCU\…\Run`** persistence, and outbound C2.

> **RAM-only caveat.** Only memory was captured for this case; disk was not analysed. Several of
> the gaps below (registry Run-key persistence, the on-disk dropper) live primarily on disk, and
> disk correlation would very likely have recovered them.

**What it got right.**
- **Reconstructed the full dropper chain**: `cmd.exe` (5568) to `Client.exe` (5836) to `cmd.exe`
  (7980) to persistent `Client.exe` (376), plus a parallel batch stager (`cmd.exe` 2380 invoking
  `EMwLtc9FBmME.bat` from Temp).
- **Correctly identified the terminal implant**: `Client.exe` running from
  `C:\Users\…\AppData\Roaming\SubDir\`, the exact QuasarRAT install signature, as the sole
  surviving process, confirmed CRITICAL.
- **Recognised it as a .NET implant** (`MSCOREE.DLL` and a self-referential module load), which
  is consistent with QuasarRAT being a .NET RAT.
- Identified the **PING-as-sleep** tradecraft used between dropper stages, and produced a clean
  timeline and MITRE mapping (T1059.003, T1543, T1134).

**Scope notes.**
- It did not name the family (QuasarRAT) or tie the chain back to the original dropper
  `1doiliemkhiet.exe`.
- The `HKCU\…\Run` persistence key was not recovered, and the C2 network connection was not
  surfaced.

The RAM-only scope is the dominant reason for the last two: persistence and the on-disk dropper
are disk-resident, and a paired disk capture would very likely have closed those gaps.

**False positives.** Confirmations centre on the genuine dropper chain and implant; they align
with ground truth for an active QuasarRAT infection.

**Hallucination check.** The dropper-chain relationships and the `AppData\Roaming\SubDir` path
are corroborated across `pstree`, `psscan`, and `cmdline` evidence in the traceability index. No
fabricated evidence identified.

**Per-case metrics.** 6 CONFIRMED (1 CRITICAL, 5 HIGH) / 6 INCONCLUSIVE / 12 total.

### B.5 Stolen Szechuan Sauce (Case001)

**Ground truth (from the published answers).** A Metasploit **Meterpreter** intrusion on
19 September 2020: RDP brute-force from **`194.61.24.102`** into the domain controller, a payload
(`coreupdate.exe`) downloaded over HTTP and installed persistently **as a Local System auto-start
service and via the registry**, with the on-disk beacon at **`C:\Windows\System32\coreupdater.exe`**;
lateral movement over RDP to the Windows 10 desktop (`DESKTOP-SDN1RPT`, the image analysed here),
the same malware deployed there, data exfiltrated (`secret.zip`, `loot.zip`), and a second
malicious IP **`203.78.103.109`**. We ran the RAM module against the desktop memory image only.

**What it got right (true positive).** The headline result is a direct match: AMAMA confirmed
**`coreupdater.exe` (PID 8324)** as a non-system binary masquerading in `\Windows\System32\` with a
SYSTEM-class token, independently corroborated by the `malware_pebmasquerade` plugin. This is
exactly the case's persistent Meterpreter service binary, recovered from memory with no prior
knowledge of the scenario.

**Post-exploitation cluster (consistent with ground truth).** The remaining four confirmations —
process hollowing of `csrss.exe` (424, shellcode command line and PEB masquerade), a hollow
`svchost.exe` (1148, no `-k` argument and SYSTEM token), a tampered `RuntimeBroker.exe` (8128, a
structurally impossible module-list entry), and an abused `WmiPrvSE.exe` (8416, fully enabled
SYSTEM token) — are consistent with Meterpreter process migration and token manipulation, which the
published answers describe ("migrated it"). The `csrss` and `RuntimeBroker` findings each rest on
strong multi-signal evidence; the token-only reads in this cluster are weaker and overlap with the
snapshot-timing pattern noted on the clean control (B.2), so a portion of the cluster is better
read as corroborating activity than as five fully independent implants.

**What it missed (RAM-only scope).** It did not name the payload as Meterpreter/Metasploit, surface
the attacker/C2 IPs (`194.61.24.102`, `203.78.103.109`), or reconstruct the RDP entry vector, the
service/registry persistence, the lateral movement, or the data exfiltration (`secret.zip`,
`loot.zip`, `Szechuan Sauce.txt`). These live primarily in disk, registry, log, and PCAP evidence;
a paired disk capture and the available PCAP would close most of them.

**Hallucination check.** The System32 path, SYSTEM-class token, and PEB-masquerade flag for
`coreupdater.exe` resolve to cited verbatim evidence, as do the privilege and module-list anomalies
behind the other confirmations. No fabricated evidence identified.

**Per-case metrics.** 5 CONFIRMED (2 CRITICAL, 3 HIGH) / 16 INCONCLUSIVE / 21 total. Confirmation
rate 24%, above the clean control (12%) and in line with the other malicious cases.

---

## C. Evidence-integrity approach

A core requirement is that AMAMA must never alter the original evidence, and that this must not
depend on the language model choosing to behave. The architecture enforces integrity
structurally, at several independent layers:

- **Deterministic extraction "sandwich".** The LLM agents never touch raw evidence. Deterministic
  Python collectors extract text artifacts from the image; the agents receive only that text and
  return schema-validated JSON findings (`messages.create` in
  `Backbone/backbone/orchestrator/agent.py` and `Backbone/backbone/report/agent.py`). The agents
  are given no filesystem, shell, or write tool, so there is no action surface through which a
  model could reach the original image.
- **Disk image mounted read-only.** The Windows volume is mounted with
  `mount -o ro,noexec,nosuid` (ntfs-3g, falling back to the kernel `ntfs3` driver), in
  `Modules/Disk/disk-image-mounter/mount_image.py` (`mount_ntfs`, around lines 576 to 610). The
  raw image is reached through a loop device, and `$MFT` is carved with `icat` (read-only Sleuth
  Kit).
- **Browser databases opened immutable.** SQLite stores are opened with
  `file:…?mode=ro&immutable=1` so parsing cannot write back, in
  `Modules/Disk/disk-collector/browser_collector.py` (lines 30 to 31, "never touches the file").
- **RAM parsed passively.** Volatility 3 is a read-only parser; the memory image is only read,
  never written.
- **Integrity by hashing.** PE files are hashed with streaming SHA-256
  (`Modules/Disk/disk-collector/pe_analyzer.py`, `sha256_file`, around lines 64 to 75). Those
  hashes flow into findings and threat-intel lookups, giving a verifiable fingerprint of what was
  analysed.
- **Full traceability and auditing.** Every run writes a self-contained audit tree, and every
  finding is traceable from the report, through its `finding_id`, to the `produced_by` call_id,
  to the exact JSONL agent call that produced it (the "Evidence Traceability Index", Section 7 of
  each `incident_report.md`, mirrored in `traceability.json`). No claim is free-floating: an
  analyst can always walk back to the tool execution and the verbatim artifact line behind it.
  This is itself an integrity control, because it makes fabricated or untraceable evidence
  detectable.

**What happens if an agent tries to bypass these protections?** Integrity does not rely on the
model's good behaviour, because three independent barriers stand in the way:

1. **No capability.** The agent is text-in and JSON-out, with no write, exec, or file tool. There
   is simply no action it can emit that touches the evidence.
2. **Kernel enforcement.** Even if a write were somehow attempted against the mount, the `ro`
   mount makes any write syscall fail with `EROFS`, and `noexec` prevents executing recovered
   malware from the mounted image.
3. **Schema gate.** The orchestrator ingests only contract-valid findings; any malformed or
   out-of-band agent output is dropped, never executed.

The original evidence therefore remains unmodified regardless of how an agent behaves.

---

## D. Cross-dataset summary and limitations

Repeating the headline metric, the **confirmation rate** rises with the strength of real malice
and falls to its minimum on the clean control:

| Dataset | Confirm-rate | Confirmed:Inconclusive |
|---------|--------------|------------------------|
| Clean Win11 (control) | **12%** | **0.13** |
| Szechuan Sauce | 24% | 0.31 |
| ROCBA | 31% | 0.44 |
| NimPlantv2 | 33% | 0.50 |
| QuasarRAT | 50% | 1.00 |

This ordering is the most important quantitative result in this report: the pipeline confirms
least where there is nothing to find. On the clean control, 15 of 17 entities were correctly held
at INCONCLUSIVE, with the two HIGH confirmations pointing to a focused refinement of the
DKOM/psscan-only heuristic.

**Limitations and future work.**
- **RAM-only cases cannot see disk, registry, or network evidence.** Scheduled-task persistence
  (NimPlantv2), Run-key persistence plus the on-disk dropper (QuasarRAT), and the service/registry
  persistence, RDP entry vector, and C2 IPs (Szechuan Sauce) live primarily on disk, in the
  registry, or in network captures; pairing a disk capture and PCAP with the memory image would
  materially strengthen those cases.
- **Precision over recall.** Some real signals are deliberately held at INCONCLUSIVE when no
  verbatim evidence line was captured, for example the strongest internal-C2 connection in the
  NimPlantv2 case. This trades some recall for trustworthiness: we would rather under-claim than
  assert something the evidence does not directly support.
- **DKOM and snapshot-timing heuristics** are the clearest area to sharpen, as shown by the
  clean-image control and by the weaker token-only reads in the Szechuan post-exploitation cluster.

**Bottom line.** AMAMA carried the major narrative on every malicious case: the focal compromised
account and the accessed **Airwolf** project (plus a break-in time that matches the briefing) on
ROCBA, the right implant and dropper chain on QuasarRAT, the right
injection-into-legitimate-process pattern plus a C2 candidate on NimPlantv2, and the persistent
**`coreupdater.exe` Meterpreter beacon** in System32 on Szechuan Sauce — all while keeping its
confirmation rate lowest on clean data. The clearest next steps are sharpening the DKOM heuristic,
tightening attack-vector attribution (the remote-versus-physical question on ROCBA), answering the
exfiltration-destination question, and widening disk and network coverage.