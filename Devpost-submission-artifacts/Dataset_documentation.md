# Dataset Documentation

This document records **what AMAMA was tested against**: the source and provenance of every
evidence image fed to the pipeline, the expected (ground-truth) content of each, and a short
factual summary of what the agent found. It is intentionally modular, with one section per
dataset, so additional cases can be appended without restructuring.

A critical evaluation of these findings (false positives, missed artifacts, hallucination
checks, key metrics) is provided in the accuracy report. The raw runs that back every claim are
in agent_execution_logs/.

A note on ground truth: assembling objective ground truth for forensic memory and disk images is
genuinely hard. Public datasets vary in how much they disclose, and self-built images only have
the ground truth we recorded while building them. The "expected content" below reflects our best
effort per source.

---

## Overview

| # | Dataset | Evidence type | Source | Logs |
|---|---------|---------------|--------|------|
| 1 | ROCBA workstation | Disk **+** RAM | SANS Hackathon-2026 "Standard Forensic Case" | `ROCBA/` |
| 2 | Clean Windows 11 | RAM only | Self-built (fresh Win11 VM) | `Windows_11_c/` |
| 3 | NimPlantv2 process-injection | RAM only | Public, daniyyell Memory-Forensics dataset | `daniyyell_dataset_4/` |
| 4 | QuasarRAT infection | RAM only | Self-built (same Win11 VM plus live malware) | `Windows_11_VM_e/` |
| 5 | Stolen Szechuan Sauce (Case001) | RAM only | Public, DFIR Madness "Case001" (Windows 10 desktop memory) | `Szechuan_Sauce/` |

(The Logs column gives the per-case subfolder inside agent_execution_logs/.)

---

## 1. ROCBA workstation (disk + RAM)

**Source and provenance.** SANS Hackathon-2026 "Standard Forensic Case", published as a paired
disk image and RAM image of a single Windows workstation.
URL: <https://sansorg.egnyte.com/fl/HhH7crTYT4JK#folder-link/HACKATHON-2026/Standard%20Forensic%20Case>
This is the only case in our set with both disk and memory evidence, so it exercises the full
RAM, Disk, and Threat-Intel orchestration. A vendor-supplied case briefing (slide deck)
accompanies the images and serves as the ground truth.

**Expected content / ground truth (from the case briefing).** This is an IP-theft and espionage
case, and **Fred Rocba is the victim, not the perpetrator**. Fred is a newly hired engineer at
**Stark Research Labs (SRL)**, a high-tech R&D firm (biotech, metals, advanced alloys,
weapons-adjacent projects) and a long-standing target of nation-state cyber groups. He received
an SRL-issued Microsoft Surface (Windows 10, fully patched, single-user, US Eastern time) on
2020-10-24 and worked from home via RDP and SaaS (Office 365 / Exchange
`frocba@stark-research-labs.com`, Dropbox, OneDrive, Google Drive, iCloud; Outlook managing both
`fred.rocba@gmail.com` and `fred.rocba@outlook.com`).

The incident: Fred left for a planned Disney vacation on the morning of **2020-11-10**. On the
**evening of 2020-11-13 (EDT)** an intruder physically broke into his home and used his SRL
system, which was left powered on and logged in, to access and steal SRL intellectual property.
Nothing physical was taken; the theft was digital. The briefing frames the case as **five key
questions** for the analyst to answer:

1. What key projects did Fred Rocba have access to?
2. What was stolen?
3. **Where was it transferred to?**
4. How was it stolen?
5. When did the activity occur?

**What the agent found (summary).** AMAMA centred the investigation on the focal compromised
account **`fredr`** (`fred.rocba@outlook.com`) on Fred's system and surfaced access to sensitive
SRL data: the **OneDrive "Stark Research Labs / SRL-Projects - Airwolf"** project folder
(directly answering "what projects") and the user's **Outlook `.ost` email store**. It placed the
key activity at roughly 2020-11-14T03:42 UTC, which is the evening of 2020-11-13 EDT and matches
the break-in window, and reconstructed a chain of mechanisms (account use, kernel-driver install
`googledrivefs3229`, RDP/SMB lateral movement, SDelete anti-forensics, in-memory hollowing) with
a MITRE ATT&CK mapping. 16 entities CONFIRMED, 36 INCONCLUSIVE. Note that the agent attributed
the access to a remote external takeover (brute-force plus an Azure IP, "cobra" `52.249.198.56`),
whereas the briefing describes a physical intrusion of the logged-in system, a vector difference
discussed in the accuracy report. The "where was it transferred to?" question was **not**
answered.

---

## 2. Clean Windows 11 (RAM only)

**Source and provenance.** Self-built. A completely fresh Windows 11 installed from the official
Microsoft media, run unmodified in VirtualBox, with its memory captured via VirtualBox's
`dumpvmcore`. No software was installed and no malware was ever introduced.
URL: <https://drive.google.com/drive/folders/1CLuyib651DgSv24-JyiIgw5gdcWYvj3x>

**Expected content / ground truth.** **Nothing malicious.** This image is a negative control: a
perfect run would confirm zero malicious findings. It measures the pipeline's specificity, that
is, its tendency to raise false alarms on benign data.

**What the agent found (summary).** AMAMA produced **2 CONFIRMED HIGH** findings (both
process-hiding / DKOM reads on benign processes) and held the remaining **15** entities at
INCONCLUSIVE. On a clean image the 2 confirmations are, by definition, false positives, but the
very low confirmation rate relative to the malicious cases is an encouraging signal of the
pipeline's restraint. This is treated in full in the accuracy report.

---

## 3. NimPlantv2 process-injection (RAM only)

**Source and provenance.** Public dataset, daniyyell "Memory-Forensics Attack Simulation
Dataset", which bundles several memory images, each with a short scenario description.
URL: <https://daniyyell.com/datasets/Memory-Forensics-Attack-Simulation-Dataset/>
We used the hard process-injection scenario.

**Expected content / ground truth.** As described by the dataset author: process injection
(hard) using **NimPlant v2**, **scheduled-task** persistence, **outbound C2 suspected**, with
the implant's code running inside a legitimate process.

**What the agent found (summary).** AMAMA flagged the "code in a legitimate process" pattern via
SYSTEM-equivalent token theft on legitimate binaries (`MicrosoftEdgeUpdate.exe`,
`RuntimeBroker.exe`, `audiodg.exe`) and surfaced an **outbound C2 candidate**
(`backgroundTask` to `23.192.26.3:80`), with additional outbound connections (including an
internal `192.168.135.57:8070`) held at INCONCLUSIVE. 4 entities CONFIRMED HIGH, 8 INCONCLUSIVE.
MITRE T1055 / T1134 and a timeline were produced.

---

## 4. QuasarRAT infection (RAM only)

**Source and provenance.** Self-built. The same clean Windows 11 VirtualBox base as dataset 2,
into which we uploaded and executed a live **QuasarRAT** sample (`1doiliemkhiet.exe`, a roughly
3.2 MB .NET Windows Remote Access Trojan), then captured memory roughly 30 seconds after
execution.
URL (same location as dataset 2): <https://drive.google.com/drive/folders/1CLuyib651DgSv24-JyiIgw5gdcWYvj3x>

> **Caveat.** For this case we captured RAM only; the disk was not collected or analysed.
> Correlating the memory findings with disk artifacts (registry hives, the on-disk dropper,
> persistence keys) would very likely have produced richer intelligence. The RAM-only scope is a
> known limitation of this particular case.

**Expected content / ground truth.** Known QuasarRAT behaviour: a .NET RAT that provides remote
control, command execution, file transfer, keylogging and credential theft. It commonly installs
its implant to **`%APPDATA%\SubDir\Client.exe`** and persists via the
**`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`** key, with outbound C2 to the operator.

**What the agent found (summary).** AMAMA reconstructed the full dropper chain
(`cmd.exe` to `Client.exe` to `cmd.exe` to `Client.exe`) and correctly identified the persistent
implant **`Client.exe` running from `C:\Users\…\AppData\Roaming\SubDir\`**, the exact QuasarRAT
install signature, flagging it as a **.NET implant** (`MSCOREE.DLL`) under a SYSTEM-equivalent
token. 6 entities CONFIRMED (1 CRITICAL, 5 HIGH), 6 INCONCLUSIVE, with a timeline and MITRE
mapping. Gaps (family attribution, Run-key persistence, C2 network) are discussed in the accuracy
report.

---

## 5. Stolen Szechuan Sauce — Case001 (RAM only)

**Source and provenance.** Public training case from DFIR Madness, "Case001 — The Stolen Szechuan
Sauce", a paired-host intrusion scenario (a Windows Server 2012 R2 domain controller `DC01` and a
Windows 10 workstation `DESKTOP-SDN1RPT`) with disk, memory, pagefile, autoruns, and PCAP evidence
for each. We analysed the **Windows 10 desktop memory image** (`DESKTOP-SDN1RPT-memory`) with the
RAM module only.
Case: <https://dfirmadness.com/the-stolen-szechuan-sauce/>
Answers (ground truth): <https://dfirmadness.com/answers-to-szechuan-case-001/>

**Expected content / ground truth (from the published answers).** On 19 September 2020, an attacker
at **`194.61.24.102`** brute-forced RDP (Hydra) into the internet-exposed domain controller as
`Administrator`, then used Internet Explorer to download a **Metasploit Meterpreter** payload
(`coreupdate.exe`) over HTTP. The malware was installed persistently **as an auto-start Windows
service running as Local System and via the registry**, with the on-disk beacon at
**`C:\Windows\System32\coreupdater.exe`**. The attacker moved laterally over **RDP from the DC to
`DESKTOP-SDN1RPT`** and deployed the same malware there, then exfiltrated data (`secret.zip` from
the DC, `loot.zip` from the desktop), accessed `Szechuan Sauce.txt`, and time-stomped
`Beth_Secret.txt`. A second malicious IP, **`203.78.103.109`**, was also involved.

**What the agent found (summary).** From memory alone, AMAMA confirmed the case's signature
implant: **`coreupdater.exe` (PID 8324) masquerading as a system binary in `\Windows\System32\`**
with a SYSTEM-class token, independently flagged by the `malware_pebmasquerade` plugin — a direct
match to the persistent Meterpreter service binary in the ground truth. It additionally confirmed a
cluster of in-memory post-exploitation activity consistent with Meterpreter process migration:
process hollowing of `csrss.exe` (PID 424, shellcode command line + PEB masquerade), a hollow
`svchost.exe` (PID 1148, no `-k` argument, SYSTEM token), a tampered `RuntimeBroker.exe` (PID 8128,
impossible module-list entry), and an abused `WmiPrvSE.exe` (PID 8416, fully enabled SYSTEM token).
**5 entities CONFIRMED (2 CRITICAL, 3 HIGH), 16 INCONCLUSIVE**, with a MITRE mapping (T1055.012,
T1134, T1036.005, T1047) and a partial timeline.