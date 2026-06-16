# AMAMA — Multi-Agent DFIR Triage

AMAMA is designed as a **modular DFIR workbench**: the Backbone orchestrator coordinates the investigation, and forensic capabilities plug into it as modules. A module only needs to expose a small contract (`scan`, `query`) and be listed in `Backbone/config/orchestrator.yaml`; Backbone then knows how to run it, add its findings to a case graph, and ask follow-up questions, either to the same module or to another one for cross-module investigation. Today, the built-in modules are **RAM**, **Disk**, and **Threat Intel**, but the same contract is meant for future modules too.

A short demo video walking through a live run is available at https://youtu.be/WyYYYbMxT6E.

In a typical run, with the current setup, AMAMA takes a raw **memory image** and a raw **disk image** and produces an evidence-traceable `incident_report.md`. RAM and Disk run in parallel and follow the same internal architecture: each module first uses deterministic extraction scripts to extract artifacts from the images (for example, Volatility in the RAM module) before handing focused evidence to LLM agents. This avoids sending huge raw inputs to the model while still preserving deep forensic context. Backbone merges their findings into one case graph, enriches confirmed IOCs using the Threat Intel module, which calls the VirusTotal API, routes cross-module follow-up queries, and writes the final report. The goal is to keep the system extensible while making every conclusion traceable back to verbatim artifact evidence. See [`Modules/README.md`](Modules/README.md) for the plug-in contract.

## Project layout

```
AMAMA/
  Backbone/         orchestrator, threat-intel + report agents, contracts/schemas
  Modules/
    RAM/            memory forensics module (Volatility 3)
    Disk/           disk forensics module (mount, MFT, registry, event logs, …)
```

Each part has its own README. `Modules/README.md` explains the module contract and how to plug in a new module — **any module declared in the orchestrator config is fully integrated automatically**.

## Documentation map

Every part of the repo documents itself; this is the index.

| Doc | What it covers |
|---|---|
| [`Architecture.pdf`](Architecture.pdf) | High-level system diagram (single-page overview) |
| [`Backbone/README.md`](Backbone/README.md) | Orchestrator / Threat-Intel / Report layer — what lives where |
| [`Backbone/ARCHITECTURE.md`](Backbone/ARCHITECTURE.md) | Full orchestration flow, design rationale, contracts, case graph, file/class map |
| [`Modules/README.md`](Modules/README.md) | The module contract and how to plug in a new module |
| [`Modules/RAM/README.md`](Modules/RAM/README.md) | RAM module user guide (Volatility 3 pipeline) |
| [`Modules/RAM/Architecture.md`](Modules/RAM/Architecture.md) | RAM module internals: extraction → collection → analysis |
| [`Modules/RAM/ram-collector/README.md`](Modules/RAM/ram-collector/README.md) | The artifact-to-chunk collector, the internal tool used by the RAM module to extract data from the RAM image efficiently |
| [`Modules/Disk/README.md`](Modules/Disk/README.md) | Disk module user guide (mount → collect → agentic pipeline) |
| [`Modules/Disk/Architecture.md`](Modules/Disk/Architecture.md) | Disk module internals |
| [`auditing/README.md`](auditing/README.md) | Audit-tree layout, record schemas, worked examples |

---

## Getting started — fresh clone → incident report

Target environment: a clean **SIFT Workstation** (Ubuntu), this repo cloned, one RAM image, and one disk image (**currently, only Windows images are supported**). Total run time: ~50 min; disk mount+collect adds ~5–15 min and runs in parallel with RAM.

Input format requirements:

- **RAM image** — provide one Windows memory dump file. Common extensions are `.raw`, `.lime`, `.elf`, `.vmem`, and `.mem`; the extension is only a convention, because Volatility detects the memory format from the file contents.
- **Disk image** — provide one Windows disk image file inside `Modules/Disk/Disk_image/`. Supported extensions are `.E01`, `.Ex01`, `.dd`, `.raw`, `.img`, `.vmdk`, `.vhd`, and `.vhdx`. The disk module expects an NTFS Windows partition and the folder should contain exactly one image file.
- **Artifacts-only reruns** — if you already collected artifacts, you can omit `ram_image` to reuse `RAM_Artifacts/`, or omit `image_dir` to reuse `Disk_Artifacts/`.

### 0. Set a convenience variable

```bash
export AMAMA=$(pwd)          # run this from the repo root (the dir containing Backbone/ and Modules/)
ls "$AMAMA/Backbone" "$AMAMA/Modules"   # sanity check
```

### 1. System packages (disk mounting/parsing needs these)

```bash
sudo apt update
sudo apt install -y ewf-tools sleuthkit fuse ntfs-3g qemu-utils parted python3-pip git
```

### 2. Install Volatility 3 (for the RAM module)

```bash
sudo mkdir -p /home/MyTools && cd /home/MyTools
sudo git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3 && sudo python3 -m pip install -e . --break-system-packages
ls /home/MyTools/volatility3/vol.py      # note this path — you'll put it in the config
```

> The first Volatility run downloads Windows symbol tables (internet access required). The RAM module handles this by running one warm-up Volatility plugin first, which creates or downloads the cache before the parallel plugin workers start.

### 3. Install Python dependencies (system-wide so `sudo` also sees them)

```bash
# Backbone orchestrator (pulls anthropic, httpx, jsonschema, pyyaml)
python3 -m pip install -e "$AMAMA/Backbone" --break-system-packages

# RAM collector token accuracy (avoids oversized chunks)
python3 -m pip install tiktoken --break-system-packages

# Disk collector deps (registry/evtx/mft/pe parsers)
sudo python3 -m pip install -r "$AMAMA/Modules/Disk/requirements.txt" --break-system-packages
```

> Disk collection runs under `sudo`, so its deps must be installed for **root's** python — hence the `sudo pip` on the disk requirements.

### 4. API keys

```bash
export ANTHROPIC_API_KEY=<your-funded-anthropic-key>   # all LLM agents (RAM/disk/orchestrator/report)
export VT_API_KEY=<your-virustotal-key>                # ThreatIntel (ti) module
```

> Put these in `~/.bashrc` if you want them to persist.

### 5. Place your images

```bash
cp /path/to/your/memory.raw   "$AMAMA/Modules/RAM/RAM_image/"      # RAM: .raw / .lime / .elf / .vmem / .mem
cp /path/to/your/disk.E01     "$AMAMA/Modules/Disk/Disk_image/"    # Disk: .E01 / .Ex01 / .dd / .raw / .img / .vmdk / .vhd / .vhdx
```

### 6. Point the config at YOUR paths

Copy `Backbone/config/orchestrator.example.yaml` to `Backbone/config/orchestrator.yaml` and fill in your paths (replace every `<AMAMA>` with the absolute path from step 0 — `echo $AMAMA`; use **absolute** paths):

```yaml
case:
  max_rounds: 5
  max_queries_per_round: 30
  output_dir: "./output"

modules:
  - class: ram_module.RamModule
    path: ../../Modules/RAM/ram-agentic-architecture
    kwargs:
      use_llm: true
      scan_mode: fast                                                    # 'fast' (default) or 'full'
      ram_image: <AMAMA>/Modules/RAM/RAM_image/<your-memory-image>       # ← your RAM image
      vol_path: /home/MyTools/volatility3/vol.py                         # ← your vol.py (step 2)
      artifact_dir: <AMAMA>/Modules/RAM/RAM_Artifacts                    # ← created automatically

  - class: disk_module.DiskModule
    path: ../../Modules/Disk/disk-agentic-architecture
    kwargs:
      use_llm: true
      image_dir: <AMAMA>/Modules/Disk/Disk_image                         # ← your disk image dir; auto mount+collect
      collect_mode: fast                                                 # 'fast' (default) or 'full' (adds PE analysis)
      artifact_dir: <AMAMA>/Modules/Disk/Disk_Artifacts                  # ← collected here automatically (omit image_dir to reuse pre-collected)

  - class: backbone.threat_intel.ThreatIntelAgent   # no `path:` — it's in the backbone package
    kwargs: {}                                       # reads VT_API_KEY from the environment

report: {}
```

### 7. Run the orchestrator (end-to-end)

```bash
cd "$AMAMA/Backbone"          # IMPORTANT: run from Backbone/ (paths are relative to CWD)
python3 -m backbone run --case-id my-case-001 --config config/orchestrator.yaml
```

That command starts one full investigation named `my-case-001`:

1. **Backbone loads the config** and starts every configured module for that case.
2. **RAM and Disk scan in parallel.**
   - RAM extracts Volatility artifacts from the memory image, turns them into smaller chunks, then runs LLM-assisted triage and analyst validation on those chunks.
   - Disk mounts and collects Windows artifacts from the disk image, then runs its triage and analyst flow.
3. **Backbone merges both outputs into one case graph** containing entities, verdicts, evidence lines, and relationships found by the modules.
4. **Backbone routes follow-up questions** between modules when one module finds an entity another module can investigate better.
5. **Threat Intel enriches confirmed IOCs** through VirusTotal when configured.
6. **The report agent writes the final incident report** to `output/incident_report.md`.

When the run finishes, the CLI prints a summary line like `[backbone] case=… termination=… report=output/incident_report.md`.

### 8. Results

```bash
cat "$AMAMA/Backbone/output/incident_report.md"     # the narrative incident report
less "$AMAMA/Backbone/output/case_state.json"       # full entity/verdict graph + routing history
```

Per-module pipeline logs are written to `Modules/RAM/ram-agentic-architecture/output/ram.log` and `Modules/Disk/disk-agentic-architecture/output/disk.log`, and every run produces a full audit tree under `auditing/` (see [Auditing system](#auditing-system)).

---

## Troubleshooting

- **`Memory image not found`** → `ram_image` in the YAML doesn't match the file you copied in step 5.
- **`Volatility 3 not found`** → fix `vol_path` in the YAML, or `export VOL3_PATH=/home/MyTools/volatility3/vol.py`.
- **Disk: `No supported image found`** → the image isn't in `Modules/Disk/Disk_image/` or has an unsupported extension (`.e01/.ex01/.dd/.raw/.img/.vmdk/.vhd/.vhdx`).
- **Disk collector import errors under sudo** → you installed the disk deps for your user but not root; re-run step 3's `sudo pip … requirements.txt`.
- **Disk auto-collect didn't run / `[scan] WARN: … falling back to existing artifacts`** → mount/collect is best-effort: on a `sudo -n` failure (no passwordless sudo) or a mount error it logs a WARN and falls back to whatever is already in `Disk_Artifacts/`. Fix passwordless sudo (or run `sudo -E python3 -m backbone run …`), and check `image_dir` points at the dir containing your disk image.
- **Re-run disk without re-collecting** (faster iteration) → remove the `image_dir:` line from the disk kwargs; the disk module reuses the existing `Disk_Artifacts/`.
- **Re-run RAM without re-extracting** (faster iteration) → remove the `ram_image:` line from the YAML; the RAM module re-analyses the existing `RAM_Artifacts/`. Add `reuse_analysis: true` to its kwargs to also skip the LLM analysis and reuse the previous verdicts.
- **`HTTP 400 … reached your specified API usage limits`** → the Anthropic key is over budget; use a funded key.
- **`HTTP 429` lines** → normal transient rate-limiting; the pipeline backs off and retries (RAM/disk also share a cross-process API lock so they don't hit the API simultaneously).
- **Mount left over after a crash** → `sudo python3 Modules/Disk/disk-image-mounter/mount_image.py --umount`.

---

## Auditing system

Every pipeline run automatically produces a self-contained audit tree under `auditing/{case_id}/{YYYYMMDD-HHMMSS}/` (anchored to the repo root; one new timestamped folder per run). It captures the full agent communication and tool execution sequence:

- **Structured logs** — every LLM call by every agent, and every threat intelligence lookup, appends one JSONL record (`agent_calls.jsonl`, `orchestrator_calls.jsonl`, `queries.jsonl`) with timestamp, model, exact token usage, latency, and links to the input/output files of that call. Sorting the records by timestamp replays the entire run.
- **Agent-to-agent messages** — modules talk through the orchestrator's case graph; `case_state.json` records, per entity, who found it, who was asked about it, and what each agent answered, with every hop timestamped in the call logs.
- **Full execution sequence & cost** — `run_summary.json` is the single entry-point: an ordered, timestamped list of every phase (scans, enrichment, routing rounds, report) plus per-component token counts and prompt/model provenance hashes.
- **Iteration-over-iteration traces** — the tree shows how the agents' approach changed: Agent 2 (analyst) re-examines and can reject Agent 1 (triage) findings with a written justification, and the orchestrator's per-round query counts shrink down to `convergence`.

See [`auditing/README.md`](auditing/README.md) for the full directory layout, record schemas, and worked examples — including a triage finding rejected by the analyst, and a round-by-round convergence trace.

The audit trees are runtime output and are git-ignored (only the README is committed).

## License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

This project is licensed under the [MIT License](LICENSE).  
Copyright (c) 2026 Abdallah Zerkani on behalf of AMAMA team.
