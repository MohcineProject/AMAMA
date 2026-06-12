# AMAMA — Multi-Agent DFIR Triage

AMAMA takes a raw **memory image** and a raw **disk image** and produces an evidence-traceable `incident_report.md`. Two forensic modules — **RAM** (Volatility 3) and **Disk** (image mount + Windows artifact collection) — each run a deterministic-extraction + LLM-agent pipeline. The **Backbone orchestrator** runs them in parallel, enriches confirmed IOCs via **VirusTotal**, routes follow-up entity queries between modules, and writes the final report. Deterministic scripts sandwich the reasoning agents, keeping token usage low and every claim traceable to verbatim artifact evidence.

## Project layout

```
AMAMA/
  Backbone/         orchestrator, threat-intel + report agents, contracts/schemas
  Modules/
    RAM/            memory forensics module (Volatility 3)
    Disk/           disk forensics module (mount, MFT, registry, event logs, …)
  frontend/         React + TypeScript UI (Vite + Tailwind + shadcn/ui)
  backend_dummy/    FastAPI mock backend for frontend development
```

Each part has its own README. `Modules/README.md` explains the module contract and how to plug in a new module — any module declared in the orchestrator config is fully integrated automatically.

---

## Getting started — fresh clone → incident report

Target environment: a clean **SIFT Workstation** (Ubuntu), this repo cloned, one RAM image and one disk image. Total run time: ~50 min (RAM Volatility + per-chunk LLM dominate on large images); disk mount+collect adds ~5–15 min and runs in parallel with RAM.

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

> First Volatility run downloads Windows symbol tables (needs internet). The pipeline warms the symbol cache once before parallel plugins, so this is handled.

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
cp /path/to/your/memory.raw   "$AMAMA/Modules/RAM/RAM_image/"      # .raw / .lime / .elf / .vmem
cp /path/to/your/disk.E01     "$AMAMA/Modules/Disk/Disk_image/"    # .E01 / .Ex01 / .dd / .raw / .img / .vmdk / .vhd / .vhdx
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

This runs RAM (Volatility extraction → collector → per-chunk LLM triage/pivot/analyst) and disk (triage → pivot → analyst) in parallel, then the orchestrator routes follow-up queries between modules + VirusTotal, and writes the report. It prints a final `[backbone] case=… termination=… report=output/incident_report.md` line.

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

## Frontend (dev preview)

The UI currently runs against the mock backend while the real pipeline is being wired in. Two terminals:

```bash
# Terminal 1 — mock backend
cd backend_dummy
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Terminal 2 — frontend
cd frontend
npm install
npm run dev   # http://localhost:5173
```

Vite proxies `/api/*` and `/health` to <http://localhost:8000>, so the frontend connects to the backend with no extra config. See `frontend/README.md` and `backend_dummy/README.md` for details.

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
