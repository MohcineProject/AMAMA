# How to Use the RAM Forensic Pipeline

---

## Repository Reorganization — May 2026

> **Read this first if you are a new agent picking up this work.**
>
> All RAM-module files previously scattered at the repository root have been consolidated under `Modules/RAM/`. The table below is the authoritative record of every move made. Nothing was deleted; only paths changed. One line in one config file was updated to reflect the rename.

### File and Directory Moves (root → Modules/RAM/)

| What | Old path (repo root) | New path |
|---|---|---|
| User guide (this file) | `How_to_use_it.md` | `Modules/RAM/How_to_use_it.md` |
| Technical deep-dive | `Detailed_explanation.md` | `Modules/RAM/Detailed_explanation.md` |
| High-level overview | `version2.md` | `Modules/RAM/version2.md` |
| Volatility technique guide (domains) | `domain_investigation.txt` | `Modules/RAM/domain_investigation.txt` |
| Volatility technique guide (registry) | `registry_persistence_detection.txt` | `Modules/RAM/registry_persistence_detection.txt` |
| 67 Volatility 3 plugin outputs | `Grep_input/` (directory) | `Modules/RAM/RAM_Artifacts/` (renamed) |
| FIND_EVIL collector chunks (pipeline input) | `INPUT/` (directory) | `Modules/RAM/INPUT/` |
| DFIR-Collector package | `DFIR-Collector/` (directory) | `Modules/RAM/ram-collector/` (renamed) |
| Agentic pipeline | `agentic-architecture/` (directory) | `Modules/RAM/ram-agentic-architecture/` (renamed) |

The /models directory was removed, remove it as well on github!

### Code Change Made (one line)

**File:** `Modules/RAM/ram-agentic-architecture/config.json`, line 3

```diff
- "grep_input_dir": "../Grep_input",
+ "grep_input_dir": "../RAM_Artifacts",
```

This path is resolved at runtime relative to `ram-agentic-architecture/`, so `../RAM_Artifacts` correctly points to `Modules/RAM/RAM_Artifacts/`. The `input_dir` value (`../INPUT`) was already correct and required no change.

---

## Committing to the Orchestrator Branch

> **Instructions for the agent performing the git commit.**

The working directory is `/home/sansforensics/Documents/AMAMA/`. There is currently **no `.git` directory** — this is not yet a local git repository. You must initialise it, wire up the GitHub remote, and push the current on-disk state as-is to the `Orchestrator` branch.

The local file tree already reflects the final desired state. Do not move or rename anything — just stage and push what is there.

### Steps

```bash
cd /home/sansforensics/Documents/AMAMA

# 1. Initialise the local repo
git init

# 2. Set the remote (ask the user for the URL if unknown)
git remote add origin <GITHUB_REMOTE_URL>

# 3. Fetch existing remote state so git knows about the branch
git fetch origin

# 4. Check out the Orchestrator branch (creates it locally tracking the remote)
git checkout -b Orchestrator origin/Orchestrator
# If the branch does not yet exist on the remote, use instead:
#   git checkout -b Orchestrator

# 5. Stage the new Modules/RAM/ tree
git add Modules/RAM/

# 6. Stage the removal of the old root-level paths that were moved
#    (git needs to know the old locations are gone)
git rm --cached How_to_use_it.md
git rm --cached Detailed_explanation.md
git rm --cached version2.md
git rm --cached domain_investigation.txt
git rm --cached registry_persistence_detection.txt
git rm --cached evil_windows.elf
git rm -r --cached Grep_input/
git rm -r --cached INPUT/
git rm -r --cached DFIR-Collector/
git rm -r --cached agentic-architecture/

# 7. Verify the staging area looks right before committing
git status
git diff --cached --stat

# 8. Commit
git commit -m "Reorganize RAM module into Modules/RAM/

All RAM-module files moved from repo root into Modules/RAM/ following the
same layered structure as Modules/Disk/:

  evil_windows.elf          → Modules/RAM/RAM_image/
  Grep_input/               → Modules/RAM/RAM_Artifacts/   (renamed)
  INPUT/                    → Modules/RAM/INPUT/
  DFIR-Collector/           → Modules/RAM/ram-collector/   (renamed)
  agentic-architecture/     → Modules/RAM/ram-agentic-architecture/ (renamed)
  *.md / *.txt docs         → Modules/RAM/

One config line updated: ram-agentic-architecture/config.json
  grep_input_dir: '../Grep_input' → '../RAM_Artifacts'

Pipeline verified end-to-end with --no-llm after the move."

# 9. Push to remote
git push -u origin Orchestrator
```

### What the remote branch should contain after the push

```
Modules/RAM/
├── How_to_use_it.md
├── Detailed_explanation.md
├── version2.md
├── domain_investigation.txt
├── registry_persistence_detection.txt
│
├── RAM_image/
││
├── RAM_Artifacts/                         ← 67 Volatility 3 plugin outputs
│   ├── pslist.txt
│   ├── pstree.txt
│   ├── psscan.txt
│   ├── cmdline.txt
│   ├── dlllist.txt
│   ├── malfind.txt
│   ├── malware_*.txt                      ← 13 malware-detection plugin outputs
│   ├── registry_*.txt                     ← 12 registry plugin outputs
│   └── ...  (67 files total)
│
├── INPUT/                                 ← FIND_EVIL collector chunks (pipeline input)
│   ├── chunk_001.txt
│   ├── chunk_002.txt
│   └── ...  (up to chunk_009.txt)
│
├── ram-collector/                         ← DFIR-Collector package
│   ├── README.md
│   ├── pyproject.toml
│   └── collector/
│       ├── __main__.py
│       ├── vol3_runner.py
│       ├── chunker.py
│       ├── exclusions.py
│       ├── format_line.py
│       ├── merge.py
│       └── tree.py
│
└── ram-agentic-architecture/              ← 4-stage pipeline
    ├── config.json                        ← grep_input_dir set to ../RAM_Artifacts
    ├── llm_config.json
    ├── ARCHITECTURE.md
    ├── README.md
    ├── scripts/
    │   ├── run_pipeline.py                ← main entry point
    │   ├── triage_agent.py                ← Agent 1: process triage
    │   ├── pivot_grep.py                  ← deterministic grep stage
    │   ├── pivot_analyst.py               ← Agent 2: evidence validation
    │   ├── report_agent.py                ← Agent 3: report writer
    │   ├── llm_client.py
    │   ├── utils.py
    │   └── whitelist.txt
    ├── prompts/
    │   ├── agent1_triage.md
    │   ├── agent2_pivot.md
    │   └── agent3_report.md
    ├── schemas/
    ├── logs/
    └── output/                            ← generated at runtime
        ├── chunk_001/
        │   ├── triage.txt
        │   ├── pivot.txt
        │   └── analyst.txt
        ├── ...
        ├── aggregated_analyst.txt
        └── report.md
```

---

## What This Tool Does

The RAM forensic pipeline takes a Windows memory image, extracts and chunks the process forest via the DFIR-Collector, then runs a four-stage analysis:

1. **Agent 1 (triage)** — flags suspicious processes per chunk
2. **Grep pivot** — deterministic search of all 67 Volatility artifacts for corroborating evidence
3. **Agent 2 (analyst)** — issues CONFIRMED / INCONCLUSIVE / REJECTED verdicts
4. **Agent 3 (report)** — synthesises a structured incident report

**Input**: `Modules/RAM/INPUT/` (collector chunks) + `Modules/RAM/RAM_Artifacts/` (Volatility plugin outputs)  
**Output**: Markdown incident report at `Modules/RAM/ram-agentic-architecture/output/report.md`

---

## Prerequisites

- Python 3.8 or later
- `pip install requests`
- An API key for an LLM provider (see Step 1)
- Volatility 3 at `/home/MyTools/volatility/volatility3/vol.py` (for re-collection; pre-collected artifacts already present)

---

## Module Structure

```
Modules/RAM/
├── How_to_use_it.md              ← this file
├── Detailed_explanation.md       ← technical deep-dive
├── version2.md                   ← high-level design overview
├── domain_investigation.txt      ← Volatility technique: browser domain recovery
├── registry_persistence_detection.txt  ← Volatility technique: registry persistence
│
├── RAM_image/                    ← input layer
│   └── evil_windows.elf          ← 8.2 GB Windows RAM dump (test image)
│
├── RAM_Artifacts/                ← Volatility 3 plugin outputs (67 files)
│   ├── pslist.txt, pstree.txt, psscan.txt
│   ├── cmdline.txt, dlllist.txt, netscan.txt, netstat.txt
│   ├── malfind.txt, malware_*.txt
│   ├── registry_*.txt
│   └── ...
│
├── INPUT/                        ← FIND_EVIL collector chunks
│   ├── chunk_001.txt
│   └── ...
│
├── ram-collector/                ← DFIR-Collector (chunks the RAM image for the pipeline)
│   └── collector/
│
└── ram-agentic-architecture/     ← 4-stage pipeline
    ├── config.json
    ├── llm_config.json
    ├── scripts/
    ├── prompts/
    ├── schemas/
    └── output/
```

---

## Step 1 — Configure the LLM API Key

Open `Modules/RAM/ram-agentic-architecture/llm_config.json` and set your credentials:

```json
{
  "provider": "openrouter",
  "api_base": "https://openrouter.ai/api/v1/chat/completions",
  "model": "meta-llama/llama-3.3-70b-instruct:free",
  "api_key": "sk-or-v1-YOUR-KEY-HERE",
  "api_key_env": "OPENROUTER_API_KEY",
  "temperature": 0.2,
  "max_tokens": 2000,
  "max_retries": 5,
  "verify_ssl": false
}
```

**Option A — OpenRouter (recommended for getting started)**
Free tier, multiple models. Sign up at openrouter.ai. Note: some free models require a payment method on file even with no spend. If you get "No endpoints found" errors, check account settings.

**Option B — Anthropic API**
Set `provider` to `anthropic`:
```json
{
  "provider": "anthropic",
  "api_base": "https://api.anthropic.com/v1/messages",
  "model": "claude-opus-4-7",
  "api_key": "sk-ant-YOUR-KEY-HERE",
  "api_key_env": "ANTHROPIC_API_KEY"
}
```

**Option C — Environment variable**
Set `OPENROUTER_API_KEY` (or whichever name is in `api_key_env`) and leave `api_key` blank.

---

## Step 2 — (Re-)Collect from the RAM Image

Skip this step if `INPUT/` already contains `chunk_*.txt` files. Run it to regenerate the chunks from a fresh Volatility sweep or when the image changes.

### Option A — From pre-computed Volatility files (fast, <1 min)

Use this when `RAM_Artifacts/` is already populated:

```bash
cd Modules/RAM/ram-collector
python3 -m collector \
  --from-folder ../RAM_Artifacts \
  --output-dir ../INPUT \
  --log-level INFO
```

### Option B — Directly from the RAM image (~30–60 min for 8.2 GB)

Use this to re-run Volatility internally (the collector shells out to `vol.py`). Add `--no-handles` to skip the slowest plugin and reduce chunk size by ~70%:

```bash
cd Modules/RAM/ram-collector
python3 -m collector \
  --image ../RAM_image/evil_windows.elf \
  --output-dir ../INPUT \
  --no-handles \
  --log-level INFO
```

> **Note:** `--image` mode runs the 9 core Volatility plugins internally but does **not** write the TSV outputs to `RAM_Artifacts/`. If you also need to refresh `RAM_Artifacts/` (for the pivot_grep stage), run Volatility separately for each plugin and save outputs there.

The collector applies 21 exclusion rules for known-benign Windows system processes (System, smss.exe, csrss.exe, svchost.exe with `-k`, etc.) before chunking. What remains are the processes worth triaging.

---

## Step 3 — Run the Pipeline

```bash
cd Modules/RAM/ram-agentic-architecture
python scripts/run_pipeline.py --use-llm
```

The pipeline automatically:
1. Discovers all `chunk_*.txt` files in `../INPUT/`
2. Per chunk: runs Agent 1 (triage) → grep pivot → Agent 2 (analyst)
3. Aggregates all per-chunk analyst outputs
4. Runs Agent 3 to generate the final report

### Command-Line Flags

| Flag | Description |
|---|---|
| `--use-llm` | Enable LLM for Agents 1, 2, and 3 |
| `--no-llm` | Disable LLM — rule-based fallback + structured template (no API key needed) |
| `--config PATH` | Path to config.json (default: `ram-agentic-architecture/config.json`) |
| `--llm-config PATH` | Path to llm_config.json (default: `ram-agentic-architecture/llm_config.json`) |
| `--out DIR` | Root output directory (default: `ram-agentic-architecture/output/`) |

---

## Step 4 — View the Outputs

```
ram-agentic-architecture/output/
├── chunk_001/
│   ├── triage.txt       ← Agent 1: suspicious processes with severity + reason
│   ├── pivot.txt        ← Grep pivot: verbatim evidence lines from RAM_Artifacts/
│   └── analyst.txt      ← Agent 2: CONFIRMED / INCONCLUSIVE / REJECTED verdicts
├── chunk_002/
│   └── ...
├── aggregated_analyst.txt   ← all analyst.txt files concatenated
└── report.md                ← final incident report (the main analyst-facing output)
```

### Per-chunk intermediates explained

| File | Stage | What it contains |
|---|---|---|
| `triage.txt` | Agent 1 | `[PROCESS]` blocks: pid, ppid, image, cmdline, severity, reasons |
| `pivot.txt` | Grep stage | Verbatim lines from `RAM_Artifacts/` files, grouped by PID, with source filename and line number |
| `analyst.txt` | Agent 2 | `[CONFIRMED]` / `[INCONCLUSIVE]` / `[REJECTED]` blocks with justification and key evidence citations |

**The most important file is `report.md`** — the others are the intermediate audit trail.

---

## Step 5 — Interpret the Report

The report has six sections: Executive Summary, Attack Timeline, MITRE ATT&CK Mapping, Indicators of Compromise (IOCs), Recommendations, and Confidence Assessment.

### Verdict labels

| Verdict | Meaning |
|---|---|
| **CONFIRMED** | Multiple independent artifact types corroborate the finding |
| **INCONCLUSIVE** | Signal present but insufficient for confirmation — warrants manual review |
| **REJECTED** | Evidence shows legitimate behavior — not shown in report body |

The pipeline is conservative: it prefers a missed threat over a false alarm.

---

## Tuning the Pipeline

Edit `Modules/RAM/ram-agentic-architecture/config.json`:

| Parameter | Default | Effect |
|---|---|---|
| `max_lines_per_file` | 120 | Max grep lines per artifact file per PID |
| `max_total_lines_per_target` | 400 | Max total grep lines per PID across all files |
| `pid_files` | 20 files listed | Volatility files searched by PID (word-boundary match) |
| `path_files` | 25 files listed | Volatility files searched by path/image name |
| `suspicious_keywords` | list | Command-line patterns triggering rule-based scoring |
| `suspicious_dirs` | list | Directory patterns triggering elevated scoring |

---

## Troubleshooting

**No chunks found**
Ensure `Modules/RAM/INPUT/` contains files matching `chunk_*.txt`. The `input_dir` in `config.json` resolves relative to `ram-agentic-architecture/` — the default `../INPUT` is correct for the current layout.

**Missing Volatility artifact files**
The grep stage skips absent files silently. Analysis quality degrades but the pipeline completes. `grep_input_dir` in `config.json` controls where it looks — currently set to `../RAM_Artifacts`.

**Agent 2 marks everything INCONCLUSIVE**
LLM call failed. The pipeline degrades gracefully. Check `llm_config.json` credentials and network connectivity.

**SSL errors**
`"verify_ssl": false` in `llm_config.json` disables SSL verification for TLS-inspection proxies. If errors persist, check corporate proxy settings.

**handles.txt / getsids.txt missing (collector warning)**
These are optional Volatility plugins. The collector skips them and continues. To add them, run `windows.handles.Handles` and `windows.getsids.GetSIDs` via Vol3 and save outputs to `RAM_Artifacts/`.
