# Auditing — agent execution logs

Every pipeline run automatically writes a self-contained audit tree under this folder:

```
auditing/{case_id}/{YYYYMMDD-HHMMSS}/
```

The folder is always anchored to the repo root regardless of the working directory. A new timestamped subfolder is created on each run, so multiple runs of the same case accumulate side-by-side without overwriting each other. The trees are **runtime output and are git-ignored** — only this README is committed. All log excerpts below are illustrative examples in the exact format the pipeline produces.

The audit tree answers four questions about any run:

1. **What did each agent do, and what did it cost?** → structured JSONL call logs with timestamps and token usage ([Structured call logs](#structured-call-logs))
2. **How did the agents talk to each other?** → the case graph and routing records ([Agent-to-agent communication](#agent-to-agent-communication))
3. **How did the investigation change over iterations?** → per-round traces and inter-agent rejections ([Iteration-over-iteration traces](#iteration-over-iteration-traces--how-the-agents-approach-changes))
4. **Where did this claim in the report come from?** → the traceability walk ([Traceability](#traceability))

---

## Directory structure

```
auditing/
└── {case_id}/
    └── {YYYYMMDD-HHMMSS}/
        ├── run_summary.json               ← single entry-point for the whole run
        │
        ├── backbone/
        │   ├── orchestrator_calls.jsonl   ← one record per orchestrator LLM call
        │   ├── report_call.jsonl          ← one record for the report LLM call
        │   ├── case_state.json            ← copy of the final case graph
        │   └── incident_report.md         ← copy of the generated report
        │
        ├── threat_intel/
        │   └── queries.jsonl              ← one record per VirusTotal lookup
        │
        ├── ram/
        │   ├── agent_calls.jsonl          ← one record per RAM LLM call
        │   ├── 01_chunks/                 ← memory text chunks fed to triage agent
        │   ├── 02_per_chunk_analysis/     ← triage / pivot / analyst output per chunk
        │   │   ├── chunk_001/
        │   │   │   ├── triage.txt
        │   │   │   ├── pivot.txt
        │   │   │   └── analyst.txt
        │   │   └── ...
        │   ├── aggregated_analyst.txt
        │   └── scan_result.json
        │
        └── disk/
            ├── agent_calls.jsonl          ← one record per Disk LLM call
            ├── 01_preprocess/             ← TRIAGE_INPUT_*.txt fed to triage agent
            ├── 02_triage/                 ← triage_persistence/events/mft + combined
            ├── 03_pivot/                  ← pivot.txt (grep evidence)
            ├── 04_analyst/                ← analyst.txt (Agent 2 output)
            ├── mft_audit.jsonl            ← filtered MFT entries
            └── scan_result.json
```

The numbered folders (`01_…`, `02_…`, …) mirror the pipeline order inside each module, so reading a module's folder top-to-bottom replays its execution: what was fed in, what Agent 1 said, what evidence was gathered, and what Agent 2 concluded.

`ram/01_chunks/` and the `agent_calls.jsonl` files for RAM and Disk are only populated when the full LLM pipeline runs (i.e. a live memory image / disk image is provided). When reusing cached analysis (`reuse_analysis: true` or no `ram_image`), the per-chunk artifacts are still copied but no new LLM call records are written.

---

## `run_summary.json`

The single entry-point for a run. Key fields:

| Field | Description |
|---|---|
| `run_id` | Matches the timestamped folder name |
| `termination_reason` | `convergence` or `max_rounds_reached` |
| `execution_sequence` | Ordered list of every phase with timestamps — initial scans, TI enrichment, routing rounds, report |
| `cost_summary` | Total and per-component token counts and LLM call counts |
| `provenance` | Model ID and SHA-256 of the system prompt for orchestrator and report agents |
| `audit_files` | Relative paths to all JSONL logs in this run |
| `module_artifacts` | Relative paths to all copied pipeline artifacts |

`cost_summary` aggregates what the JSONL logs record per call, so total spend is verifiable bottom-up:

```json
"cost_summary": {
  "total": { "llm_calls": 38, "tokens_in": 412055, "tokens_out": 31544 },
  "by_component": {
    "backbone/orchestrator": { "llm_calls": 2,  "tokens_in": 4512,   "tokens_out": 154 },
    "backbone/report":       { "llm_calls": 1,  "tokens_in": 42924,  "tokens_out": 11016 },
    "modules":               { "llm_calls": 35, "tokens_in": 364619, "tokens_out": 20374 }
  }
}
```

---

## Structured call logs

Every LLM call (across all agents) and every VirusTotal lookup appends one JSON line to the relevant `*.jsonl` file. One schema everywhere:

| Field | Meaning |
|---|---|
| `call_id` | UUID v4, unique per call |
| `timestamp` | UTC ISO-8601, when the call started |
| `agent_name` | e.g. `backbone/orchestrator`, `ram/triage_agent`, `disk/pivot_analyst`, `threat_intel/vt_lookup` |
| `model` | model ID, or `"virustotal-api"` for TI lookups |
| `tokens_in` / `tokens_out` | exact token usage for the call (0 for TI) |
| `latency_ms` | wall-clock duration |
| `input_files` / `output_files` | paths **relative to the run folder** — what the agent read and what it wrote |
| `query_id` / `entity` / `verdict` | set on routed entity queries and TI lookups |
| `error` | non-null if the call failed |

Three example records (orchestrator decision, module agent call, TI lookup):

```json
{"call_id": "9480e24f-526b-4ddf-af81-d6e9bedf0a90", "timestamp": "2026-06-09T08:01:52Z", "agent_name": "backbone/orchestrator", "model": "claude-haiku-4-5-20251001", "tokens_in": 2249, "tokens_out": 145, "latency_ms": 2504, "input_files": ["backbone/case_state.json"], "output_files": [], "query_id": null, "entity": null, "verdict": null, "error": null}
{"call_id": "1f6b8c02-7d34-4b1a-9e55-3a0c9d2f8e41", "timestamp": "2026-06-09T08:00:11Z", "agent_name": "disk/triage_agent", "model": "claude-sonnet-4-6", "tokens_in": 18342, "tokens_out": 1207, "latency_ms": 14873, "input_files": ["disk/01_preprocess/TRIAGE_INPUT_PERSISTENCE.txt"], "output_files": ["disk/02_triage/triage_persistence.txt"], "query_id": null, "entity": null, "verdict": null, "error": null}
{"call_id": "d001e5af-41a6-4950-ae8c-876d5da7c124", "timestamp": "2026-06-09T08:02:03Z", "agent_name": "threat_intel/vt_lookup", "model": "virustotal-api", "tokens_in": 0, "tokens_out": 0, "latency_ms": 768, "input_files": [], "output_files": [], "query_id": "9c0637f4-2866-45cd-81d5-3391a6a744d8", "entity": {"type": "ip", "value": "203.0.113.45"}, "verdict": "NOT_FOUND", "error": null}
```

Because each record links the call to its exact `input_files` and `output_files` inside the run folder, the JSONL logs double as the **tool-execution sequence**: sorting all records by `timestamp` reconstructs the full run, and every prompt input and agent output is preserved on disk next to the record.

---

## Agent-to-agent communication

Agents never talk to each other directly — every message goes through the orchestrator's **case graph**, and every hop is recorded:

1. **Module → backbone.** Each module's scan ends in a `scan_result.json`: structured findings with verdict (`CONFIRMED` / `INCONCLUSIVE` / `REJECTED`), severity, MITRE techniques, and verbatim evidence lines. The backbone ingests these into the graph.
2. **Backbone → modules / TI.** Each routing round, the orchestrator LLM reads the current graph (`orchestrator_calls.jsonl` records that call) and dispatches entity queries to other modules and VirusTotal. Each dispatched query gets a `query_id`.
3. **Modules / TI → backbone.** Answers come back as verdicts attached to that `query_id` — TI answers in `threat_intel/queries.jsonl`, module answers in their `agent_calls.jsonl`.
4. **Backbone → report.** The final graph state is handed to the report agent (`report_call.jsonl`).

The message history is materialized in `backbone/case_state.json`: every entity node carries `first_seen_module`, `queried_modules`, and `verdicts_received` — i.e. *who found it, who was asked about it, and what each agent answered*:

```json
"ip:203.0.113.45": {
  "type": "ip",
  "value": "203.0.113.45",
  "first_seen_module": "disk",
  "queried_modules": ["disk", "ti"],
  "verdicts_received": [
    { "module": "disk", "verdict": "CONFIRMED", "severity": "HIGH" },
    { "module": "ti",   "verdict": "NOT_FOUND", "severity": null }
  ]
}
```

Timestamps for every hop live in the corresponding JSONL records (matched via `query_id`), and the round-level summary lives in `case_state.json`'s `rounds` array and `run_summary.json`'s `execution_sequence`.

---

## Iteration-over-iteration traces — how the agents' approach changes

The audit tree doesn't just record *what* the agents concluded — it records how conclusions **changed between pipeline stages and between rounds**. Two worked examples:

### Example A — Agent 1's finding is rejected by Agent 2

Inside each module, Agent 1 (triage) casts a wide net and Agent 2 (pivot analyst) re-examines every finding against grep-collected evidence. Agent 2 can — and does — overturn Agent 1. The full exchange is preserved in the disk module's numbered folders.

**Step 1 — Agent 1 flags it** (`disk/02_triage/triage_combined.txt`): an executable running from a temp folder looks like classic malware staging, so triage raises it at HIGH severity:

```
[FINDING]
triage_source: persistence
type:       execution
key:        C:\Users\jdoe\AppData\Local\Temp\GUMF3B9.tmp\GoogleUpdateSetup.exe
severity:   HIGH
reasons:    execution:binary_run_from_temp_directory|staging:tmp_folder_with_random_suffix
source:     registry_shimcache.txt
```

**Step 2 — deterministic evidence gathering** (`disk/03_pivot/pivot.txt`): the pivot script greps every collected artifact for the finding's key and dumps the verbatim hits — MFT entries, shimcache rows, prefetch records — under a `=== FINDING 5 ===` header.

**Step 3 — Agent 2 rejects it** (`disk/04_analyst/analyst.txt`): reading the pivot evidence, the analyst recognizes the legitimate pattern and overturns the finding, with its reasoning recorded verbatim:

```
[REJECTED]
----------------------------------------------------------------
Finding:    5
Type:       execution
Key:        C:\Users\jdoe\AppData\Local\Temp\GUMF3B9.tmp\GoogleUpdateSetup.exe

Legitimate explanation:
  The GUM*.tmp subfolder naming pattern is the standard Google Update
  installer drop mechanism: the framework extracts a versioned setup binary
  into a temporary GUID-named folder before running it. The MFT confirms a
  legitimate installed copy under "Program Files (x86)\Google\Update\", and
  the companion GoogleUpdate.exe in the same temp folder (shimcache) is
  consistent with a normal self-update sequence.
----------------------------------------------------------------
```

The rejection is then counted in `disk/scan_result.json` (`"counts": {"confirmed": …, "inconclusive": …, "rejected": …}`), and rejected findings are excluded from what the module reports to the backbone — so the audit tree shows both the initial hypothesis and exactly why it was dropped.

### Example B — the orchestrator narrows round over round

At the cross-module level, the orchestrator re-reads the updated case graph at the start of every routing round. As verdicts come back, fewer entities remain worth querying, so the query set shrinks until the orchestrator decides nothing new can be learned. `run_summary.json`'s `execution_sequence` captures this trajectory:

```json
"execution_sequence": [
  { "step": 1, "phase": "initial_scan", "module": "ram",  "started_at": "2026-06-09T07:59:26Z", "completed_at": "2026-06-09T08:27:41Z" },
  { "step": 2, "phase": "initial_scan", "module": "disk", "started_at": "2026-06-09T07:59:26Z", "completed_at": "2026-06-09T08:14:02Z" },
  { "step": 3, "round": 0, "phase": "confirmed_ioc_enrichment", "queries_dispatched": 8, "new_entities_added": 0 },
  { "step": 4, "round": 1, "queries_dispatched": 2, "new_entities_added": 0 },
  { "step": 5, "phase": "report", "completed_at": "2026-06-09T08:31:55Z" }
],
"termination_reason": "convergence"
```

Reading the trace: round 0 enriched all 8 confirmed IOCs via VirusTotal; with those verdicts in the graph, the orchestrator's next call (visible in `orchestrator_calls.jsonl`) dispatched only 2 follow-up queries; and since they added no new entities, it declared **convergence** instead of burning the remaining rounds. Each round's LLM decision, the queries it produced, and the verdicts that came back are all individually logged, so the strategy shift between rounds is reconstructible call by call.

---

## Traceability

To trace a finding in `incident_report.md` back to its source:

1. Find the entity value in `backbone/case_state.json` → note its `query_id`
2. `grep <query_id>` in the relevant `agent_calls.jsonl` → get `input_files`
3. The `input_files` paths resolve directly within the audit folder

Provenance fields in `run_summary.json` (model IDs + SHA-256 of each system prompt) pin down exactly which agent configuration produced the run.
