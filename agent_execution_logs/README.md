# Agent Execution Logs

This folder gathers the complete, self-contained audit trees for every AMAMA run referenced in
our DFIR deliverables, with one subtree per dataset. Each tree is exactly what the pipeline emits
at runtime (the same layout documented in auditing/), copied here so the runs are committed
alongside the code and reproducible by a reviewer.

These logs are the evidence behind the two companion documents. The dataset documentation
explains what each image is and what was found, and the accuracy report gives a critical,
metric-based assessment of those findings.

## Datasets in this folder

| # | Dataset | Modules run | Subfolder |
|---|---------|-------------|-----------|
| 1 | ROCBA workstation (disk + RAM) | ram · disk · ti | `ROCBA/` |
| 2 | Clean Windows 11 (RAM only) | ram · ti | `Windows_11_c/20260615-083921/` |
| 3 | NimPlantv2 process-injection (RAM only) | ram · ti | `daniyyell_dataset_4/20260614-225130/` |
| 4 | QuasarRAT infection (RAM only) | ram · ti | `Windows_11_VM_e/20260615-080536/` |

Runs are keyed by `{case_id}/{YYYYMMDD-HHMMSS}/` so re-runs of the same case accumulate
side-by-side without overwriting. (The ROCBA tree is stored directly under its case folder.)

## Layout of a single run

```
<case>/<timestamp>/
├── run_summary.json          ← start here: provenance, models, cost, execution sequence
├── backbone/
│   ├── incident_report.md    ← the final report (ends with the Evidence Traceability Index)
│   ├── traceability.json     ← every finding mapped to the tool execution that produced it
│   ├── case_state.json       ← final case graph (entities, verdicts, routing)
│   ├── orchestrator_calls.jsonl
│   └── report_call.jsonl
├── ram/                      ← RAM module: agent_calls.jsonl, scan_result.json, per-chunk analysis
├── disk/                     ← Disk module (ROCBA only): triage/pivot/analyst stages, mft_audit.jsonl
└── threat_intel/
    └── queries.jsonl         ← one record per VirusTotal lookup
```

## How to trace any claim back to its source

Every statement in an `incident_report.md` is traceable end to end:

1. Find the entity in the report and read its `finding_id` / `query_id` in the Evidence
   Traceability Index (Section 7 of the report).
2. That row gives the evidence locator (`source_file:line`) and the `produced_by` agent and
   `call_id`.
3. Search for that `call_id` in the named JSONL log (for example `ram/agent_calls.jsonl`) to
   reach the exact agent call, including its input and output files, timestamp, and token usage.

The full per-line evidence (every `source_file:line` plus verbatim `content`) lives in
`traceability.json` inside each run's `backbone/` folder. The complete record schemas and worked
examples are documented in auditing/.
