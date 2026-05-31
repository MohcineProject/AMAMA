# COMPLETE_ARCHITECTURE — Multi-Module Forensic Agent

This directory is the **single source of truth** for the multi-module forensic agent architecture. It is self-contained and meant to be droppable into any module repo (RAM, disk, network) or the orchestrator repo, so each team can read what they need without cross-referencing the others.

## What this system is

Three forensic modules — **RAM**, **disk**, **network** — each running their own pipelines on their own artifacts, coordinated by an **orchestrator** that drives an iterative correlation loop. A **threat intelligence** service enriches findings with external IOC sources (VirusTotal, AbuseIPDB, etc.). The orchestrator pivots back into modules with targeted entity queries until the investigation converges, then produces a single final report.

```
   ┌───── Orchestrator (loop driver, case state) ─────┐
   │           │           │           │              │
   ▼           ▼           ▼           ▼              ▼
  RAM        Disk      Network     Threat Intel    Final Report
 module     module      module     (VT, etc.)      (last step)
```

## How to read this directory (by role)

| Role | Reading order |
|---|---|
| **First time, anyone** | `README.md` → `01_architecture.md` → `02_contracts.md` |
| **Disk team** | `README.md` → `01_architecture.md` → `02_contracts.md` → `07_disk_module_spec.md` → `05_module_implementation.md` |
| **RAM refactor lead** | `README.md` → `06_ram_module_changes.md` → `02_contracts.md` → `05_module_implementation.md` |
| **Orchestrator builder** | `README.md` → `01_architecture.md` → `04_orchestrator_and_ti.md` → `02_contracts.md` |
| **TI builder** | `README.md` → `04_orchestrator_and_ti.md` → `02_contracts.md` |
| **Anyone implementing schemas** | `02_contracts.md` → `schemas/*.json` |
| **QA / verification** | `09_verification.md` |

## Contents

```
COMPLETE_ARCHITECTURE/
├── README.md                       ← you are here
├── 01_architecture.md              hub-and-spoke big picture, why this shape
├── 02_contracts.md                 the typed envelopes — EntityQuery, EntityFindings, ModuleScanResult
├── 03_pivot_back.md                how pivot queries are answered (hybrid grep + scoped LLM)
├── 04_orchestrator_and_ti.md       orchestrator vs threat intel separation, loop semantics
├── 05_module_implementation.md     generic adapter spec — what every module must implement
├── 06_ram_module_changes.md        RAM-specific: what stays, what's new, what's removed
├── 07_disk_module_spec.md          disk team's contract checklist + entity-type tool mapping
├── 08_repo_layout.md               the five repos and how they pin the shared contract
├── 09_verification.md              end-to-end test plan
└── schemas/
    ├── entity_query.schema.json
    ├── entity_findings.schema.json
    └── module_scan_result.schema.json
```

## The contract in one paragraph

Every interaction across modules uses one of three JSON envelopes: **`ModuleScanResult`** (a module's initial broad scan output, sent unsolicited at case start), **`EntityQuery`** (orchestrator asks a module about a specific entity), and **`EntityFindings`** (module's answer to a query). All three carry a `contract_version` field. All evidence is verbatim from source artifact files with line numbers and optional timestamps. All verdicts are one of `CONFIRMED | INCONCLUSIVE | REJECTED | NOT_FOUND | NOT_APPLICABLE`. JSON schemas in `schemas/` are the ground truth.

## Key design decisions (one-line summaries)

1. **Hub-and-spoke**, not blackboard or RPC mesh — modules stay independent, orchestrator is the only coordinator.
2. **TI is separate from orchestrator** — TI does correlation + external lookups; orchestrator does routing + loop control.
3. **Pivot-back = hybrid** — deterministic grep first, scoped LLM only when retrieval has signal worth interpreting.
4. **Loop terminates** on either `max_rounds=5` OR no-new-entities convergence, whichever fires first.
5. **Cross-module entity linkage is best-effort** — modules emit what they naturally have; orchestrator pivots to fill gaps.
6. **Evidence timestamps** are part of the contract (optional but populated when source has them) — used for final timeline ordering.
7. **TI failures (rate limit, no network) are graceful** — affected entity returns `NOT_FOUND`, loop continues.
8. **Final report is built by the orchestrator** as the last step, over the full case state. No module ships a report writer.
9. **`Cyber-contracts/` is the only shared dependency** — versioned independently, pinned by every other repo.

## Reading time

Estimated 30 minutes end-to-end. Each file is under 200 lines and scan-able.
