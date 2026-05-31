# 01 — Architecture

## The shape: hub-and-spoke with typed envelopes

```
┌───────────────────────────────────────────────────────────────────┐
│                     ORCHESTRATOR (controller)                     │
│                                                                   │
│   - drives the investigation loop                                 │
│   - holds the case state (known entities, dedup set, history)    │
│   - picks who to ask next                                         │
│   - assembles the final report at the end                         │
└──┬───────────────┬───────────────┬───────────────┬────────────────┘
   │               │               │               │
   ▼               ▼               ▼               ▼
┌──────┐      ┌──────┐       ┌──────────┐    ┌──────────────────┐
│ RAM  │      │ Disk │       │ Network  │    │  Threat Intel    │
│module│      │module│       │  module  │    │  (enrichment)    │
└──┬───┘      └──┬───┘       └────┬─────┘    │  VT, AbuseIPDB,  │
   │             │                │          │  AlienVault, …   │
   │   per-module pipelines       │          └────────┬─────────┘
   │  (RAM = today's 3 agents)    │                   │
   │                              │                   │
   └────────────┬─────────────────┴───────────────────┘
                │
                ▼
        Two operating modes per module:
          1. INITIAL: full broad scan (the today flow)
          2. QUERY:   answer a typed EntityQuery from orchestrator
```

## The components

### Orchestrator
- The only component that knows about all modules.
- Holds the **case state**: the set of known entities, where each entity came from, which modules have been queried about it, and the full audit history of queries and responses.
- Implements the **investigation loop** (see `04_orchestrator_and_ti.md`).
- Produces the **final report** as the last step, after the loop terminates.

### Modules (RAM, disk, network)
- Each one runs its own pipeline on its own artifact files. RAM has 3 LLM agents + 1 grep stage; disk has its own tools (MFT, USN, registry hives, prefetch); network has its own (pcap, flow logs, DNS).
- Each module has **two modes**:
  - **INITIAL**: a one-shot broad scan, emits a `ModuleScanResult` (the structured form of "everything I found unprompted").
  - **QUERY**: answers an `EntityQuery` from the orchestrator about one specific entity, emits an `EntityFindings`.
- Modules do **not** talk to each other directly. Everything goes through the orchestrator.

### Threat Intel (TI)
- A peer service called by the orchestrator between rounds.
- Wraps external IOC providers (VirusTotal, AbuseIPDB, AlienVault OTX, GreyNoise, etc.) behind a uniform interface.
- Normalizes external responses to the same `EntityFindings` shape that internal modules emit — so to the orchestrator, an external IOC lookup looks structurally identical to a module response.
- Does **not** decide what to pivot on. Does **not** know module internals.

### Shared contract package (`Cyber-contracts/`)
- Holds the JSON schemas for `EntityQuery`, `EntityFindings`, `ModuleScanResult`.
- The only artifact pinned by every other repo. Versioned independently.

## Why this shape (and not the alternatives)

| Alternative | Why we didn't pick it |
|---|---|
| **Blackboard / shared event store** | More moving parts (database, event bus, subscriptions). No clear win for 3 modules. Adds operational complexity. |
| **Tight RPC mesh** (modules call each other) | Couples module repos pairwise. Pivot routing logic ends up duplicated across modules. Hard to test. |
| **Single super-agent with all tools (ReAct)** | Loses parallelism (modules can run their initial scans concurrently). One bad LLM step poisons the whole investigation. Hard to specialize prompts per artifact type. Hard to test. |
| **Orchestrator + TI merged** | TI logic is heavy (external clients, rate limiting, response normalization, caching). Merging makes the orchestrator harder to reason about. Keeping them separate lets us mock TI in orchestrator tests. |

## What each component owns (responsibility matrix)

| Concern | Owner |
|---|---|
| Run RAM/disk/network forensic tools | The respective module |
| Interpret evidence for a specific entity | The respective module (scoped LLM) |
| Decide which module to query next | Orchestrator |
| Track which entities have been seen | Orchestrator |
| Terminate the loop | Orchestrator |
| Query VirusTotal / external IOC providers | TI |
| Cache external lookups within a case | TI |
| Correlate cross-source IOCs into campaigns | TI |
| Write the final human-readable report | Orchestrator |

## What each component does **not** own

| Component | Does not own |
|---|---|
| RAM / Disk / Network | Knowing other modules exist; pivot routing; final report writing |
| Orchestrator | Forensic domain knowledge; reading artifact files directly; calling external IOC APIs |
| TI | Pivot decisions; module internals; loop control; final report |

## Data flow at a glance

```
1. Case starts
   └─► Orchestrator triggers INITIAL scan on every module in parallel
       └─► RAM, Disk, Network each emit ModuleScanResult
           └─► Orchestrator seeds case state with all primary + related entities

2. Loop (up to max_rounds, until convergence)
   ├─► Orchestrator sends new entities to TI for enrichment
   │   └─► TI returns EntityFindings[] (external context + possibly new related entities)
   ├─► Orchestrator picks (entity, target_module) pairs to query
   │   └─► Module returns EntityFindings (per-entity verdict + evidence + related entities)
   └─► Orchestrator merges new findings into case state, checks termination

3. Loop terminates
   └─► Orchestrator runs report builder over case state + all artifact references
       └─► Final report.md
```

## Where to go next

- Want the wire format? → `02_contracts.md`
- Want to understand how a single pivot query is answered inside a module? → `03_pivot_back.md`
- Want to understand the loop and TI's role? → `04_orchestrator_and_ti.md`
- Building a module? → `05_module_implementation.md`
