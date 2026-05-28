# Backbone

Central coordination layer for the multi-module forensic agent system.

## What lives here

| Component | Role |
|-----------|------|
| **Orchestrator agent** | Reviews module findings (batch), maintains the case graph, issues follow-up `EntityQuery` messages |
| **Threat Intel agent** | Enriches entities via external IOC sources (VirusTotal, etc.) |
| **Report agent** | Produces the final incident report from case state |

Forensic modules (RAM, disk, network) live under `../models/` and are plugged in via config manifests.

## Layout

```
Backbone/
├── backbone/           # Python package
│   ├── orchestrator/   # investigation loop + LLM agent
│   ├── threat_intel/   # IOC enrichment
│   ├── report/         # final report builder
│   ├── case_graph.py   # entity graph (orchestrator memory)
│   ├── contracts/      # schema validation helpers
│   └── dispatch/       # async module adapters
├── schemas/            # JSON contracts (EntityQuery, EntityFindings, ModuleScanResult)
├── prompts/            # LLM system prompts
├── config/             # orchestrator + module manifest examples
└── tests/
```

## Quick start (scaffold)

```bash
cd Backbone
pip install -e ".[dev]"
python -m backbone --help
```

## Contracts

All cross-component messages use the JSON schemas in `schemas/`. Human-readable spec: `../COMPLETE_ARCHITECTURE/02_contracts.md`.

## Flow (batch model)

1. Orchestrator triggers **scan** on each registered module (parallel).
2. Modules return `ModuleScanResult` → ingested into **case graph**.
3. Orchestrator agent reviews graph summary → may call **Threat Intel** → issues `EntityQuery` to modules.
4. `EntityFindings` responses merge back into the graph until convergence.
5. **Report agent** writes `report.md`.
