# Backbone

Central coordination layer for the multi-module forensic agent system.

## What lives here

| Component | Role |
|-----------|------|
| **Orchestrator agent** | Reviews module findings (batch), maintains the case graph, issues follow-up `EntityQuery` messages |
| **Threat Intel agent** | Enriches entities via external IOC sources (VirusTotal, etc.) |
| **Report agent** | Produces the final incident report from case state |

Forensic modules (RAM, disk, network) live under `../models/` and are loaded by class import path.

## Layout

```
Backbone/
├── backbone/
│   ├── orchestrator/   # investigation loop + LLM agent
│   ├── threat_intel/   # IOC enrichment
│   ├── report/         # final report builder
│   ├── case_graph.py   # entity graph (orchestrator memory)
│   ├── contracts/      # schemas, validation, BaseForensicModule
│   └── registry.py     # loads module classes from config
├── schemas/            # JSON contracts
├── prompts/
├── config/
└── tests/
```

## Quick start

```bash
cd Backbone
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # Windows
pip install -e ".[dev]"
pytest -q
python -m backbone run --case-id test-001
```

## Contracts

All cross-component messages use the JSON schemas in `schemas/`. Every model under `../models/` **must inherit** `BaseForensicModule` from `backbone.contracts.base_model`.

## Flow (batch model)

1. Registry loads `BaseForensicModule` subclasses from config.
2. Orchestrator calls `module.scan(case_id)` on each (parallel) → `ModuleScanResult` → case graph.
3. Orchestrator agent reviews → Threat Intel → `module.query(EntityQuery)` follow-ups.
4. Report agent writes `report.md`.
