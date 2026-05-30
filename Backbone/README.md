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
cp .env.example .env            # then fill in your API keys (see below)
pytest -q
python -m backbone run --case-id test-001
```

## API keys

Copy `.env.example` to `.env` (git-ignored) and fill in the two keys before running tests:

| Key | Used by | Where to get it |
|-----|---------|-----------------|
| `VT_API_KEY` | Threat Intel module — live IOC lookups against VirusTotal | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) |
| `ANTHROPIC_API_KEY` | Orchestrator agent — LLM routing decisions (Claude Haiku) | [console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys) |

The 25 Threat Intel tests are fully mocked and run without any keys. The 3 non-LLM orchestrator tests also run without keys. The 4 `@pytest.mark.llm` orchestrator tests require `ANTHROPIC_API_KEY` and are skipped automatically when it is absent.

## Contracts

All cross-component messages use the JSON schemas in `schemas/`. Every model under `../models/` **must inherit** `BaseForensicModule` from `backbone.contracts.base_model`.

**Full architecture (flow + file/class map):** [`ARCHITECTURE.md`](ARCHITECTURE.md)

## Flow (batch model)

1. Registry loads `BaseForensicModule` subclasses from config.
2. Orchestrator calls `module.scan(case_id)` on each (parallel) → `ModuleScanResult` → case graph.
3. Orchestrator agent reviews → Threat Intel → `module.query(EntityQuery)` follow-ups.
4. Report agent writes `report.md`.
