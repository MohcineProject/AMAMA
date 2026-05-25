# 08 — Repo layout

## The five repos

```
Cyber-contracts/         ← shared JSON schemas + thin Python helper package
                            (versioned independently; pinned by every other repo)

Cyber-agent/             ← RAM module (this repo today)
                            implements: scan + query for RAM artifacts

Cyber-disk/              ← disk module (separate repo)
                            implements: scan + query for disk artifacts

Cyber-network/           ← network module (separate repo, when built)
                            implements: scan + query for network artifacts

Cyber-orchestrator/      ← orchestrator + TI + final report builder
                            new repo
```

## Why split this way

| Constraint | What it implies |
|---|---|
| Different teams own different modules | Each module is its own repo with its own release cadence. |
| Modules must not depend on each other | No `Cyber-agent` ↔ `Cyber-disk` imports. They only share the contract. |
| The contract is the only cross-cutting concern | It needs its own repo, its own version. Changing it unilaterally would break everyone. |
| The orchestrator depends on the contract, not on modules | Orchestrator imports `cyber-contracts`; it shells out to module CLIs (or uses HTTP if you later go service-oriented). |
| Each repo is independently buildable / testable | A module repo's tests run with the contract + a mock orchestrator. The orchestrator repo's tests run with the contract + mock modules. |

## What `Cyber-contracts/` contains

```
Cyber-contracts/
├── pyproject.toml
├── README.md
├── CHANGELOG.md
├── cyber_contracts/
│   ├── __init__.py
│   ├── schemas/
│   │   ├── entity_query.schema.json
│   │   ├── entity_findings.schema.json
│   │   └── module_scan_result.schema.json
│   ├── types.py             # TypedDict definitions for type hints
│   ├── enums.py             # entity types, verdicts, severities
│   └── validate.py          # validate_query(), validate_findings(), validate_scan_result()
└── tests/
    ├── test_validate.py
    └── fixtures/
        ├── valid_query.json
        ├── valid_findings.json
        ├── valid_scan_result.json
        └── invalid_*.json
```

The package is small (a few hundred lines + schemas). It has one dependency: `jsonschema`.

It is versioned with semver:
- **Patch** (1.0.0 → 1.0.1): bug fix in validators, no schema change
- **Minor** (1.0.x → 1.1.0): backward-compatible schema additions (new optional fields, new enum values that older code can ignore)
- **Major** (1.x → 2.x): backward-incompatible changes (removed fields, changed required fields, removed enum values)

## How each repo pins the contract

```toml
# Cyber-agent/pyproject.toml (RAM)
[project]
dependencies = ["cyber-contracts ~= 1.0", "requests", ...]

# Cyber-disk/pyproject.toml
[project]
dependencies = ["cyber-contracts ~= 1.0", ...]

# Cyber-network/pyproject.toml
[project]
dependencies = ["cyber-contracts ~= 1.0", ...]

# Cyber-orchestrator/pyproject.toml
[project]
dependencies = ["cyber-contracts ~= 1.0", ...]
```

`~= 1.0` accepts 1.x but not 2.x. When the contract ships 2.0, every repo opts in by bumping their pin.

The schemas in each module repo's `schemas/` directory (e.g., RAM's `agentic-architecture/schemas/entity_query.schema.json` after the refactor) are **copies pinned at install time**, useful for offline validation and for analysts reading the repo. They are kept in sync with the installed contract package via a make target or CI check.

## How the orchestrator invokes modules

For v1, **subprocess invocation** is enough:

```python
# inside Cyber-orchestrator/
import subprocess, json

def query_module(target_module: str, query: dict) -> dict:
    # Write query JSON
    qpath = f"/tmp/queries/{query['query_id']}.json"
    rpath = f"/tmp/queries/{query['query_id']}.findings.json"
    with open(qpath, "w") as f: json.dump(query, f)
    # Invoke the module's CLI
    subprocess.run([
        sys.executable, "-m", f"{target_module}.query",
        "--query", qpath,
        "--out",   rpath
    ], check=True)
    # Read response
    with open(rpath) as f: return json.load(f)
```

Each module is a separately-installed Python package. The orchestrator doesn't need to know where each module's code lives — Python's module resolution handles it.

Later, if you want network isolation or different language runtimes, you can swap subprocess for HTTP without changing the contract.

## Where the final report lives

`Cyber-orchestrator/cyber_orchestrator/report_builder.py`. It consumes:

- `case_state.json` (orchestrator's own state file)
- Each module's `output/scan_result.json` and any referenced human-readable artifacts (`artifacts.human_report`)
- All `EntityQuery` / `EntityFindings` audit blocks

It writes a single `report.md`. This is the only deliverable the orchestrator produces directly.

Reuse target: the existing `agentic-architecture/scripts/report_agent.py` from the RAM repo is moved here and reworked to consume `case_state.json` instead of `aggregated_analyst.txt`. The six-section structure (Executive Summary / Timeline / MITRE / IOCs / Recommendations / Confidence Assessment) is mostly preserved, with one new section: a **cross-module pivot trace** appendix showing the path the investigation took.

## What the disk and network teams clone

```
git clone <disk-repo-url>            # their own repo
pip install cyber-contracts          # the shared contract package
```

They then look at `COMPLETE_ARCHITECTURE/` (copied into their repo, or kept as a submodule, or read in `Cyber-agent`) and start implementing.

The disk team should **not** need to clone `Cyber-agent` (the RAM repo) at any point. If they find themselves wanting to, that's a sign of contract leakage — file a bug against the docs.

## What goes where (placement quick-reference)

| Artifact | Lives in |
|---|---|
| JSON schemas (canonical) | `Cyber-contracts/cyber_contracts/schemas/` |
| JSON schemas (pinned copies for human reading) | each module's `schemas/` directory |
| `EntityQuery` Python type hint | `cyber_contracts.types.EntityQuery` |
| `validate_query()` helper | `cyber_contracts.validate.validate_query` |
| RAM's `entity_query.py` (the dispatcher) | `Cyber-agent/agentic-architecture/scripts/entity_query.py` |
| Disk's equivalent | wherever the disk team puts it |
| Orchestrator's loop driver | `Cyber-orchestrator/cyber_orchestrator/loop.py` |
| TI's VT client | `Cyber-orchestrator/cyber_orchestrator/ti/virustotal.py` |
| Final report builder | `Cyber-orchestrator/cyber_orchestrator/report_builder.py` |
| `COMPLETE_ARCHITECTURE/` (this folder) | Top-level of whichever repo you want it canonical in (suggest: `Cyber-contracts/` or a top-level meta-repo) |

## Suggested rollout order

1. **Day 0**: Create `Cyber-contracts/` with the three schemas (already drafted in `COMPLETE_ARCHITECTURE/schemas/`). Publish v1.0.0.
2. **Day 1–7**: RAM refactor (per `06_ram_module_changes.md`). At the end of this week, RAM module emits valid `scan_result.json` and answers `EntityQuery` for at least `pid`, `image_name`, `ip`.
3. **Day 1–14 (parallel)**: Disk team builds their adapter (per `07_disk_module_spec.md`).
4. **Day 8–14**: Build the minimal orchestrator: spawn both modules' `scan`, parse results, run one round of pivots, write report. No loop yet.
5. **Day 15–21**: Add the loop, dedup, TI integration (with at least VirusTotal). End-to-end on the canonical test case.
6. **Later**: Network module, additional TI sources, polish.

The contract is stable enough that disk and orchestrator teams can build in parallel from day 1 without coordination beyond the `Cyber-contracts/` version.
