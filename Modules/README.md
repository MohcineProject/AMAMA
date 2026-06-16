# Modules

Pluggable forensic modules live here. Each module is a self-contained analysis capability that the Backbone orchestrator loads at startup, scans in parallel with the others, and queries during the investigation. The orchestrator knows nothing about any specific module: add a new one, declare it in the config, and it is fully integrated — initial scan, pivot queries, threat-intel enrichment, and the final report all include it with **zero orchestrator changes**.

```
Modules/
├── RAM/    # memory forensics (Volatility 3) — see RAM/README.md
└── Disk/   # disk forensics (MFT, registry, event logs, …) — see Disk/README.md
```

## The contract

Each module **must inherit** `BaseForensicModule` (`Backbone/backbone/contracts/base_model.py`):

```python
from backbone.contracts.base_model import BaseForensicModule

class DiskModule(BaseForensicModule):
    module_id = "disk"
    supported_entity_types = ["file_path", "hash_sha256", "registry_key", ...]

    async def scan(self, case_id: str) -> ModuleScanResult:
        ...

    async def query(self, query: EntityQuery) -> EntityFindings:
        ...
```

### Obligations

1. **Inherit** `BaseForensicModule` (`Backbone/backbone/contracts/base_model.py`).
2. Set **`module_id`** and **`supported_entity_types`** on the class.
3. Implement **`scan()`** → returns validated `ModuleScanResult`.
4. Implement **`query()`** → returns validated `EntityFindings`.
5. Use **`validate_scan_result()` / `validate_findings()`** (via base class helpers) before returning.
6. Modules do **not** import from `backbone.orchestrator` — only contracts + your own code.

The JSON wire formats are defined in `Backbone/schemas/` (`module_scan_result.schema.json`, `entity_query.schema.json`, `entity_findings.schema.json`); the full flow is described in `Backbone/ARCHITECTURE.md`.

## Register with the Backbone

In `Backbone/config/orchestrator.yaml`:

```yaml
modules:
  - class: disk_module.DiskModule                        # importable class name
    path: ../../Modules/Disk/disk-agentic-architecture   # put on sys.path (relative to the config file)
    kwargs:                                              # passed to the constructor
      use_llm: true
      artifact_dir: /abs/path/to/Modules/Disk/Disk_Artifacts
```

The Backbone imports the class, instantiates it with `kwargs`, and calls `scan()` / `query()` directly.

## Adding a new module

1. Create `Modules/<Name>/` with your analysis code.
2. Write a class inheriting `BaseForensicModule` with a unique `module_id`, its `supported_entity_types`, and `scan()` / `query()`.
3. Add an entry to `Backbone/config/orchestrator.yaml` (class + path + kwargs).

That's it — on the next run the orchestrator scans your module in parallel with the others, routes an `EntityQuery` to it whenever an entity matches your `supported_entity_types`, and folds its findings into threat-intel enrichment and the final report.
