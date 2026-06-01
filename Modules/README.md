# Models

Pluggable forensic modules live here. Each module **must inherit** `BaseForensicModule`:

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

## Obligations

1. **Inherit** `BaseForensicModule` (`Backbone/backbone/contracts/base_model.py`).
2. Set **`module_id`** and **`supported_entity_types`** on the class.
3. Implement **`scan()`** → returns validated `ModuleScanResult`.
4. Implement **`query()`** → returns validated `EntityFindings`.
5. Use **`validate_scan_result()` / `validate_findings()`** (via base class helpers) before returning.
6. Modules do **not** import from `backbone.orchestrator` — only contracts + your own code.

## Register with Backbone

In `Backbone/config/orchestrator.yaml`:

```yaml
modules:
  - class: models.disk.disk_module.DiskModule
    kwargs:
      artifact_dir: "../models/Disk/Disk_Artifacts"
```

Backbone imports the class and calls `scan()` / `query()` directly — no CLI, no adapter layer.

## Expected layout

```
models/
├── ram/       # memory forensics (Volatility)
├── disk/      # disk forensics (MFT, registry, …)
└── network/   # network forensics (pcap, flows, DNS)
```

See `COMPLETE_ARCHITECTURE/02_contracts.md` for the JSON wire format.
