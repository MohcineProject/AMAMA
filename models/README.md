# Models

Pluggable forensic modules live here. Each module implements the shared contract:

- **scan** — initial broad analysis → `ModuleScanResult`
- **query** — answer an `EntityQuery` → `EntityFindings`

Expected layout (when added):

```
models/
├── ram/       # memory forensics (Volatility)
├── disk/      # disk forensics (MFT, registry, …)
└── network/   # network forensics (pcap, flows, DNS)
```

Modules are invoked by **Backbone** via manifest entrypoints. They do not talk to each other directly.

See `COMPLETE_ARCHITECTURE/` for the full contract and `Backbone/README.md` for orchestration.
