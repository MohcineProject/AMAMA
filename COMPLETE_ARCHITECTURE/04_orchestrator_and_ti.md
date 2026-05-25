# 04 — Orchestrator and Threat Intel

This document defines what the orchestrator does, what the threat intel service does, where the boundary is, and how the investigation loop runs.

## Separation of concerns

### Orchestrator owns

- **Case state**: the set of known entities, where each came from (which module / which finding), which modules have already been queried about it, and the full audit history of queries and responses.
- **Routing**: deciding which entities to ask which modules, based on the entity's type and the modules that haven't yet seen it.
- **Loop control**: round counter, termination check, dedup.
- **TI calls**: invokes TI between rounds with the current entity set.
- **Final report**: produced as the last step after the loop terminates, over the full case state + all artifact references.

### Threat Intel owns

- **External IOC clients**: VirusTotal, AbuseIPDB, AlienVault OTX, GreyNoise, etc. Each one wrapped behind a common interface.
- **Response normalization**: external responses are converted to the same `EntityFindings` shape that internal modules emit. To the orchestrator, a VT lookup looks structurally identical to a RAM/disk response.
- **Caching**: within a single case, the same hash/IP/domain is queried at most once per provider.
- **Correlation**: when multiple entities map to the same campaign or threat family per external sources, TI emits a synthetic finding that surfaces the link (with new `related_entities` if the campaign profile has more indicators).

### Neither component owns

- **Forensic interpretation** — that stays in each module.
- **Reading artifact files** — only modules read their own artifacts.
- **The decision of which entity to pivot on next** — orchestrator-only.

## Investigation loop

```
1. Case start
   ├─ Orchestrator triggers INITIAL scan on every module (parallel)
   └─ Each module emits a ModuleScanResult
         └─ Orchestrator parses findings[]:
            - adds every primary_entity and related_entity to case state
            - tags each with its source (module + finding_id)

2. Loop, until termination
   round R:
   ├─ Orchestrator picks new entities discovered since the last round
   │  └─ Sends them to TI for enrichment (one batch call)
   │     └─ TI returns EntityFindings[] (one per entity, includes new related_entities from external sources)
   │        └─ Orchestrator adds new entities to case state
   │
   ├─ Orchestrator decides which (entity, target_module) pairs to query
   │  - skip any (module, entity_type, entity_value) tuple already queried this case (dedup)
   │  - skip entity types the target module declared NOT_APPLICABLE in this case
   │  - prioritize by severity of source finding when over per-round budget
   │
   ├─ Orchestrator sends EntityQuery to each chosen module (parallel)
   │  └─ Module returns EntityFindings
   │     └─ Orchestrator merges: adds related_entities to case state, marks the (module, entity) tuple as queried
   │
   └─ Termination check (run at end of round):
      - if round >= max_rounds → STOP
      - if no new entities added this round → STOP
      - otherwise → round R+1

3. After termination
   └─ Orchestrator runs the report builder over case state + all artifact refs
      └─ Final report.md (the only human-facing deliverable)
```

## Termination rules

| Rule | Default | Configurable |
|---|---|---|
| `max_rounds` (hard cap) | 5 | yes |
| No-new-entities convergence | always on | no |
| `max_queries_per_round` (overflow safety) | 30 | yes |

Both `max_rounds` and convergence apply. Whichever fires first ends the loop.

The per-round budget exists to prevent a TI response that contains, say, a 200-IOC campaign profile from spiking a single round. Excess entities roll into the next round, sorted by severity of their source finding.

## Dedup

Keyed by `(target_module, entity.type, entity.value)`. Once a tuple has been queried in a case, subsequent attempts return the cached `EntityFindings` immediately without re-invoking the module.

This means: even if disk and RAM both find the same IP, only one of them gets asked about it. The orchestrator picks the most-likely-to-have-evidence module first (based on entity type → module priority).

## Entity type → module priority (orchestrator routing table)

| Entity type | First-try module | Second-try | Notes |
|---|---|---|---|
| `pid` | RAM | — | Disk and network don't track PIDs |
| `image_name` | RAM | disk | RAM has running processes; disk has the file on disk |
| `file_path` | disk | RAM | Disk has authoritative file metadata; RAM may have it loaded |
| `hash_sha256` (and other hashes) | disk | TI | Disk computes hashes from the file; TI enriches externally |
| `ip`, `domain`, `url` | network | RAM | Network has flow/pcap; RAM may have the connection in netscan |
| `registry_key` | disk | RAM | Disk reads hives; RAM has live registry views via `registry_printkey` |
| `mutex` | RAM | — | Disk and network can't see runtime mutexes |
| `user_sid` | RAM | disk | RAM has tokens; disk has SAM/SECURITY hive data |

The orchestrator tries the first module. If the response is `NOT_APPLICABLE` or `NOT_FOUND` AND there's a second-try, it queries the second.

## TI batch interface

To avoid one HTTP call per entity, TI exposes a batch endpoint:

```
POST /enrich
{
  "contract_version": "1.0",
  "case_id": "case-...",
  "entities": [
    { "type": "hash_sha256", "value": "abc..." },
    { "type": "ip",          "value": "1.2.3.4" }
  ]
}

Response:
{
  "findings": [
    <EntityFindings>,
    <EntityFindings>
  ]
}
```

Each finding inside `findings[]` matches the `EntityFindings` schema exactly, with `responding_module: "ti"` and `evidence[].source_file` pointing at the external source (e.g., `"virustotal"`, `"abuseipdb"`).

## Graceful TI failure

Per the resolved decisions:

- If TI can't reach an external provider (network down, rate limited, API key invalid), the affected entity gets back `verdict: NOT_FOUND` with `justification` explaining the failure mode (e.g., `"VirusTotal rate-limited; entity not enriched this round"`).
- The orchestrator treats `NOT_FOUND` from TI like any other `NOT_FOUND`: it doesn't add new entities for that entity, but the loop continues.
- No special `--no-external` flag, no `NO_NETWORK` sentinel. The contract handles offline cases via the existing verdict enum.

## Final report

Built by the orchestrator after the loop terminates. Inputs:

- Case state (all entities, all findings)
- Each module's `ModuleScanResult.artifacts.human_report` path (the per-module audit-trail TXT, preserved verbatim for reference)
- All `EntityFindings` collected during the loop
- All `EntityQuery` audit blocks (for the appendix)

Output: `report.md` with sections:

1. **Executive summary** — confirmed/inconclusive/rejected counts across all modules + TI; overall severity assessment
2. **Attack timeline** — chronological list of CONFIRMED findings ordered by `evidence[].timestamp` (falling back to first-seen order when timestamps are missing)
3. **MITRE ATT&CK mapping** — table of techniques aggregated across all confirmed findings
4. **Indicators of Compromise** — top 20 verbatim evidence lines from CONFIRMED findings; include file paths, hashes, IPs, domains as separate sub-tables
5. **Recommendations** — containment, investigation, remediation
6. **Confidence assessment** — what was confirmed vs. inconclusive, what gaps remain
7. **Appendix: cross-module pivot trace** — for each entity that drove the loop, show which module surfaced it and which modules confirmed/rejected it (this is the audit story)

The orchestrator's report builder may use LLM or templating; either is acceptable. The existing `report_agent.py` from the RAM repo is a good starting point (it supports both modes today) — moved out of RAM and reworked to consume the orchestrator's case state instead of `aggregated_analyst.txt`.

## Case state — minimum data model

The orchestrator must keep at least this much in memory (and persist it to disk for audit):

```python
case_state = {
  "case_id": str,
  "rounds": [
    {
      "round_number": int,
      "ti_calls": [<EntityFindings>, ...],
      "module_queries": [
        {"query": <EntityQuery>, "response": <EntityFindings>},
        ...
      ],
      "new_entities_added": int
    },
    ...
  ],
  "entities": {
    # keyed by (type, value)
    ("ip", "185.220.101.45"): {
      "first_seen": {"round": 0, "module": "network", "finding_id": "net-c001-f003"},
      "queried_modules": {"ram", "ti"},  # dedup set
      "verdicts_received": [
        {"module": "ram", "verdict": "CONFIRMED", "severity": "HIGH"},
        {"module": "ti",  "verdict": "CONFIRMED", "severity": "HIGH"}
      ]
    },
    ...
  },
  "initial_scans": {
    "ram":     <ModuleScanResult>,
    "disk":    <ModuleScanResult>,
    "network": <ModuleScanResult>
  }
}
```

Persisting this as `output/case_state.json` between rounds gives the orchestrator a free crash-recovery story and a complete audit artifact.
