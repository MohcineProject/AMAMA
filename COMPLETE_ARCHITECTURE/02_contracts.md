# 02 — Contracts (the typed envelopes)

Three JSON envelopes carry every interaction across modules. JSON schemas in `schemas/` are the ground truth — this document is a human-readable companion.

All envelopes include `"contract_version": "1.0"`. Any module receiving an envelope with an unknown version returns `verdict: NOT_APPLICABLE` with `justification: "unsupported contract_version"`.

---

## 1. `EntityQuery` — orchestrator → module

Sent when the orchestrator wants a module to look up a specific entity.

### Example

```json
{
  "contract_version": "1.0",
  "query_id": "550e8400-e29b-41d4-a716-446655440000",
  "round": 2,
  "case_id": "case-2026-05-20-001",
  "target_module": "ram",
  "entity": {
    "type": "ip",
    "value": "185.220.101.45"
  },
  "context": {
    "source_module": "network",
    "source_finding_id": "net-c001-f003",
    "reason": "Outbound connection to known Tor exit node — confirm process attribution"
  },
  "scope": {
    "max_evidence_lines": 50,
    "include_related_entities": true,
    "time_window": null
  }
}
```

### Field reference

| Field | Required | Type | Description |
|---|---|---|---|
| `contract_version` | yes | string | Must equal `"1.0"` for now. |
| `query_id` | yes | string (uuid-v4) | Globally unique. Echoed back in the response. |
| `round` | yes | integer (≥0) | Which orchestrator round produced this query. `0` is reserved for initial-scan derived queries; loop rounds are 1..N. |
| `case_id` | yes | string | Identifies the investigation. Modules use this for audit file naming. |
| `target_module` | yes | enum | `ram` \| `disk` \| `network`. The module receiving the query should refuse to process if this doesn't match its identity. |
| `entity.type` | yes | enum | See entity types below. |
| `entity.value` | yes | string | The literal value to search for. |
| `context.source_module` | yes | enum | Which module (or `ti`) surfaced this entity originally. |
| `context.source_finding_id` | yes | string | Backreference to a prior finding. Used for audit. |
| `context.reason` | yes | string | Human/LLM-readable. **This is what the scoped LLM in the target module reads to know what kind of answer is wanted** (attribution vs behavior vs provenance). Make it specific. |
| `scope.max_evidence_lines` | no | int (default 50) | Cap on `evidence[]` size in the response. |
| `scope.include_related_entities` | no | bool (default true) | If false, module skips populating `related_entities` (cheaper). |
| `scope.time_window` | no | object \| null | Optional `{from: ISO-8601, to: ISO-8601}` to filter evidence by timestamp. |

### Entity types (closed enum)

`ip`, `domain`, `url`, `hash_md5`, `hash_sha1`, `hash_sha256`, `file_path`, `image_name`, `pid`, `registry_key`, `mutex`, `user_sid`

A module that doesn't handle a given type returns `verdict: NOT_APPLICABLE` immediately, no LLM call.

---

## 2. `EntityFindings` — module → orchestrator

The response to an `EntityQuery`. TI also emits this shape for external lookups.

### Example

```json
{
  "contract_version": "1.0",
  "query_id": "550e8400-e29b-41d4-a716-446655440000",
  "responding_module": "ram",
  "entity": { "type": "ip", "value": "185.220.101.45" },
  "verdict": "CONFIRMED",
  "severity": "HIGH",
  "mitre": ["T1071.001"],
  "justification": "PID 3412 (powershell.exe spawned by WINWORD) holds an established TCP connection to this IP. SeDebugPrivilege enabled, encoded -Enc command in cmdline. Cross-references with malfind RWX region in same process.",
  "evidence": [
    {
      "source_file": "netscan.txt",
      "line": 1422,
      "content": "0xff... TCPv4 ... 185.220.101.45 443 ESTABLISHED 3412",
      "verbatim": true,
      "timestamp": "2026-05-13T19:27:14Z"
    },
    {
      "source_file": "malfind.txt",
      "line": 88,
      "content": "3412 ... PAGE_EXECUTE_READWRITE ...",
      "verbatim": true,
      "timestamp": null
    }
  ],
  "related_entities": [
    { "type": "pid",        "value": "3412",              "relationship": "owns_connection" },
    { "type": "image_name", "value": "powershell.exe",    "relationship": "process_image" },
    { "type": "user_sid",   "value": "S-1-5-21-...-1001", "relationship": "process_owner" }
  ],
  "cost": { "llm_calls": 1, "tokens_in": 1840, "tokens_out": 320 }
}
```

### Field reference

| Field | Required | Type | Description |
|---|---|---|---|
| `contract_version` | yes | string | `"1.0"` |
| `query_id` | yes | string | Echoes the `EntityQuery.query_id`. |
| `responding_module` | yes | enum | `ram` \| `disk` \| `network` \| `ti`. |
| `entity` | yes | object | Echoes the queried entity. |
| `verdict` | yes | enum | `CONFIRMED` \| `INCONCLUSIVE` \| `REJECTED` \| `NOT_FOUND` \| `NOT_APPLICABLE`. See verdict semantics below. |
| `severity` | only when `verdict=CONFIRMED` | enum or null | `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL`. Null for non-CONFIRMED. |
| `mitre` | no | string[] | MITRE ATT&CK technique IDs (e.g., `T1059.001`). Empty if none cleanly apply. |
| `justification` | yes | string | 1–4 sentences explaining the verdict, citing evidence. Required even for `NOT_FOUND` (short, e.g., "No matching lines in any RAM artifact"). |
| `evidence` | yes | array | Verbatim lines from source artifact files. May be empty for `NOT_FOUND` / `NOT_APPLICABLE`. |
| `evidence[].source_file` | yes | string | Filename within the module's artifact tree. |
| `evidence[].line` | yes | int | Line number in `source_file` (1-indexed). |
| `evidence[].content` | yes | string | Verbatim line content. |
| `evidence[].verbatim` | yes | bool | Always `true` for honest implementations. Reserved in case future versions allow paraphrase. |
| `evidence[].timestamp` | no | string (ISO-8601) \| null | Populated when the source artifact carries a timestamp. Used by the final report for timeline ordering. |
| `related_entities` | yes (may be empty) | array | New entities discovered while answering this query. **This is what drives loop expansion.** |
| `related_entities[].type` | yes | enum | Same enum as `entity.type`. |
| `related_entities[].value` | yes | string | |
| `related_entities[].relationship` | yes | string | Free-text label describing the link (e.g., `owns_connection`, `process_image`, `loaded_dll`, `parent_process`). |
| `cost` | yes | object | Observability. `llm_calls`, `tokens_in`, `tokens_out`. All `0` when no LLM fired. |

### Verdict semantics

| Verdict | When to use |
|---|---|
| `CONFIRMED` | Clear evidence supports the suspicion implied by `context.reason`. Multiple corroborating signals OR one unambiguous indicator. |
| `INCONCLUSIVE` | Some signal exists but insufficient to confirm or reject. The orchestrator should consider further pivots. |
| `REJECTED` | Evidence shows benign behavior. The entity is explained. |
| `NOT_FOUND` | No matching evidence in this module's artifacts. (Retrieval returned 0 hits.) |
| `NOT_APPLICABLE` | This module does not handle this entity type (e.g., RAM asked about `hash_sha256`). No work was done. |

---

## 3. `ModuleScanResult` — module → orchestrator (initial broad scan)

Emitted once per case by each module, unprompted, after its initial broad scan completes.

### Example

```json
{
  "contract_version": "1.0",
  "case_id": "case-2026-05-20-001",
  "module": "ram",
  "scan_started_at": "2026-05-20T14:30:00Z",
  "scan_completed_at": "2026-05-20T14:34:22Z",
  "summary": "9 chunks processed. 2 CONFIRMED, 1 INCONCLUSIVE, 6 REJECTED.",
  "counts": { "confirmed": 2, "inconclusive": 1, "rejected": 6 },
  "findings": [
    {
      "finding_id": "ram-c001-f001",
      "verdict": "CONFIRMED",
      "severity": "HIGH",
      "mitre": ["T1059.001"],
      "primary_entity": { "type": "pid", "value": "3412" },
      "related_entities": [
        { "type": "image_name", "value": "powershell.exe", "relationship": "process_image" },
        { "type": "ip",         "value": "185.220.101.45", "relationship": "outbound_c2" }
      ],
      "justification": "Spawned from WINWORD.EXE (Office macro execution). Encoded command contains download cradle pattern. SeDebugPrivilege enabled.",
      "evidence": [
        { "source_file": "cmdline.txt", "line": 542, "content": "3412 powershell.exe -Enc SQBFAFgA...", "verbatim": true, "timestamp": "2026-05-13T19:26:58Z" }
      ]
    }
  ],
  "artifacts": {
    "human_report": "output/aggregated_analyst.txt",
    "per_chunk":    ["output/chunk_001/analyst.txt", "output/chunk_002/analyst.txt"]
  }
}
```

### Field reference

| Field | Required | Description |
|---|---|---|
| `contract_version` | yes | `"1.0"` |
| `case_id` | yes | Matches the case_id used in subsequent EntityQuery calls. |
| `module` | yes | `ram` \| `disk` \| `network`. |
| `scan_started_at` / `scan_completed_at` | yes | ISO-8601 timestamps. |
| `summary` | yes | 1–2 sentence human-readable summary. |
| `counts` | yes | `confirmed` / `inconclusive` / `rejected` totals. |
| `findings[]` | yes (may be empty) | Each finding has the same evidence/related_entities/justification shape as `EntityFindings`, plus a `finding_id` and a `primary_entity` (the entity the finding centers on). |
| `findings[].finding_id` | yes | Stable string ID. Convention: `<module>-<chunk_or_subscan>-f<index>` (e.g., `ram-c001-f001`). |
| `findings[].primary_entity` | yes | The "anchor" entity (e.g., the PID for a process-centered finding). |
| `findings[].related_entities` | yes (may be empty) | Best-effort linkages. Modules emit what they naturally have; the orchestrator pivots to fill the rest. |
| `artifacts` | yes | Paths to the module's own audit-trail files (TXT for humans). Orchestrator preserves these for the final report. |

### Best-effort linkage policy

Modules are **not** required to perform extra work to populate `related_entities` for a primary entity. They emit only what their natural pipeline produced. If RAM knows the IP for PID 3412 but didn't bother to resolve the user SID, it just leaves SID out. The orchestrator will pivot back with an `EntityQuery` for the SID if it needs it.

---

## Common rules

- **Verbatim evidence.** `evidence[].content` must be the literal line from `source_file` at `line`. No paraphrase, no formatting changes. This is the auditability guarantee.
- **No invented entities.** `related_entities[]` may only include entities that actually appeared in the evidence the module retrieved. If you can't cite it, you can't list it.
- **Severity only on CONFIRMED.** Other verdicts have `severity: null`.
- **Timestamps best-effort.** Populate when the source artifact has them; leave `null` otherwise.
- **`cost` always populated.** Even when no LLM fired, emit `{"llm_calls": 0, "tokens_in": 0, "tokens_out": 0}`.
