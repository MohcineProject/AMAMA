# 03 — Pivot-back mechanism

When the orchestrator sends an `EntityQuery` to a module, **what actually runs?** This document spells out the answer and explains why we chose it over the alternatives.

## The chosen mechanism: hybrid retrieval + conditional LLM (Option D)

```
Module receives EntityQuery
        │
        ▼
┌──────────────────────────────────────┐
│ Stage 1: Type dispatch               │
│ - Is this entity.type something I    │
│   can answer?                        │
│ - If no → return NOT_APPLICABLE      │
│   (zero LLM calls, ~0 tokens)        │
└────────────┬─────────────────────────┘
             ▼
┌──────────────────────────────────────┐
│ Stage 2: Deterministic retrieval     │
│ - grep / index lookup across the     │
│   module's artifact files            │
│ - cap at scope.max_evidence_lines    │
│ - zero LLM                           │
└────────────┬─────────────────────────┘
             ▼
       ┌─────┴─────┐
       │           │
   0 hits      hits exist
       │           │
       ▼           ▼
┌──────────┐  ┌────────────────────────────────────┐
│ Return   │  │ Stage 3: Triviality check          │
│ NOT_FOUND│  │ (deterministic, module-specific)   │
│ no LLM   │  │ - Is the entity "obviously benign" │
└──────────┘  │   per a whitelist or signature?    │
              │ - If yes → return REJECTED + the   │
              │   whitelist evidence, no LLM       │
              └────────┬───────────────────────────┘
                       ▼
              ┌────────────────────────────────────┐
              │ Stage 4: Scoped LLM interpreter    │
              │ - Input:                           │
              │     (entity,                       │
              │      context.reason,               │
              │      retrieved evidence)           │
              │ - System prompt is small (see      │
              │   06_ram_module_changes.md for     │
              │   RAM's agentQ_focused.md)         │
              │ - LLM MUST cite only evidence      │
              │   that was passed in               │
              │ - Output: full EntityFindings      │
              └────────────────────────────────────┘
```

## Token-cost ladder

| Scenario | LLM calls | Tokens | Typical wall-clock |
|---|---|---|---|
| `NOT_APPLICABLE` (wrong entity type) | 0 | 0 | <10ms |
| `NOT_FOUND` (retrieval empty) | 0 | 0 | tens of ms |
| `REJECTED` via whitelist | 0 | 0 | tens of ms |
| `CONFIRMED` / `INCONCLUSIVE` / `REJECTED` via LLM | 1 | ~1k–3k in, ~200–500 out | 1–3 s |

In a typical case, ~70–80% of pivot queries should terminate before stage 4. This is what makes the loop affordable.

## Why this and not the alternatives

The full tradeoff analysis. Five dimensions matter:

- **Token cost** — every LLM call has a price; pivots multiply by entity count × rounds
- **Hallucination risk** — when interpretation happens, can the LLM invent evidence?
- **Modularity** — does logic stay in the right module, or leak into the orchestrator?
- **Latency** — wall-clock impact on the investigation loop
- **Auditability** — can an analyst trace every claim back to a raw artifact line?

### Option A — Pure deterministic grep (no LLM on pivot-back)

Module returns `NOT_FOUND` or `INCONCLUSIVE` + raw evidence; orchestrator/TI does the interpretation.

| Dimension | Score |
|---|---|
| Token cost | **Best** — zero LLM tokens on pivot-back |
| Hallucination risk | **Best on retrieval** — verbatim grep can't lie. But pushes interpretation to the orchestrator, which then balloons into a domain expert. |
| Modularity | **Worst** — orchestrator now needs to know that `SeDebugPrivilege Enabled` on a non-system process is suspicious. |
| Latency | **Best** |
| Auditability | Great for retrieval, poor for verdicts |

**Best for:** trivial entity types where retrieval == answer ("does file X exist on disk?"). Bad for anything needing domain interpretation.

### Option B — Always invoke a scoped LLM micro-agent

Every query fires an LLM, even when retrieval returned 0 hits.

| Dimension | Score |
|---|---|
| Token cost | **Worst** — N × M LLM calls, many wasted on empty evidence |
| Hallucination risk | **Bad** — LLMs called with empty evidence are most likely to confabulate ("this IP *could* be C2"). |
| Modularity | Great |
| Latency | Worst |
| Auditability | Good but noisy (justifications for empty evidence are filler) |

**Best for:** nothing in practice. The empty-evidence problem is real.

### Option C — Full pipeline re-run filtered to the entity

Re-trigger triage → grep → analyst (or each module's equivalent) with a filter.

| Dimension | Score |
|---|---|
| Token cost | **Worst** — full re-run |
| Hallucination risk | Same as initial run |
| Modularity | Good |
| Latency | **Worst** — tens of seconds per pivot |
| Auditability | Strong |

**Best for:** almost never. The initial scan already considered every process/file. Re-running for one entity wastes work that's already done.

### Option D — **Hybrid (chosen)**

The four-stage flow above.

| Dimension | Score |
|---|---|
| Token cost | **Best of LLM-using options** — LLM fires only when there's signal worth interpreting |
| Hallucination risk | **Low** — interpreter is given verbatim evidence + the `context.reason`, and is forbidden from citing evidence not in the input. Same discipline as the existing Agent 2 in RAM. |
| Modularity | **Best** — domain stays in the module; orchestrator is domain-blind |
| Latency | **Good** — milliseconds when no LLM, ~1–3s when LLM fires |
| Auditability | **Best** — verdict + verbatim evidence + justification all traceable |

## Discipline rules for the scoped LLM (stage 4)

Every module's interpreter prompt must enforce:

1. **No fabricated evidence.** The LLM can only cite lines that were passed in. If it wants to claim something not in the evidence, it must downgrade the verdict.
2. **No new entities not in evidence.** `related_entities[]` must only contain entities that appear in the retrieved lines.
3. **Conservative bias.** When in doubt between CONFIRMED and INCONCLUSIVE, pick INCONCLUSIVE. False negatives are preferable to false positives. (Same policy as Agent 2 today.)
4. **Use `context.reason`.** The orchestrator passes a specific question. The justification should answer that question, not a generic "this looks suspicious."
5. **Empty retrieval → no LLM call.** The interpreter is never called with zero evidence. The retrieval stage handles that case by returning `NOT_FOUND` deterministically.

## Triviality check (stage 3) — what counts as "obviously benign"

Each module decides what whitelists look like. Examples:

- **RAM:** file path matches `whitelist.txt` patterns (already exists in `agentic-architecture/scripts/whitelist.txt`) — e.g., `C:\Windows\System32\*.exe`, `C:\Program Files\Microsoft\**\*.dll`.
- **Disk:** signed by a known trusted publisher; hash matches a Microsoft/Apple/major-vendor catalog.
- **Network:** IP/domain in an internal allowlist; reverse-DNS resolves to a known infrastructure provider with no other red flags.

The check must be **conservative**: if there's any reason for doubt (e.g., the path matches whitelist but the cmdline contains `-Enc`), skip the check and proceed to the LLM.

## When does the LLM produce `INCONCLUSIVE` vs `REJECTED`?

Same rules as the existing Agent 2:

- **REJECTED** — evidence positively shows benign behavior. ("The DLL is signed by Microsoft and loaded from System32. The cross-process handle is to a sibling instance of the same service, normal for COM activation.")
- **INCONCLUSIVE** — there is *some* signal but it's not enough to confirm or rule out. ("The process has SeDebugPrivilege but no further suspicious indicators in the retrieved evidence. Need more context to decide.")
- The orchestrator will treat INCONCLUSIVE as a hint that more pivots in other modules might help.

## Audit trail

Every pivot query also produces a human-readable audit block, written to `output/queries/<query_id>.txt` (RAM convention; other modules use their own paths). The block contains:

- The `EntityQuery` JSON
- The retrieved evidence verbatim (with source file + line numbers)
- The LLM prompt (if LLM fired)
- The LLM raw response (if LLM fired)
- The final `EntityFindings` JSON

This is what an analyst opens to verify any claim in the final report.
