# Report Output Format — `report.md`

Agent 3 (`report_agent.py`) produces a single `output/report.md`.
When `--use-llm` is passed, the LLM writes a narrative version.
The structured fallback (no LLM) always produces the six sections below.

## Format

```markdown
# Incident Triage Report
_Generated: <ISO-8601 timestamp>_

## Executive Summary
<Overall assessment — number of confirmed/inconclusive/rejected findings.
If LLM ran, a 2–4 sentence narrative of incident scope and severity.>

## Attack Timeline
- **[<SEVERITY>]** PID <pid> (<image>): `<command line excerpt>`
- ...
_No confirmed findings to build a timeline from._   (if none)

## MITRE ATT&CK Mapping
| Technique | Evidence (PID / Image) |
|-----------|------------------------|
| <Txxxx — Name> | PID <pid> (<image>) |
...
_No MITRE mappings provided by Agent 2._   (if none)

## Indicators of Compromise (IOCs)
| Evidence |
|----------|
| `<verbatim evidence line>` |
...
_No verbatim IOCs extracted._   (if none)

## Recommendations
1. **Immediate**: ...
2. **Investigation**: ...
3. **Remediation**: ...

## Confidence Assessment
**<N>** confirmed finding(s) with corroborating evidence.
**<M>** inconclusive finding(s) requiring manual review.
**<K>** finding(s) rejected as benign.
<Optional sentence about inconclusive items.>

---
_Source: `aggregated_analyst.txt` — see per-chunk analyst.txt for full evidence._
```

## Notes

- `report.md` is the only output file in Markdown format; all intermediate files are plain TXT.
- The IOC table is capped at 20 rows (first 20 `Key Evidence` lines from confirmed findings).
- Recommendations differ based on whether confirmed findings exist or not.
- In LLM mode, the structure and section order may vary; the fallback always uses the exact template above.
- Source for this report is `output/aggregated_analyst.txt`, which concatenates all per-chunk `analyst.txt` files with `=== CHUNK N: chunk_XXX.txt ===` headers.
