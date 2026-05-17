# Pivot Analyst Output Format — `analyst.txt`

Agent 2 (`pivot_analyst.py`) writes one `analyst.txt` per chunk.
The format is defined verbatim by `prompts/agent2_pivot.md` and is the ground truth.
`report_agent.py` parses `aggregated_analyst.txt` (all chunks concatenated) using this format.

## Format

```
================================================================
FIND_EVIL — PIVOT REPORT
Generated: <ISO-8601 timestamp>
Summary: <2–4 sentence overall incident scope assessment>
Counts: confirmed=<N>  inconclusive=<M>  rejected=<K>
================================================================

[CONFIRMED]
----------------------------------------------------------------
PID:      <pid>
PPID:     <ppid>
Image:    <executable name>
Cmdline:  <command line, trimmed to suspicious portion if long>
Severity: LOW|MEDIUM|HIGH|CRITICAL
MITRE:    <Txxxx — Technique Name>    (blank if no clean mapping)

Justification:
  <2–4 sentences citing specific evidence and explaining the verdict>

Key Evidence:
  - <verbatim line from grep input>
  - <verbatim line>
----------------------------------------------------------------

[CONFIRMED]
... (next confirmed finding) ...

================================================================

[INCONCLUSIVE]
----------------------------------------------------------------
PID:      <pid>
PPID:     <ppid>
Image:    <executable name>
Cmdline:  <command line>

Justification:
  <explanation of why the finding could not be confirmed or rejected>

Key Evidence:
  - <verbatim line, if any>
----------------------------------------------------------------
```

## Notes

- `REJECTED` findings are **not** written to the body; they are counted only in the header `Counts:` line.
- `Severity` appears only on `CONFIRMED` blocks; `INCONCLUSIVE` has no tier.
- `MITRE` is optional — blank if no clean ATT&CK technique applies.
- `Key Evidence` lines must be verbatim from the grep-script input (no paraphrase).
- If the LLM is unavailable, `pivot_analyst.py` writes a fallback with `confirmed=0` and all findings as `INCONCLUSIVE`.

## Parser contract (`report_agent.py`)

Uses `re.findall(r'\[CONFIRMED\]\s*-{3,}\s*(.*?)-{3,}', text, re.DOTALL)` and the equivalent for `[INCONCLUSIVE]` to extract blocks. Within each block, reads `PID:`, `PPID:`, `Image:`, `Cmdline:`, `Severity:`, `MITRE:` with `re.search`, and `Key Evidence` lines starting with `  - `.
