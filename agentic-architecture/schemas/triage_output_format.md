# Triage Output Format — `triage.txt`

Agent 1 (`triage_agent.py`) writes one `triage.txt` per chunk.
`pivot_grep.py` and `pivot_analyst.py` both parse this file.

## Format

```
=== TRIAGE REPORT ===
Generated: <ISO-8601 timestamp>
Chunk: <chunk_NNN.txt>
Summary: <1–2 sentence broad-tag summary from the LLM>

[PROCESS]
pid: <string>
ppid: <string>
image: <executable name>
cmdline: <full command line, or empty>
severity: LOW|MEDIUM|HIGH|CRITICAL
reasons: <tag 1> | <tag 2> | ...

[PROCESS]
...
```

## Notes

- One `[PROCESS]` block per flagged process; benign processes are omitted.
- Each block ends with a blank line.
- `reasons` tags cite the specific indicator verbatim (path, command fragment, parent PID).
- If the LLM is unavailable, the rule-based fallback writes the same format.
- If zero processes are flagged, the file contains only the header lines (no `[PROCESS]` blocks).

## Parser contract (`pivot_grep.py`, `pivot_analyst.py`)

Both scripts scan for `[PROCESS]` sentinel lines, then read `pid:`, `ppid:`, `image:`, `cmdline:`, `severity:`, `reasons:` key-value lines until the next blank line or EOF.
