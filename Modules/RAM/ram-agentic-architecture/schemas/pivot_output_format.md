# Pivot Output Format — `pivot.txt`

`pivot_grep.py` writes one `pivot.txt` per chunk.
`pivot_analyst.py` parses this file to build the LLM evidence context.

## Format

```
=== PIVOT EVIDENCE REPORT ===
Generated: <ISO-8601 timestamp>

=== PID <pid> (<image>, ppid=<ppid>) ===
Cmdline: <command line>

--- <filename.txt> ---
L<lineno>: <verbatim matching line from artifact file>
L<lineno>: <verbatim matching line>
...

--- <filename2.txt> ---
...

=== PID <pid2> (<image2>, ppid=<ppid2>) ===
(no matching lines in any artifact file)

=== END OF PIVOT REPORT ===
```

## Notes

- One `=== PID N ===` section per process that appeared in `triage.txt`.
- Evidence lines are verbatim from the Volatility artifact files, prefixed with `L<lineno>:`.
- If a PID has no hits in any artifact file, only the header and the `(no matching lines...)` line appear.
- Evidence lines are capped per-file (`max_lines_per_file` config) and across all files per PID (`max_total_lines_per_target` config) to keep context size manageable.

## Parser contract (`pivot_analyst.py`)

Scans for `=== PID <digits>` to open a section, `--- <name> ---` to open a file block, and `=== END` or the next `=== PID` to close. Lines between file block open and the next delimiter are collected as evidence.
