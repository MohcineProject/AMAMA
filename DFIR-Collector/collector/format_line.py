"""
format_line.py — Render a ProcessRecord as a single line of text.

Confidence: MEDIUM
The field names and separators are MY DESIGN — there is no canonical "ideas:21"
document available at the time of writing. The executing agent MUST review this
format against what Agent 1 actually expects and update accordingly.

!!! NEEDS REVIEW: LINE FORMAT !!!
Current format (designed from input.json schema, not a canonical spec):

  {indent}pid={N} ppid={N} name={X} path={X} cmd={JSON} start={T} [end={T}] dlls={A;B;...} nets={proto|laddr|lport|faddr|fport|state;...} sids={SID|name;...} privs={name|attrs;...} handles={type|name;...}

Design decisions and their rationale:
1. SEPARATOR CHOICE: `;` within a field (between list items), `|` within a list
   item (between sub-fields). Rationale: paths contain spaces and backslashes,
   IPs contain dots/colons, so we need separators that don't appear in data.
   RISK: pipe `|` appears in some Windows mutex/event names. If this causes
   parse errors, switch handles to a different separator.

2. CMD ENCODING: JSON-encoded (json.dumps) to ensure single-line output.
   Rationale: cmdlines can contain quotes, backslashes, and even newlines in
   rare cases. JSON encoding escapes all of these safely.

3. INDENT: 2 spaces per depth level, prepended to the entire line.
   Rationale: matches building plan spec exactly.

4. EMPTY FIELDS: Always emitted as `key=` (empty string after =).
   Rationale: the consumer (Agent 1) can rely on the key always being present;
   it doesn't have to handle missing keys vs. empty values differently.

5. HANDLES: Included as a full list despite potentially being very long.
   Rationale: building plan says "full handles, no cap". A process with 5000+
   handles will produce a very long line that may be emitted as a solo chunk.
   NEEDS REVIEW: consider filtering handles by type (File, Key, Event only) to
   reduce noise. Not done here to match the spec.

6. DATETIME FORMAT: We output the raw string from Volatility (e.g.
   "2024-01-15 10:23:45.000000 UTC") rather than parsing it.
   Rationale: avoids introducing parse errors on unknown date formats.
   NEEDS TESTING: confirm what format Volatility actually returns.
"""

from __future__ import annotations

import json
import logging

from .merge import ProcessRecord

log = logging.getLogger(__name__)

INDENT_UNIT = "  "  # 2 spaces per depth level


def format_process_line(node_depth: int, record: ProcessRecord) -> str:
    """
    Return a single newline-terminated line representing the process.

    The line is guaranteed to contain no embedded newlines (cmd is JSON-encoded).
    """
    indent = INDENT_UNIT * node_depth

    # Encode command line as a JSON string to escape newlines and special chars.
    # json.dumps includes the surrounding quotes, e.g. '"cmd here"'.
    cmd_encoded = json.dumps(record.cmd or "")

    # Build list fields — each uses `;` between items.
    dlls_str = _encode_list(record.dlls)
    nets_str = _encode_list([str(n) for n in record.nets])
    sids_str = _encode_list([str(s) for s in record.sids])
    privs_str = _encode_list(record.privs)
    handles_str = _encode_list(record.handles)

    # Time fields
    start_str = _clean_time(record.create_time)
    end_part = f" end={_clean_time(record.exit_time)}" if not record.is_alive else ""

    via_tag = "discovered_via=psscan " if record.discovered_via == "psscan" else ""

    line = (
        f"{indent}"
        f"pid={record.pid} "
        f"ppid={record.ppid} "
        f"{via_tag}"
        f"name={record.image} "
        f"path={record.path} "
        f"cmd={cmd_encoded} "
        f"start={start_str}"
        f"{end_part} "
        f"dlls={dlls_str} "
        f"nets={nets_str} "
        f"sids={sids_str} "
        f"privs={privs_str} "
        f"handles={handles_str}"
        f"\n"
    )

    # Sanity check: line must not contain embedded newlines (except the trailing one)
    # If cmd encoding somehow failed, catch it here.
    if line.count("\n") > 1:
        log.error(
            "PID %d: formatted line contains embedded newlines — "
            "cmd encoding may have failed. Replacing with escaped version.",
            record.pid
        )
        line = line.replace("\n", "\\n", line.count("\n") - 1)

    return line


def _encode_list(items: list[str]) -> str:
    """Join list items with `;`. Empty items are skipped."""
    return ";".join(item for item in items if item)


def _clean_time(time_str: str) -> str:
    """Strip surrounding whitespace from a Volatility time string."""
    return (time_str or "").strip()
