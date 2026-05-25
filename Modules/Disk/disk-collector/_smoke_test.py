"""Quick smoke test for _common helpers + record round-trip.

Not a real test suite — just catches obvious breakage before handoff.
The full test plan is in Tests_todo.md (executed by the next agent).
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as c  # noqa: E402

failures = []


def check(name, cond, *info):
    if cond:
        print(f"  OK  {name}")
    else:
        print(f"  FAIL {name}: {info}")
        failures.append(name)


# --- format_find_evil_record ---
r = c.format_find_evil_record(
    "file",
    path=r"C:\a b\x.exe",
    entropy=7.5,
    deleted=False,
    empty=None,
    ads="",
)
print(f"record line: {r!r}")
check("type-first",     r.startswith("type=file "))
check("space quoted",   '"C:\\\\a b\\\\x.exe"' in r)
check("bool lowercased", "deleted=false" in r)
check("none dropped",   "empty=" not in r)
check("empty dropped",  "ads=" not in r)

# --- windows_filetime_to_utc ---
check("ft 0 = None", c.windows_filetime_to_utc(0) is None)
dt = c.windows_filetime_to_utc(116444736000000000)
check("ft epoch_diff = 1970-01-01",
      dt is not None and dt.year == 1970 and dt.month == 1 and dt.day == 1, dt)
dt = c.windows_filetime_to_utc(132514560000000000)
check("ft 2021 sanity (year in 2020..2022)",
      dt is not None and 2020 <= dt.year <= 2022, dt)

# --- chrome_webkit_us_to_utc ---
dt = c.chrome_webkit_us_to_utc(13298904000000000)
check("chrome 2022 sanity (year in 2021..2023)",
      dt is not None and 2021 <= dt.year <= 2023, dt)

# --- firefox_unix_us_to_utc ---
dt = c.firefox_unix_us_to_utc(1700000000000000)
check("firefox 2023 sanity (year in 2022..2024)",
      dt is not None and 2022 <= dt.year <= 2024, dt)

# --- round-trip via regex ---
m = re.match(r'^type=(\S+)\s+(.*)$', r)
check("regex round-trip", m is not None and m.group(1) == "file")

# --- to_iso8601 ---
iso = c.to_iso8601(c.windows_filetime_to_utc(132514560000000000))
check("iso8601 format Z-suffixed",
      bool(re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", iso)), iso)

# --- write_records_to_file round-trip ---
import tempfile

records = [
    {"type": "file", "path": "x.exe", "deleted": True},
    {"type": "event", "id": 4624, "user": "alice"},
]
with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
    tmp = f.name
n = c.write_records_to_file(iter(records), tmp)
check("write count", n == 2, n)
with open(tmp) as f:
    lines = [l.rstrip() for l in f if l.strip()]
os.unlink(tmp)
check("two lines emitted", len(lines) == 2, lines)
check("line 0 type=file", lines[0].startswith("type=file"))
check("line 1 type=event", lines[1].startswith("type=event"))
check("event id=4624 present", "id=4624" in lines[1])

# --- pe_analyzer non-PE safety ---
import pe_analyzer as pe  # noqa: E402

result = pe.analyze_path(__file__)  # this .py file is not a PE
check("non-PE returns dict (no exception)", isinstance(result, dict))
check("non-PE has no signature key",
      "signature" not in result, result.get("signature"))

# --- disk_collector orchestrator dry-run with empty config ---
import disk_collector as oc  # noqa: E402

summary = oc.run({"browser": {}}, tempfile.mkdtemp(), ["browser"])
check("orchestrator returns summary dict", isinstance(summary, dict))
check("browser key in summary", "browser" in summary, summary)

if failures:
    print(f"\nFAILURES: {failures}")
    sys.exit(1)
print("\nAll smoke checks passed.")
