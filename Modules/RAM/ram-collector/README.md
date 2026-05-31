# collector — FIND_EVIL Volatility 3 Process Collector

Runs Volatility 3 plugins against a Windows memory image, applies exclusion
rules for known-benign system processes, and emits the surviving processes as
DFS-ordered, **subtree-safe** chunks sized for an LLM context window. Output is
written as `chunk_NNN.txt` files ready to feed to the FIND_EVIL triage agent
(Agent 1).

Each chunk preserves the parent-child hierarchy: a parent process and **all**
its descendants always live in the same chunk, so Agent 1 never sees a child
without its parent's context.

---

## Status

This package is an early draft. The Volatility 3 integration in
`collector/vol3_runner.py` has been written against documented column names but
has not been exhaustively validated against every Vol3 build in the wild. If
you hit a column-name mismatch, run with `--log-level DEBUG` and report the
plugin + offending header — it's a single-line fix per plugin.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Python 3.10+ | Used by the collector itself |
| Volatility 3 | Must be installed somewhere accessible (the collector shells out to `vol.py`) |
| Memory image | Raw `.elf`, `.img`, `.vmem`, or any format Vol3 accepts |
| `tiktoken` *(optional)* | Accurate token estimates for chunk sizing. Without it, a `char/4` approximation is used |

The collector has **no mandatory runtime Python dependencies** — Vol3 is
invoked via subprocess, not imported.

---

## Installation

### Step 1 — Locate your Volatility 3 install

The collector shells out to `vol.py` directly. Find it:

```bash
which vol.py 2>/dev/null || find / -name "vol.py" -path "*/volatility3/*" 2>/dev/null | head -3
```

On the SIFT VM it lives at:

```
/home/MyTools/volatility/volatility3/vol.py
```

If your `vol.py` is elsewhere, point the collector at it in one of two ways:

**Option A — environment variables (recommended, no code edits):**

```bash
export VOL3_PATH=/path/to/your/vol.py
export VOL3_PYTHON=python3      # optional, default: python3
```

**Option B — edit the constants** at the top of `collector/vol3_runner.py`:

```python
VOL3_PATH = "/path/to/your/vol.py"
PYTHON    = "python3"
```

### Step 2 — Activate a Python environment

The collector must run in a Python environment that can also call `vol.py`.
On the SIFT VM, Volatility ships with its own venv:

```bash
source /home/MyTools/volatility/volatility3/venv/bin/activate
```

A plain user virtualenv works equally well — the collector does **not** import
Volatility, it shells out to it.

### Step 3 — Install the collector package

```bash
# From the repo root (the folder containing pyproject.toml):
pip install -e .
```

Verify the install:

```bash
python -m collector --help
```

### Step 4 *(optional)* — Install tiktoken for accurate token counts

```bash
pip install tiktoken
# or, via the extras declared in pyproject.toml:
pip install -e .[fast]
```

Without `tiktoken`, the chunker falls back to a `len(text) / 4` heuristic. That
is fine for rough budgeting but will under- or over-shoot the real token count
by up to ~20% depending on the data.

---

## Quick Start — run against a RAM dump

```bash
python -m collector \
  --image /path/to/dump.elf \
  --output-dir ./OUTPUT_OF_COLLECTOR \
  --log-level INFO
```

This runs all Volatility plugins sequentially. **Expect 15–60 minutes** for a
large image (8+ GB). The `windows.handles` plugin is the slowest.

**If chunk sizes are too large** (handles inflate lines significantly):

```bash
python -m collector \
  --image /path/to/dump.elf \
  --output-dir ./OUTPUT_OF_COLLECTOR \
  --no-handles \
  --log-level INFO
```

`--no-handles` skips `windows.handles` and typically reduces output by 70–80%.

### Inspecting the output

```bash
ls OUTPUT_OF_COLLECTOR/
# → chunk_001.txt  chunk_002.txt  ...

head -3 OUTPUT_OF_COLLECTOR/chunk_001.txt
# → # FIND_EVIL Collector — /path/to/dump.elf — 2026-05-16T...
# → pid=4 ppid=0 name=System path= cmd="" start=...
# → pid=468 ppid=4 name=explorer.exe path=C:\Windows\explorer.exe ...
```

Each line is one process. Files are safe to feed directly to Agent 1.

---

## Development mode — skip the slow Vol3 run

If you already have Volatility output files (from a previous run or a shared
analysis folder), use `--from-folder` to skip the slow Vol3 step entirely:

```bash
python -m collector \
  --from-folder /path/to/analysis_folder \
  --output-dir /tmp/test_chunks \
  --log-level INFO
```

The folder must contain TSV files named **exactly** as listed below. Missing
files log a `WARNING` and contribute zero rows — the pipeline continues.

| Filename | Plugin | Required? |
|----------|--------|-----------|
| `pstree.txt` | `windows.pstree.PsTree` | **Required** |
| `psscan.txt` | `windows.psscan.PsScan` | **Required** |
| `cmdline.txt` | `windows.cmdline.CmdLine` | Recommended |
| `dlllist.txt` | `windows.dlllist.DllList` | Recommended |
| `privileges.txt` | `windows.privileges.Privs` | Recommended |
| `netscan.txt` | `windows.netscan.NetScan` | Optional (often empty on ELF dumps) |
| `netstat.txt` | `windows.netstat.NetStat` | Recommended (merged with netscan) |
| `handles.txt` | `windows.handles.Handles` | Optional (large; use `--no-handles` to skip) |
| `getsids.txt` | `windows.getsids.GetSIDs` | Optional |

### Generating these TSV files manually

```bash
VOL3="python3 /home/MyTools/volatility/volatility3/vol.py"
IMAGE="/path/to/dump.elf"
OUT="/path/to/analysis_folder"
mkdir -p "$OUT"

$VOL3 -q -f "$IMAGE" windows.pstree.PsTree    > "$OUT/pstree.txt"
$VOL3 -q -f "$IMAGE" windows.psscan.PsScan    > "$OUT/psscan.txt"
$VOL3 -q -f "$IMAGE" windows.cmdline.CmdLine  > "$OUT/cmdline.txt"
$VOL3 -q -f "$IMAGE" windows.dlllist.DllList  > "$OUT/dlllist.txt"
$VOL3 -q -f "$IMAGE" windows.privileges.Privs > "$OUT/privileges.txt"
$VOL3 -q -f "$IMAGE" windows.netscan.NetScan  > "$OUT/netscan.txt"
$VOL3 -q -f "$IMAGE" windows.netstat.NetStat  > "$OUT/netstat.txt"
$VOL3 -q -f "$IMAGE" windows.handles.Handles  > "$OUT/handles.txt"  # slow
$VOL3 -q -f "$IMAGE" windows.getsids.GetSIDs  > "$OUT/getsids.txt"
```

---

## Full CLI reference

```
python -m collector (--image PATH | --from-folder DIR) [OPTIONS]

Mode (exactly one required):
  --image PATH          Run Volatility 3 against a RAM dump (production; slow).
  --from-folder DIR     Read pre-computed Volatility TSV files from DIR (dev shortcut).

Output:
  --output-dir DIR      Output folder (default: ./OUTPUT_OF_COLLECTOR).
  --force               Overwrite the output directory if it already exists and is non-empty.

Tuning:
  --max-tokens N        Token budget per chunk (default: 8000).
  --no-handles          Skip the windows.handles plugin (greatly reduces chunk sizes;
                        useful on dumps where the handles table is ~49K rows).

Diagnostics:
  --log-level LEVEL     DEBUG | INFO | WARNING | ERROR  (default: INFO)
```

A `collector` console script is also installed by `pip install -e .`, so
`collector --image ...` works identically to `python -m collector --image ...`.

---

## Python API

```python
from collector import run_collector

n_chunks = run_collector(
    image_path="/path/to/dump.elf",   # or: folder_path="/path/to/analysis_folder"
    output_dir="./OUTPUT_OF_COLLECTOR",
    max_chunk_tokens=8000,
    include_handles=True,
    force=False,
)
print(f"{n_chunks} chunk file(s) written.")
```

**Arguments**

| Arg | Default | Notes |
|-----|---------|-------|
| `image_path` | — | Path to Windows memory image. Runs Vol3 via subprocess. Mutually exclusive with `folder_path`. |
| `folder_path` | — | Path to folder of pre-computed TSV files. Mutually exclusive with `image_path`. |
| `output_dir` | `./OUTPUT_OF_COLLECTOR` | Where `chunk_NNN.txt` files are written. |
| `max_chunk_tokens` | `8000` | Token budget per chunk. |
| `include_handles` | `True` | Set `False` to shrink chunks for large dumps. |
| `force` | `False` | Overwrite a non-empty `output_dir` instead of raising. |

**Returns:** number of chunk files written.

**Raises:**
- `ValueError` — neither or both of `image_path` / `folder_path` were given.
- `FileNotFoundError` — `image_path` or `folder_path` does not exist.
- `FileExistsError` — `output_dir` exists, is non-empty, and `force=False`.

---

## Output Format

### Chunk headers

The first chunk starts with a full header:

```
# FIND_EVIL Collector — /path/to/dump.elf — 2026-05-16T10:23:45+00:00
{lines...}
```

Subsequent chunks use a short header:

```
# CHUNK 2/5
{lines...}
```

### Line format (one line per process)

```
{indent}pid=N ppid=N [discovered_via=psscan] name=X path=X cmd="..." start=T [end=T] dlls=A;B;... nets=proto|laddr|lport|faddr|fport|state;... sids=SID|name;... privs=priv|attrs;... handles=type|name;...
```

- **`indent`** — 2 spaces × DFS depth (renders the parent → child hierarchy visually).
- **`cmd`** — JSON-encoded string (quotes included, special chars / newlines escaped).
- **`discovered_via=psscan`** — present **only** for processes seen by `psscan` but missing from `pstree` (hidden / DKOM candidates).
- **`end=T`** — present **only** for terminated processes.
- **`dlls`** — semicolon-separated full DLL paths.
- **`nets`** — semicolon-separated `proto|laddr|lport|faddr|fport|state` per connection.
- **`sids`** — semicolon-separated `SID|name` pairs.
- **`privs`** — semicolon-separated `PrivilegeName|Attributes` pairs.
- **`handles`** — semicolon-separated `Type|Name` pairs.

List fields use `;` between items and `|` between sub-fields within an item.

---

## Chunk-Safety Invariant

A parent process and **all** its descendants always appear in the same chunk.
Chunk boundaries only occur between root-level subtrees in the process forest.
This guarantees Agent 1 never sees a child process without its parent's
context.

---

## Excluded Processes

The collector applies 21 exclusion rules for known-benign Windows system
processes — they are stripped before chunking so Agent 1's context is spent on
interesting candidates:

`System`, `MemCompression`, `smss.exe` (root + transient copies), `csrss.exe`,
`wininit.exe`, `winlogon.exe`, `services.exe`, `lsass.exe` (with no children),
`svchost.exe` (running + terminated, with `-k` flag, session 0),
`fontdrvhost.exe`, `dwm.exe`, `LogonUI.exe`, `spoolsv.exe`, `msdtc.exe`,
`SearchIndexer.exe`, `WmiPrvSE.exe`, `unsecapp.exe`, `dllhost.exe` (with GUID),
`conhost.exe`.

### What voids the exclusion (the process is kept for triage)

Any of the following defeats the rule, regardless of which one matched:

- Executable path outside the expected directory.
- `WoW64 = True` (32-bit process on 64-bit host).
- Unexpected parent process.
- Unexpected child processes (critical for `lsass.exe`).
- Too many simultaneous instances.
- Process still alive when the rule requires it to have exited.

A `svchost.exe` without `-k`, from the wrong path, with `WoW64=True`, or with
too many instances is **kept** and sent to Agent 1 for triage.

---

## Performance Notes

- **Collection** — running all 8 Volatility plugins on a large image (8+ GB)
  can take 15–60 minutes. The handles plugin dominates.
- **Memory** — all process lines are materialized in memory before chunking.
  For typical Windows images (200–400 processes after exclusions), expect
  50–500 MB resident depending on handle list sizes.
- **Chunking** — chunks are yielded lazily internally; with the file writer
  the consumer can start processing `chunk_001.txt` while later chunks are
  still being formatted.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `FileNotFoundError: vol.py not found` | Wrong `VOL3_PATH` | `export VOL3_PATH=...` or edit the constant in `collector/vol3_runner.py` |
| `0 processes found` | `pstree` parse failed | Re-run with `--log-level DEBUG` and check the TSV column headers |
| `No chunks written` | All processes excluded | Unlikely — inspect the DEBUG log for path-matching issues |
| Chunks very large | Handles enabled on a big dump | Add `--no-handles` |
| Token budget warnings | `tiktoken` not installed | `pip install tiktoken` (or `pip install -e .[fast]`) |
| `FileExistsError` on output dir | Prior run left files in `--output-dir` | Add `--force` to overwrite |
| Slow Vol3 run | Handles plugin on a large image | Use `--no-handles`, or pre-generate TSVs and use `--from-folder` |
