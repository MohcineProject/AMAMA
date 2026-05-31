"""
Volatility 3 plugin runner.

Two modes:

  run_all_plugins(image_path) — production path. Shells out to the local
      Volatility 3 install at VOL3_PATH (configurable via env VOL3_PATH) and
      parses the TSV output of each plugin.

  load_from_folder(folder)   — development path. Reads pre-computed Vol3 CLI
      TSV files from a folder. Lets the rest of the pipeline iterate quickly
      against captured outputs without re-running Vol3 (each run is 15–60 min).

Both modes return an AllRawData container.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Local Vol3 install — overridable via env, but the project default matches
# the path documented in the root CLAUDE.md.
# ---------------------------------------------------------------------------

VOL3_PATH = os.environ.get(
    "VOL3_PATH", "/home/MyTools/volatility/volatility3/vol.py"
)
PYTHON = os.environ.get("VOL3_PYTHON", "python3")


# ---------------------------------------------------------------------------
# Plugin → TSV-filename map for --from-folder mode.
# Matches the filenames produced by run_fast_plugins.sh in the test folders.
# ---------------------------------------------------------------------------

PLUGIN_TO_FILENAME = {
    "windows.pstree.PsTree": "pstree.txt",
    "windows.psscan.PsScan": "psscan.txt",
    "windows.cmdline.CmdLine": "cmdline.txt",
    "windows.dlllist.DllList": "dlllist.txt",
    "windows.handles.Handles": "handles.txt",
    "windows.privileges.Privs": "privileges.txt",
    "windows.netscan.NetScan": "netscan.txt",
    "windows.netstat.NetStat": "netstat.txt",
    "windows.getsids.GetSIDs": "getsids.txt",
}


# ---------------------------------------------------------------------------
# Raw data containers
# ---------------------------------------------------------------------------

@dataclass
class RawProcess:
    pid: int
    ppid: int
    image: str            # ImageFileName (Vol3 truncates to 14 chars)
    path: str             # Win32 path from pstree 'Path' column (may be empty)
    device_path: str      # Device path from pstree 'Audit' column (may be empty)
    cmd: str              # Command line from pstree 'Cmd' column (may be empty)
    wow64: bool
    session: Optional[int]
    threads: int
    create_time: str
    exit_time: str
    discovered_via: str   # "pstree" or "psscan"


@dataclass
class RawDll:
    pid: int
    name: str
    path: str
    load_time: str


@dataclass
class RawHandle:
    pid: int
    type: str
    name: str


@dataclass
class RawPrivilege:
    pid: int
    privilege: str
    attributes: str


@dataclass
class RawNetEvent:
    pid: int
    proto: str
    local_addr: str
    local_port: str
    foreign_addr: str
    foreign_port: str
    state: str
    source: str  # "netscan" or "netstat"


@dataclass
class RawSid:
    pid: int
    sid: str
    name: str


@dataclass
class AllRawData:
    processes: list[RawProcess] = field(default_factory=list)
    dlls: list[RawDll] = field(default_factory=list)
    handles: list[RawHandle] = field(default_factory=list)
    privileges: list[RawPrivilege] = field(default_factory=list)
    net_events: list[RawNetEvent] = field(default_factory=list)
    sids: list[RawSid] = field(default_factory=list)


# ---------------------------------------------------------------------------
# TSV parser
# ---------------------------------------------------------------------------

def parse_tsv(text: str) -> tuple[list[str], list[dict[str, str]]]:
    """
    Parse Volatility 3 CLI TSV output.

    Layout:
      line 1: 'Volatility 3 Framework X.Y.Z'
      line 2: blank
      line 3: tab-separated header
      line 4: blank
      line 5+: tab-separated data rows

    Some plugins also emit FutureWarning lines at the top before the banner —
    we tolerate that by skipping until we find the banner.

    Returns (columns, rows) where rows are dicts keyed by column name. Ragged
    rows are right-padded with empty strings. Empty/missing cells stay as ''.
    """
    raw_lines = text.splitlines()

    banner_idx = -1
    for i, line in enumerate(raw_lines):
        if line.startswith("Volatility 3 Framework"):
            banner_idx = i
            break
    if banner_idx < 0:
        log.warning("parse_tsv: no Volatility banner found; assuming the first non-empty line is the header")
        for i, line in enumerate(raw_lines):
            if line.strip():
                banner_idx = i - 1
                break
        if banner_idx < 0:
            return [], []

    # Header is the next non-empty line after the banner.
    header_idx = -1
    for j in range(banner_idx + 1, len(raw_lines)):
        if raw_lines[j].strip():
            header_idx = j
            break
    if header_idx < 0:
        return [], []

    columns = raw_lines[header_idx].split("\t")
    rows: list[dict[str, str]] = []
    for line in raw_lines[header_idx + 1:]:
        if not line.strip():
            continue
        cells = line.split("\t")
        if len(cells) < len(columns):
            cells = cells + [""] * (len(columns) - len(cells))
        elif len(cells) > len(columns):
            # Excess cells — join the tail into the last column to preserve data.
            tail = "\t".join(cells[len(columns) - 1:])
            cells = cells[: len(columns) - 1] + [tail]
        rows.append({columns[k]: cells[k] for k in range(len(columns))})

    return columns, rows


# Strip the "* " depth markers that pstree prepends to the PID column.
def _strip_pstree_prefix(pid_cell: str) -> str:
    return pid_cell.lstrip("* ").strip()


def _parse_bool(s: str) -> bool:
    return str(s).strip().lower() in ("true", "1", "yes")


def _parse_int(s: str, default: int = 0) -> int:
    s = (s or "").strip()
    if not s or s == "-" or s == "N/A":
        return default
    try:
        return int(s)
    except ValueError:
        return default


def _parse_session(s: str) -> Optional[int]:
    s = (s or "").strip()
    if not s or s in ("N/A", "-"):
        return None
    try:
        return int(s)
    except ValueError:
        return None


def _clean_exit_time(s: str) -> str:
    """Vol3 prints 'N/A' for processes that are still running. Normalize to ''."""
    s = (s or "").strip()
    if s in ("N/A", "-"):
        return ""
    return s


# ---------------------------------------------------------------------------
# Subprocess runner
# ---------------------------------------------------------------------------

def _run_vol_plugin(image_path: str, plugin: str, timeout: int = 3600) -> Optional[str]:
    """
    Run `python vol.py -q -f image plugin` and return stdout. Returns None on
    failure (caller continues with empty rows for that plugin).
    """
    if not Path(VOL3_PATH).exists():
        raise FileNotFoundError(
            f"Volatility 3 not found at: {VOL3_PATH}\n\n"
            "To fix:\n"
            "  export VOL3_PATH=/path/to/volatility3/vol.py\n\n"
            "vol.py lives in the root of your Volatility 3 install directory.\n"
            "Example paths:\n"
            "  /opt/volatility3/vol.py\n"
            "  /home/<user>/tools/volatility3/vol.py\n"
            "  /usr/local/volatility3/vol.py"
        )

    cmd = [PYTHON, VOL3_PATH, "-q", "-f", image_path, plugin]
    log.info("Running plugin %s ...", plugin)
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log.error("Plugin %s timed out after %d s", plugin, timeout)
        return None
    elapsed = time.monotonic() - t0
    if proc.returncode != 0:
        log.warning(
            "Plugin %s exited %d (%.1f s); stderr tail: %s",
            plugin, proc.returncode, elapsed,
            (proc.stderr or "")[-500:].strip(),
        )
        # Some plugins emit data on stdout AND non-zero exit; try to parse anyway.
        if not proc.stdout:
            return None
    else:
        log.info("Plugin %s done in %.1f s", plugin, elapsed)
    return proc.stdout


# ---------------------------------------------------------------------------
# Row → dataclass converters (shared by both modes)
# ---------------------------------------------------------------------------

def _pstree_row_to_raw(row: dict[str, str]) -> Optional[RawProcess]:
    pid_s = _strip_pstree_prefix(row.get("PID", ""))
    if not pid_s.isdigit():
        return None
    return RawProcess(
        pid=int(pid_s),
        ppid=_parse_int(row.get("PPID", "")),
        image=row.get("ImageFileName", "").strip(),
        path=_clean_path_cell(row.get("Path", "")),
        device_path=row.get("Audit", "").strip(),
        cmd=_clean_cmd_cell(row.get("Cmd", "")),
        wow64=_parse_bool(row.get("Wow64", "False")),
        session=_parse_session(row.get("SessionId", "")),
        threads=_parse_int(row.get("Threads", "0")),
        create_time=row.get("CreateTime", "").strip(),
        exit_time=_clean_exit_time(row.get("ExitTime", "")),
        discovered_via="pstree",
    )


def _psscan_row_to_raw(row: dict[str, str]) -> Optional[RawProcess]:
    # psscan has no Path/Cmd/Audit; we leave them empty and let merge fill cmd
    # from the cmdline plugin.
    pid_s = (row.get("PID", "") or "").strip()
    if not pid_s.isdigit():
        return None
    return RawProcess(
        pid=int(pid_s),
        ppid=_parse_int(row.get("PPID", "")),
        image=row.get("ImageFileName", "").strip(),
        path="",
        device_path="",
        cmd="",
        wow64=_parse_bool(row.get("Wow64", "False")),
        session=_parse_session(row.get("SessionId", "")),
        threads=_parse_int(row.get("Threads", "0")),
        create_time=row.get("CreateTime", "").strip(),
        exit_time=_clean_exit_time(row.get("ExitTime", "")),
        discovered_via="psscan",
    )


def _clean_path_cell(s: str) -> str:
    """pstree prints '-' when Path is unavailable. Normalize to empty.

    Also converts NT-namespace path aliases to Win32 form:
      \\SystemRoot\\  →  C:\\Windows\\
    This affects early-boot processes (smss.exe) whose Win32 path isn't
    resolved yet when pstree records them.
    """
    s = (s or "").strip()
    if s in ("-", "N/A"):
        return ""
    if s.lower().startswith("\\systemroot\\"):
        s = "C:\\Windows" + s[len("\\SystemRoot"):]
    return s


def _clean_cmd_cell(s: str) -> str:
    """pstree prints '-' when Cmd is unavailable. Normalize to empty."""
    s = (s or "").strip()
    if s in ("-", "N/A"):
        return ""
    return s


def _dlllist_row_to_raw(row: dict[str, str]) -> Optional[RawDll]:
    pid_s = (row.get("PID", "") or "").strip()
    if not pid_s.isdigit():
        return None
    return RawDll(
        pid=int(pid_s),
        name=row.get("Name", "").strip(),
        path=row.get("Path", "").strip(),
        load_time=row.get("LoadTime", "").strip(),
    )


def _handles_row_to_raw(row: dict[str, str]) -> Optional[RawHandle]:
    pid_s = (row.get("PID", "") or "").strip()
    if not pid_s.isdigit():
        return None
    htype = row.get("Type", "").strip()
    name = row.get("Name", "").strip()
    if not htype and not name:
        return None
    return RawHandle(pid=int(pid_s), type=htype, name=name)


def _privs_row_to_raw(row: dict[str, str]) -> Optional[RawPrivilege]:
    pid_s = (row.get("PID", "") or "").strip()
    if not pid_s.isdigit():
        return None
    priv = row.get("Privilege", "").strip()
    if not priv:
        return None
    return RawPrivilege(
        pid=int(pid_s),
        privilege=priv,
        attributes=row.get("Attributes", "").strip(),
    )


def _net_row_to_raw(row: dict[str, str], source: str) -> Optional[RawNetEvent]:
    pid_s = (row.get("PID", "") or "").strip()
    if not pid_s.isdigit():
        return None
    return RawNetEvent(
        pid=int(pid_s),
        proto=row.get("Proto", "").strip(),
        local_addr=row.get("LocalAddr", "").strip(),
        local_port=str(row.get("LocalPort", "")).strip(),
        foreign_addr=row.get("ForeignAddr", "").strip(),
        foreign_port=str(row.get("ForeignPort", "")).strip(),
        state=row.get("State", "").strip(),
        source=source,
    )


def _sid_row_to_raw(row: dict[str, str]) -> Optional[RawSid]:
    pid_s = (row.get("PID", "") or "").strip()
    if not pid_s.isdigit():
        return None
    sid = row.get("SID", "").strip()
    if not sid:
        return None
    return RawSid(
        pid=int(pid_s),
        sid=sid,
        name=row.get("Name", "").strip(),
    )


# ---------------------------------------------------------------------------
# Mode 1: run Vol3 against a live RAM dump
# ---------------------------------------------------------------------------

def run_all_plugins(image_path: str, include_handles: bool = True) -> AllRawData:
    """
    Run the 9 Volatility plugins via subprocess and return the aggregated rows.

    Per-plugin failures log a warning and contribute an empty list rather than
    aborting the whole collection.

    Args:
        image_path:      absolute path to the memory image.
        include_handles: if False, skip windows.handles.Handles entirely
                         (it's the heaviest plugin and easily doubles wall time).
    """
    image_path = str(Path(image_path).expanduser().resolve())
    if not Path(image_path).exists():
        raise FileNotFoundError(f"Memory image not found: {image_path}")
    if not Path(VOL3_PATH).exists():
        raise FileNotFoundError(
            f"Volatility 3 not found at: {VOL3_PATH}\n\n"
            "To fix:\n"
            "  export VOL3_PATH=/path/to/volatility3/vol.py\n\n"
            "vol.py lives in the root of your Volatility 3 install directory.\n"
            "Example paths:\n"
            "  /opt/volatility3/vol.py\n"
            "  /home/<user>/tools/volatility3/vol.py\n"
            "  /usr/local/volatility3/vol.py"
        )

    raw = AllRawData()

    # processes: pstree primary (carries Path/Cmd/Audit), psscan supplemental.
    raw.processes.extend(_collect_processes_from_vol(image_path))

    # cmdline — fallback for processes whose pstree Cmd is empty.
    cmdline_by_pid = _collect_cmdline_from_vol(image_path)
    _fill_missing_cmds(raw.processes, cmdline_by_pid)

    raw.dlls = _collect_plugin_rows(
        image_path, "windows.dlllist.DllList", _dlllist_row_to_raw
    )

    if include_handles:
        raw.handles = _collect_plugin_rows(
            image_path, "windows.handles.Handles", _handles_row_to_raw
        )
    else:
        log.info("Skipping windows.handles.Handles (--no-handles)")

    raw.privileges = _collect_plugin_rows(
        image_path, "windows.privileges.Privs", _privs_row_to_raw
    )

    raw.net_events = (
        _collect_plugin_rows(
            image_path, "windows.netscan.NetScan",
            lambda r: _net_row_to_raw(r, source="netscan"),
        )
        + _collect_plugin_rows(
            image_path, "windows.netstat.NetStat",
            lambda r: _net_row_to_raw(r, source="netstat"),
        )
    )

    raw.sids = _collect_plugin_rows(
        image_path, "windows.getsids.GetSIDs", _sid_row_to_raw
    )

    return raw


def _collect_processes_from_vol(image_path: str) -> list[RawProcess]:
    out = _run_vol_plugin(image_path, "windows.pstree.PsTree")
    pstree_rows: list[RawProcess] = []
    if out:
        _, rows = parse_tsv(out)
        for row in rows:
            r = _pstree_row_to_raw(row)
            if r is not None:
                pstree_rows.append(r)
    log.info("pstree: %d processes", len(pstree_rows))

    out = _run_vol_plugin(image_path, "windows.psscan.PsScan")
    psscan_rows: list[RawProcess] = []
    if out:
        _, rows = parse_tsv(out)
        for row in rows:
            r = _psscan_row_to_raw(row)
            if r is not None:
                psscan_rows.append(r)
    log.info("psscan: %d processes", len(psscan_rows))

    return _union_process_lists(pstree_rows, psscan_rows)


def _union_process_lists(
    primary: list[RawProcess], secondary: list[RawProcess]
) -> list[RawProcess]:
    """Primary (pstree) wins on conflict. Secondary contributes new PIDs only."""
    seen: set[int] = set()
    merged: list[RawProcess] = []
    for p in primary:
        if p.pid in seen:
            continue
        seen.add(p.pid)
        merged.append(p)
    for p in secondary:
        if p.pid in seen:
            continue
        seen.add(p.pid)
        merged.append(p)
    return merged


def _collect_cmdline_from_vol(image_path: str) -> dict[int, str]:
    out = _run_vol_plugin(image_path, "windows.cmdline.CmdLine")
    return _parse_cmdline_tsv(out or "")


def _parse_cmdline_tsv(text: str) -> dict[int, str]:
    by_pid: dict[int, str] = {}
    if not text:
        return by_pid
    _, rows = parse_tsv(text)
    for row in rows:
        pid_s = (row.get("PID", "") or "").strip()
        if not pid_s.isdigit():
            continue
        args = row.get("Args", "").strip()
        if args in ("", "-", "N/A"):
            continue
        by_pid[int(pid_s)] = args
    return by_pid


def _fill_missing_cmds(processes: list[RawProcess], cmdline_by_pid: dict[int, str]) -> None:
    """In-place: populate empty cmd fields from the cmdline plugin."""
    filled = 0
    for p in processes:
        if p.cmd:
            continue
        cmd = cmdline_by_pid.get(p.pid)
        if cmd:
            p.cmd = cmd
            filled += 1
    if filled:
        log.info("cmdline: filled cmd for %d additional processes", filled)


def _collect_plugin_rows(image_path: str, plugin: str, row_converter):
    out = _run_vol_plugin(image_path, plugin)
    if not out:
        return []
    _, rows = parse_tsv(out)
    converted = []
    for row in rows:
        r = row_converter(row)
        if r is not None:
            converted.append(r)
    log.info("%s: %d rows", plugin, len(converted))
    return converted


# ---------------------------------------------------------------------------
# Mode 2: load from a pre-computed analysis folder
# ---------------------------------------------------------------------------

def load_from_folder(folder: str | Path, *, include_handles: bool = True) -> AllRawData:
    """
    Build AllRawData from a folder of pre-computed Volatility CLI TSV files.

    Filenames matched (case-sensitive, lowercase): pstree.txt, psscan.txt,
    cmdline.txt, dlllist.txt, handles.txt, privileges.txt, netscan.txt,
    netstat.txt, getsids.txt. Missing files log a warning and contribute zero
    rows for that plugin.

    This is the development shortcut — production runs use run_all_plugins().
    """
    folder = Path(folder).expanduser().resolve()
    if not folder.is_dir():
        raise FileNotFoundError(f"Analysis folder not found: {folder}")

    raw = AllRawData()

    pstree_text = _read_file_or_none(folder / "pstree.txt")
    pstree_rows: list[RawProcess] = []
    if pstree_text:
        _, rows = parse_tsv(pstree_text)
        for row in rows:
            r = _pstree_row_to_raw(row)
            if r is not None:
                pstree_rows.append(r)
    log.info("pstree.txt: %d processes", len(pstree_rows))

    psscan_text = _read_file_or_none(folder / "psscan.txt")
    psscan_rows: list[RawProcess] = []
    if psscan_text:
        _, rows = parse_tsv(psscan_text)
        for row in rows:
            r = _psscan_row_to_raw(row)
            if r is not None:
                psscan_rows.append(r)
    log.info("psscan.txt: %d processes", len(psscan_rows))

    raw.processes = _union_process_lists(pstree_rows, psscan_rows)

    cmdline_text = _read_file_or_none(folder / "cmdline.txt")
    cmdline_by_pid = _parse_cmdline_tsv(cmdline_text or "")
    log.info("cmdline.txt: %d cmd entries", len(cmdline_by_pid))
    _fill_missing_cmds(raw.processes, cmdline_by_pid)

    raw.dlls = _parse_file_or_empty(folder / "dlllist.txt", _dlllist_row_to_raw, "dlllist.txt")
    if include_handles:
        raw.handles = _parse_file_or_empty(folder / "handles.txt", _handles_row_to_raw, "handles.txt")
    else:
        log.info("Handles skipped (--no-handles).")
    raw.privileges = _parse_file_or_empty(folder / "privileges.txt", _privs_row_to_raw, "privileges.txt")

    netscan_events = _parse_file_or_empty(
        folder / "netscan.txt", lambda r: _net_row_to_raw(r, source="netscan"), "netscan.txt"
    )
    netstat_events = _parse_file_or_empty(
        folder / "netstat.txt", lambda r: _net_row_to_raw(r, source="netstat"), "netstat.txt"
    )
    raw.net_events = netscan_events + netstat_events

    raw.sids = _parse_file_or_empty(folder / "getsids.txt", _sid_row_to_raw, "getsids.txt")

    return raw


def _read_file_or_none(path: Path) -> Optional[str]:
    if not path.exists():
        log.warning("Missing file in --from-folder source: %s", path.name)
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def _parse_file_or_empty(path: Path, row_converter, label: str) -> list:
    text = _read_file_or_none(path)
    if not text:
        return []
    _, rows = parse_tsv(text)
    converted = []
    for row in rows:
        r = row_converter(row)
        if r is not None:
            converted.append(r)
    log.info("%s: %d rows", label, len(converted))
    return converted


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------

def vol3_available() -> bool:
    """True if VOL3_PATH points at an existing vol.py file and python is on PATH."""
    return Path(VOL3_PATH).exists() and shutil.which(PYTHON) is not None
