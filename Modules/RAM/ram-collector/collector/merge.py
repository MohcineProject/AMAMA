"""
merge.py — Combine AllRawData into per-PID ProcessRecord objects.

Inputs come from vol3_runner.py which now provides:
  - RawProcess.cmd populated (from pstree Cmd, or cmdline fallback)
  - RawProcess.path populated (Win32 form, from pstree Path)
  - RawProcess.device_path populated (from pstree Audit)
  - RawProcess.discovered_via in {"pstree", "psscan"}
  - RawNetEvent.source in {"netscan", "netstat"} — used to prefer netstat's
    State value when both sources report the same tuple.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from .vol3_runner import AllRawData

log = logging.getLogger(__name__)


@dataclass
class NetEvent:
    proto: str
    local_addr: str
    local_port: str
    foreign_addr: str
    foreign_port: str
    state: str

    def __str__(self) -> str:
        return (
            f"{self.proto}|{self.local_addr}|{self.local_port}"
            f"|{self.foreign_addr}|{self.foreign_port}|{self.state}"
        )


@dataclass
class SidEntry:
    sid: str
    name: str

    def __str__(self) -> str:
        return f"{self.sid}|{self.name}"


@dataclass
class ProcessRecord:
    pid: int
    ppid: int
    image: str
    path: str
    device_path: str
    wow64: bool
    session: Optional[int]
    threads: int
    create_time: str
    exit_time: str
    cmd: str
    discovered_via: str = "pstree"
    dlls: list[str] = field(default_factory=list)
    handles: list[str] = field(default_factory=list)
    privs: list[str] = field(default_factory=list)
    nets: list[NetEvent] = field(default_factory=list)
    sids: list[SidEntry] = field(default_factory=list)

    @property
    def is_alive(self) -> bool:
        return not self.exit_time or self.exit_time.strip() in ("", "N/A")

    @property
    def path_lower(self) -> str:
        return self.path.lower()

    @property
    def image_lower(self) -> str:
        return self.image.lower()


def build_records(raw: AllRawData) -> dict[int, ProcessRecord]:
    """Merge all raw plugin data into a dict of ProcessRecord keyed by PID."""

    dlls_by_pid: dict[int, list[str]] = defaultdict(list)
    seen_dll_keys: dict[int, set[str]] = defaultdict(set)
    for dll in raw.dlls:
        key = (dll.path or dll.name).lower()
        if not key or key in seen_dll_keys[dll.pid]:
            continue
        seen_dll_keys[dll.pid].add(key)
        dlls_by_pid[dll.pid].append(dll.path or dll.name)

    handles_by_pid: dict[int, list[str]] = defaultdict(list)
    for h in raw.handles:
        entry = f"{h.type}|{h.name}".rstrip("|")
        if entry:
            handles_by_pid[h.pid].append(entry)

    privs_by_pid: dict[int, list[str]] = defaultdict(list)
    for p in raw.privileges:
        entry = f"{p.privilege}|{p.attributes}".rstrip("|")
        if entry:
            privs_by_pid[p.pid].append(entry)

    # netscan + netstat merge — dedupe by (pid, proto, laddr, lport, faddr, fport).
    # netstat wins on State when both sources report the same connection (netstat
    # is generally more accurate when it works).
    net_index: dict[tuple, NetEvent] = {}
    net_source: dict[tuple, str] = {}
    for n in raw.net_events:
        key = (n.pid, n.proto, n.local_addr, n.local_port, n.foreign_addr, n.foreign_port)
        existing = net_index.get(key)
        if existing is None:
            net_index[key] = NetEvent(
                proto=n.proto,
                local_addr=n.local_addr,
                local_port=n.local_port,
                foreign_addr=n.foreign_addr,
                foreign_port=n.foreign_port,
                state=n.state,
            )
            net_source[key] = n.source
        else:
            # Prefer netstat over netscan for State; otherwise keep first.
            if n.source == "netstat" and net_source.get(key) != "netstat":
                existing.state = n.state or existing.state
                net_source[key] = "netstat"
            elif not existing.state and n.state:
                existing.state = n.state
    nets_by_pid: dict[int, list[NetEvent]] = defaultdict(list)
    for (pid, *_), event in net_index.items():
        nets_by_pid[pid].append(event)

    sids_by_pid: dict[int, list[SidEntry]] = defaultdict(list)
    seen_sid_keys: dict[int, set[str]] = defaultdict(set)
    for s in raw.sids:
        key = s.sid.lower()
        if key in seen_sid_keys[s.pid]:
            continue
        seen_sid_keys[s.pid].add(key)
        sids_by_pid[s.pid].append(SidEntry(sid=s.sid, name=s.name))

    records: dict[int, ProcessRecord] = {}
    seen_pids: set[int] = set()
    for rp in raw.processes:
        if rp.pid in seen_pids:
            continue
        seen_pids.add(rp.pid)

        records[rp.pid] = ProcessRecord(
            pid=rp.pid,
            ppid=rp.ppid,
            image=rp.image,
            path=rp.path,
            device_path=rp.device_path,
            wow64=rp.wow64,
            session=rp.session,
            threads=rp.threads,
            create_time=rp.create_time,
            exit_time=rp.exit_time,
            cmd=rp.cmd,
            discovered_via=rp.discovered_via,
            dlls=list(dlls_by_pid.get(rp.pid, [])),
            handles=list(handles_by_pid.get(rp.pid, [])),
            privs=list(privs_by_pid.get(rp.pid, [])),
            nets=list(nets_by_pid.get(rp.pid, [])),
            sids=list(sids_by_pid.get(rp.pid, [])),
        )

    log.info(
        "merge: %d ProcessRecord objects (%d psscan-only)",
        len(records),
        sum(1 for r in records.values() if r.discovered_via == "psscan"),
    )
    return records
