"""Parse Windows .evtx event logs → type=event FIND_EVIL_DISK records.

Input: a directory containing any of:
  Security.evtx
  System.evtx
  Application.evtx
  Microsoft-Windows-Sysmon%4Operational.evtx  (or aliased Sysmon.evtx)

Output files (in Disk_Artifacts/):
  eventlog_security.txt
  eventlog_system.txt
  eventlog_application.txt
  eventlog_sysmon.txt

Filter: only events with ID in config["high_signal_event_ids"] are kept.
Exception: 1102 (Security log cleared) and 104 (System log cleared) are ALWAYS
emitted — they are anti-forensics signals per HOW_TO_BUILD.md §8.5.

Per-event-ID field extractors live in _EVENT_PARSERS; add more there without
touching the iteration loop.

# UNCERTAIN: XML element names for EventData/Data fields vary across event
# versions and OS builds. The fallback _data_by_name() does a case-insensitive
# attribute lookup and silently returns "" on miss — verify against real evtx
# files in the test phase.
"""
from __future__ import annotations

import itertools
import os
import sys
import xml.etree.ElementTree as ET
from typing import Callable, Dict, Iterator, List, Optional

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _common as _c  # type: ignore
else:
    from . import _common as _c

try:
    from Evtx.Evtx import Evtx  # python-evtx
    _HAS_EVTX = True
except ImportError:
    Evtx = None  # type: ignore
    _HAS_EVTX = False


# Map filename (lowercase) → output bucket + source tag
_LOG_ROUTING = {
    "security.evtx":    ("eventlog_security.txt",    "Security.evtx"),
    "system.evtx":      ("eventlog_system.txt",      "System.evtx"),
    "application.evtx": ("eventlog_application.txt", "Application.evtx"),
    "sysmon.evtx":      ("eventlog_sysmon.txt",      "Sysmon.evtx"),
    "microsoft-windows-sysmon%4operational.evtx": ("eventlog_sysmon.txt", "Sysmon.evtx"),
}


# XML namespace used by Windows event records
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _strip_ns(tag: str) -> str:
    """Remove XML namespace prefix from a tag name."""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _find(parent, ns_path: str, bare_path: str):
    """find() that falls back to bare tag — safe when elements have no children (falsy in ET)."""
    r = parent.find(ns_path, _NS)
    return r if r is not None else parent.find(bare_path)


def _data_by_name(event_data: Optional[ET.Element], name: str) -> str:
    """Lookup <Data Name="X">value</Data> case-insensitively."""
    if event_data is None:
        return ""
    target = name.lower()
    for d in event_data:
        if _strip_ns(d.tag) != "Data":
            continue
        attr = d.attrib.get("Name") or d.attrib.get("name") or ""
        if attr.lower() == target:
            return (d.text or "").strip()
    return ""


def _all_data(event_data: Optional[ET.Element]) -> Dict[str, str]:
    """Flatten EventData into {name: text} for events without named Data fields."""
    out: Dict[str, str] = {}
    if event_data is None:
        return out
    for d in event_data:
        if _strip_ns(d.tag) != "Data":
            continue
        name = d.attrib.get("Name") or d.attrib.get("name") or f"Data{len(out)}"
        out[name] = (d.text or "").strip()
    return out


# -------------------------- Per-event-ID parsers --------------------------

def _parse_4624(data: ET.Element) -> dict:
    """Successful logon."""
    return {
        "user":      _data_by_name(data, "TargetUserName"),
        "domain":    _data_by_name(data, "TargetDomainName"),
        "logon_id":  _data_by_name(data, "TargetLogonId"),
        "logon_type": _data_by_name(data, "LogonType"),
        "src_ip":    _data_by_name(data, "IpAddress"),
        "process":   _data_by_name(data, "ProcessName"),
    }


def _parse_4625(data: ET.Element) -> dict:
    """Failed logon."""
    return {
        "user":       _data_by_name(data, "TargetUserName"),
        "domain":     _data_by_name(data, "TargetDomainName"),
        "logon_type": _data_by_name(data, "LogonType"),
        "src_ip":     _data_by_name(data, "IpAddress"),
        "failure":    _data_by_name(data, "FailureReason"),
        "status":     _data_by_name(data, "Status"),
    }


def _parse_4648(data: ET.Element) -> dict:
    """Explicit-credential logon (runas / lateral movement)."""
    return {
        "user":        _data_by_name(data, "SubjectUserName"),
        "target_user": _data_by_name(data, "TargetUserName"),
        "target_host": _data_by_name(data, "TargetServerName"),
        "process":     _data_by_name(data, "ProcessName"),
    }


def _parse_4672(data: ET.Element) -> dict:
    """Special privileges assigned — elevated logon."""
    return {
        "user":     _data_by_name(data, "SubjectUserName"),
        "logon_id": _data_by_name(data, "SubjectLogonId"),
        "privileges": _data_by_name(data, "PrivilegeList"),
    }


def _parse_4688(data: ET.Element) -> dict:
    """Process creation."""
    return {
        "process":         _data_by_name(data, "NewProcessName"),
        "pid":             _data_by_name(data, "NewProcessId"),
        "parent_process":  _data_by_name(data, "ParentProcessName"),
        "parent_pid":      _data_by_name(data, "ProcessId"),
        "user":            _data_by_name(data, "SubjectUserName"),
        "logon_id":        _data_by_name(data, "SubjectLogonId"),
        "cmdline":         _data_by_name(data, "CommandLine"),
        "token_type":      _data_by_name(data, "TokenElevationType"),
    }


def _parse_4697_7045(data: ET.Element) -> dict:
    """Service install."""
    # 4697 (Security) and 7045 (System) use different field names
    return {
        "service_name": _data_by_name(data, "ServiceName") or _data_by_name(data, "ServiceFileName"),
        "image_path":   _data_by_name(data, "ImagePath") or _data_by_name(data, "ServiceFileName"),
        "service_type": _data_by_name(data, "ServiceType"),
        "start_type":   _data_by_name(data, "StartType") or _data_by_name(data, "ServiceStartType"),
        "account":      _data_by_name(data, "AccountName") or _data_by_name(data, "ServiceAccount"),
    }


def _parse_4698(data: ET.Element) -> dict:
    """Scheduled task created."""
    return {
        "task_name":    _data_by_name(data, "TaskName"),
        "task_content": _data_by_name(data, "TaskContent"),
        "user":         _data_by_name(data, "SubjectUserName"),
    }


def _parse_4720(data: ET.Element) -> dict:
    """User account created."""
    return {
        "target_user": _data_by_name(data, "TargetUserName"),
        "subject_user": _data_by_name(data, "SubjectUserName"),
    }


def _parse_4732(data: ET.Element) -> dict:
    """Member added to security-enabled local group."""
    return {
        "group":  _data_by_name(data, "TargetUserName"),
        "member": _data_by_name(data, "MemberName") or _data_by_name(data, "MemberSid"),
        "user":   _data_by_name(data, "SubjectUserName"),
    }


def _parse_5140(data: ET.Element) -> dict:
    """Network share accessed."""
    return {
        "user":     _data_by_name(data, "SubjectUserName"),
        "src_ip":   _data_by_name(data, "IpAddress"),
        "share":    _data_by_name(data, "ShareName"),
        "share_path": _data_by_name(data, "ShareLocalPath"),
    }


def _parse_1102(data: ET.Element) -> dict:
    """Audit log cleared (Security)."""
    return {
        "user":    _data_by_name(data, "SubjectUserName"),
        "domain":  _data_by_name(data, "SubjectDomainName"),
        "anti_forensics": True,
    }


def _parse_104(data: ET.Element) -> dict:
    """Event log cleared (System). Different schema from 1102."""
    flat = _all_data(data)
    return {
        "channel": flat.get("Channel", "") or flat.get("ChannelName", ""),
        "user":    flat.get("SubjectUserName", ""),
        "anti_forensics": True,
    }


# Sysmon parsers — most use UtcTime / Image / CommandLine / ParentImage / ParentCommandLine
def _parse_sysmon_1(data: ET.Element) -> dict:
    """Sysmon process creation."""
    return {
        "process":        _data_by_name(data, "Image"),
        "pid":            _data_by_name(data, "ProcessId"),
        "cmdline":        _data_by_name(data, "CommandLine"),
        "parent_process": _data_by_name(data, "ParentImage"),
        "parent_cmdline": _data_by_name(data, "ParentCommandLine"),
        "user":           _data_by_name(data, "User"),
        "hashes":         _data_by_name(data, "Hashes"),
    }


def _parse_sysmon_3(data: ET.Element) -> dict:
    """Sysmon network connection."""
    return {
        "process":      _data_by_name(data, "Image"),
        "pid":          _data_by_name(data, "ProcessId"),
        "protocol":     _data_by_name(data, "Protocol"),
        "src_ip":       _data_by_name(data, "SourceIp"),
        "src_port":     _data_by_name(data, "SourcePort"),
        "dst_ip":       _data_by_name(data, "DestinationIp"),
        "dst_port":     _data_by_name(data, "DestinationPort"),
        "dst_hostname": _data_by_name(data, "DestinationHostname"),
    }


def _parse_sysmon_11(data: ET.Element) -> dict:
    """Sysmon file created."""
    return {
        "process":  _data_by_name(data, "Image"),
        "filename": _data_by_name(data, "TargetFilename"),
    }


def _parse_sysmon_13(data: ET.Element) -> dict:
    """Sysmon registry value set."""
    return {
        "process":     _data_by_name(data, "Image"),
        "target":      _data_by_name(data, "TargetObject"),
        "event_type":  _data_by_name(data, "EventType"),
        "details":     _data_by_name(data, "Details"),
    }


# Keyed by (event_id, is_sysmon)
_EVENT_PARSERS: Dict[tuple, Callable[[ET.Element], dict]] = {
    (4624, False): _parse_4624,
    (4625, False): _parse_4625,
    (4648, False): _parse_4648,
    (4672, False): _parse_4672,
    (4688, False): _parse_4688,
    (4697, False): _parse_4697_7045,
    (4698, False): _parse_4698,
    (4720, False): _parse_4720,
    (4732, False): _parse_4732,
    (5140, False): _parse_5140,
    (7045, False): _parse_4697_7045,
    (1102, False): _parse_1102,
    (104,  False): _parse_104,
    (1,  True):  _parse_sysmon_1,
    (3,  True):  _parse_sysmon_3,
    (11, True):  _parse_sysmon_11,
    (13, True):  _parse_sysmon_13,
}


def _parse_event_record(xml_str: str, is_sysmon: bool, source_tag: str,
                        always_emit: set, allow_set: set) -> Optional[dict]:
    """Parse one event XML record. Returns a record dict or None if filtered."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    sys_el = _find(root, "e:System", "System")
    if sys_el is None:
        return None

    event_id_el = _find(sys_el, "e:EventID", "EventID")
    if event_id_el is None or not event_id_el.text:
        return None
    try:
        event_id = int(event_id_el.text)
    except ValueError:
        return None

    # Filter: respect allow-list, but ALWAYS emit log-cleared events
    if event_id not in always_emit and allow_set and event_id not in allow_set:
        return None

    time_el = _find(sys_el, "e:TimeCreated", "TimeCreated")
    time_str = ""
    if time_el is not None:
        time_str = time_el.attrib.get("SystemTime", "")

    # Normalize the SystemTime (ISO8601 with subseconds + 'Z' or '+00:00'),
    # truncating subseconds to keep our line format predictable.
    if time_str:
        try:
            import datetime as _dt
            ts = time_str.replace("Z", "+00:00")
            dt = _dt.datetime.fromisoformat(ts)
            time_str = _c.to_iso8601(dt)
        except Exception:
            pass

    provider_el = _find(sys_el, "e:Provider", "Provider")
    provider = provider_el.attrib.get("Name", "") if provider_el is not None else ""

    computer_el = _find(sys_el, "e:Computer", "Computer")
    computer = (computer_el.text or "") if computer_el is not None else ""

    data_el = _find(root, "e:EventData", "EventData")

    record: dict = {
        "type": "event",
        "id": event_id,
        "time": time_str,
        "provider": provider,
        "computer": computer,
        "artifact_source": source_tag,
    }

    parser = _EVENT_PARSERS.get((event_id, is_sysmon))
    if parser is not None and data_el is not None:
        try:
            extra = parser(data_el)
            for k, v in extra.items():
                if v not in (None, ""):
                    record[k] = v
        except Exception:
            # If a per-ID parser fails, still emit the basic record
            pass
    elif data_el is not None and not allow_set:
        # If no allow-list given, dump every Data field
        record.update({k: v for k, v in _all_data(data_el).items() if v})

    return record


# -------------------------- Public API --------------------------

def _classify_evtx(file_path: str) -> Optional[tuple]:
    """Returns (out_filename, source_tag, is_sysmon) or None."""
    low = os.path.basename(file_path).lower()
    if low in _LOG_ROUTING:
        out_name, source = _LOG_ROUTING[low]
        is_sysmon = "sysmon" in low
        return out_name, source, is_sysmon
    # Generic .evtx that we don't know — bucket into application.
    if low.endswith(".evtx"):
        return "eventlog_application.txt", os.path.basename(file_path), "sysmon" in low
    return None


def collect_file(evtx_path: str, is_sysmon: bool, source_tag: str,
                 always_emit: set, allow_set: set,
                 raw_limit: Optional[int] = None) -> Iterator[dict]:
    if not _HAS_EVTX:
        raise RuntimeError("python-evtx not installed. `pip install python-evtx`")
    with Evtx(evtx_path) as log:
        for i, record in enumerate(log.records()):
            if raw_limit is not None and i >= raw_limit:
                break
            try:
                xml_str = record.xml()
            except Exception:
                continue
            parsed = _parse_event_record(xml_str, is_sysmon, source_tag, always_emit, allow_set)
            if parsed:
                yield parsed


def run_from_config(config: dict, out_dir: str) -> dict:
    section = config.get("eventlog") or {}
    evtx_dir = section.get("evtx_dir")
    if not evtx_dir or not os.path.isdir(evtx_dir):
        print(f"[eventlog_collector] evtx_dir not found: {evtx_dir!r} — skipping",
              file=__import__("sys").stderr)
        return {"output_files": [], "record_count": 0}

    max_recs = config.get("max_records")
    allow_set = set(config.get("high_signal_event_ids") or [])
    always_emit = set(config.get("always_emit_event_ids") or [1102, 104])

    max_archive_age_days = config.get("max_archive_age_days")

    # Aggregate per output bucket
    buckets: Dict[str, List[dict]] = {}
    files_seen = 0
    for entry in sorted(os.listdir(evtx_dir)):
        # Skip archive files in quick-test mode or when they fall outside the age window
        if entry.lower().startswith("archive-"):
            if max_recs:
                continue
            if max_archive_age_days is not None:
                import datetime as _dt
                full_check = os.path.join(evtx_dir, entry)
                try:
                    mtime = _dt.datetime.fromtimestamp(os.path.getmtime(full_check))
                    cutoff = _dt.datetime.now() - _dt.timedelta(days=max_archive_age_days)
                    if mtime < cutoff:
                        continue
                except OSError:
                    pass
        full = os.path.join(evtx_dir, entry)
        if not os.path.isfile(full):
            continue
        cls = _classify_evtx(full)
        if cls is None:
            continue
        out_name, source_tag, is_sysmon = cls
        files_seen += 1
        try:
            recs = list(collect_file(full, is_sysmon, source_tag, always_emit, allow_set,
                                     raw_limit=max_recs * 20 if max_recs else None))
        except Exception as e:
            print(f"[eventlog_collector] failed to parse {full}: {e}", file=sys.stderr)
            continue
        buckets.setdefault(out_name, []).extend(recs)

    if files_seen == 0:
        return {"error": f"no .evtx files found in {evtx_dir!r}",
                "output_files": [], "record_count": 0}

    out_files: List[str] = []
    total = 0
    for fname, recs in buckets.items():
        if not recs:
            continue
        out_path = os.path.join(out_dir, fname)
        n = _c.write_records_to_file(iter(recs), out_path, limit=max_recs)
        out_files.append(out_path)
        total += n
    return {"output_files": out_files, "record_count": total}


def main() -> None:
    parser = _c.setup_cli(
        "Parse .evtx event logs into FIND_EVIL_DISK type=event records.",
        default_out="Disk_Artifacts/",
    )
    parser.add_argument("--evtx-dir", required=True,
                        help="Directory containing Security.evtx/System.evtx/etc.")
    args = parser.parse_args()
    config = _c.load_json(args.config) if args.config else {}
    config.setdefault("eventlog", {})["evtx_dir"] = args.evtx_dir
    res = run_from_config(config, args.out if os.path.isdir(args.out) else "Disk_Artifacts")
    print(f"[eventlog_collector] wrote {res['record_count']} records → {res['output_files']}")


if __name__ == "__main__":
    main()
