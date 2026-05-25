"""Persistence collector: scheduled tasks + WMI subscriptions.

Run keys + services are produced by zimmerman_registry_collector (RECmd/DFIRBatch).
This module handles the artifacts not covered by RECmd:

  1. Parses scheduled task XMLs → Disk_Artifacts/scheduled_tasks.txt
  2. Emits WMI subscription rows → Disk_Artifacts/wmi_subscriptions.txt

Outputs:
  Disk_Artifacts/scheduled_tasks.txt
  Disk_Artifacts/wmi_subscriptions.txt
"""
from __future__ import annotations

import os
import sys
import xml.etree.ElementTree as ET
from typing import Iterator, List, Optional

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _common as _c  # type: ignore
else:
    from . import _common as _c

_reg = None  # registry_collector removed; optional feature disabled


# Task XMLs use this namespace.
_TASK_NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


def _strip_ns(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _xml_text(elem, path: str) -> str:
    """Find a sub-element (with or without namespace) and return stripped text."""
    if elem is None:
        return ""
    # Try with namespace
    found = elem.find(path, _TASK_NS)
    if found is None:
        # Strip "t:" prefix and try without namespace
        found = elem.find(path.replace("t:", ""))
    if found is None:
        return ""
    return (found.text or "").strip()


def _walk_tasks_dir(tasks_dir: str) -> Iterator[str]:
    """Yield every task XML file path under tasks_dir (recursive).

    Real images put tasks under C:\\Windows\\System32\\Tasks with nested
    subdirectories grouping by Microsoft\\Windows\\<feature>. Most are XML;
    occasionally there's a corresponding registry entry under
    SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache.
    """
    for root, _dirs, files in os.walk(tasks_dir):
        for f in files:
            full = os.path.join(root, f)
            # Tasks usually have no extension; sniff for XML
            try:
                with open(full, "rb") as fh:
                    head = fh.read(64)
            except OSError:
                continue
            stripped = head.lstrip()
            if (stripped.startswith(b"<?xml") or stripped.startswith(b"<Task")
                    or head[:2] in (b"\xff\xfe", b"\xfe\xff")):
                yield full


def _parse_task_xml(path: str) -> Optional[dict]:
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception:
        return None

    # Triggers — list every trigger type present
    triggers_el = root.find("t:Triggers", _TASK_NS) or root.find("Triggers")
    trigger_types: List[str] = []
    trigger_info: List[str] = []
    if triggers_el is not None:
        for child in triggers_el:
            tname = _strip_ns(child.tag)
            trigger_types.append(tname)
            # Extract a couple of useful sub-fields per trigger type
            start = _xml_text(child, "t:StartBoundary") or _xml_text(child, "StartBoundary")
            if start:
                trigger_info.append(f"{tname}@{start}")
            else:
                trigger_info.append(tname)

    # Actions — collect Exec command/arguments
    actions_el = root.find("t:Actions", _TASK_NS) or root.find("Actions")
    action_paths: List[str] = []
    action_args: List[str] = []
    if actions_el is not None:
        for action in actions_el:
            if _strip_ns(action.tag) != "Exec":
                continue
            cmd = _xml_text(action, "t:Command") or _xml_text(action, "Command")
            args = _xml_text(action, "t:Arguments") or _xml_text(action, "Arguments")
            if cmd:
                action_paths.append(cmd)
            if args:
                action_args.append(args)

    # Principals — RunAs user
    principals_el = root.find("t:Principals", _TASK_NS) or root.find("Principals")
    run_as = ""
    if principals_el is not None:
        principal = list(principals_el)
        if principal:
            run_as = _xml_text(principal[0], "t:UserId") or _xml_text(principal[0], "UserId")

    # Date / Author metadata
    reg_info = root.find("t:RegistrationInfo", _TASK_NS) or root.find("RegistrationInfo")
    date = _xml_text(reg_info, "t:Date") or _xml_text(reg_info, "Date") if reg_info is not None else ""
    author = _xml_text(reg_info, "t:Author") or _xml_text(reg_info, "Author") if reg_info is not None else ""

    # The task NAME is the basename of the file path. The full task path is the
    # relative path under Tasks/.
    return {
        "type": "persistence",
        "mechanism": "scheduled_task",
        "name": os.path.basename(path),
        "task_path": path,
        "trigger": ";".join(trigger_info) if trigger_info else ";".join(trigger_types) or "",
        "trigger_types": ";".join(trigger_types) if trigger_types else "",
        "action": ";".join(action_paths),
        "action_args": ";".join(action_args) if action_args else "",
        "run_as": run_as,
        "author": author,
        "registered": date,
        "artifact_source": "Task_Scheduler",
    }


def collect_scheduled_tasks(tasks_dir: str) -> Iterator[dict]:
    if not tasks_dir or not os.path.isdir(tasks_dir):
        return
    for path in _walk_tasks_dir(tasks_dir):
        rec = _parse_task_xml(path)
        if rec:
            yield rec


# -------------------------- WMI subscriptions --------------------------

def collect_wmi(wmi_dir: str) -> Iterator[dict]:
    """v1 implementation: emit a placeholder summary record per repository file.

    Full WMI repository parsing (OBJECTS.DATA + INDEX.BTR + MAPPING) requires
    a dedicated parser. # UNCERTAIN: integrating `python-cim` would let us
    walk EventConsumer / __EventFilter / __FilterToConsumerBinding objects to
    detect classic WMI persistence (e.g. CommandLineEventConsumer). The test
    agent should decide whether to invest in that or shell out to PowerShell
    `Get-CIMInstance __EventFilter` against a mounted hive (offline mode only).
    """
    if not wmi_dir or not os.path.isdir(wmi_dir):
        return
    for entry in sorted(os.listdir(wmi_dir)):
        full = os.path.join(wmi_dir, entry)
        if not os.path.isfile(full):
            continue
        try:
            size = os.path.getsize(full)
        except OSError:
            size = 0
        yield {
            "type": "persistence",
            "mechanism": "wmi",
            "name": entry,
            "trigger": "UNKNOWN_REQUIRES_WMI_PARSER",
            "action": "UNKNOWN_REQUIRES_WMI_PARSER",
            "file_size_bytes": size,
            "artifact_source": "WMI_Repository",
            "needs_full_parser": True,
        }


# -------------------------- Public API --------------------------

def run_from_config(config: dict, out_dir: str) -> dict:
    section = config.get("persistence") or {}
    tasks_dir = section.get("tasks_dir")
    wmi_dir   = section.get("wmi_dir")
    include_registry = bool(section.get("include_registry_persistence", False))

    out_files: List[str] = []
    total = 0
    errors: List[str] = []
    limit = config.get("max_records")

    # Scheduled tasks
    if tasks_dir:
        if not os.path.isdir(tasks_dir):
            errors.append(f"tasks_dir not found: {tasks_dir!r}")
        else:
            out_path = os.path.join(out_dir, "scheduled_tasks.txt")
            try:
                n = _c.write_records_to_file(collect_scheduled_tasks(tasks_dir), out_path,
                                             limit=limit)
                if n:
                    out_files.append(out_path)
                    total += n
            except Exception as e:
                errors.append(f"tasks: {e}")

    # WMI subscriptions
    if wmi_dir:
        out_path = os.path.join(out_dir, "wmi_subscriptions.txt")
        try:
            n = _c.write_records_to_file(collect_wmi(wmi_dir), out_path, limit=limit)
            if n:
                out_files.append(out_path)
                total += n
        except Exception as e:
            errors.append(f"wmi: {e}")

    # Optional registry persistence re-walk — disabled (registry_collector removed;
    # use zimmerman_registry_collector instead).
    if include_registry and _reg is not None:
        reg_hive_dir = section.get("hive_dir") or (config.get("registry") or {}).get("hive_dir")
        if reg_hive_dir and os.path.isdir(reg_hive_dir):
            autoruns: List[dict] = []
            services: List[dict] = []
            for cat, rec in _reg.collect_all(reg_hive_dir, config):
                # Re-shape registry records into persistence records
                if cat == "autorun":
                    autoruns.append({
                        "type": "persistence",
                        "mechanism": "run_key",
                        "name": rec.get("value"),
                        "trigger": "logon",
                        "action": rec.get("data"),
                        "artifact_source": rec.get("artifact_source"),
                        "registry_key": rec.get("key"),
                    })
                elif cat == "service":
                    services.append({
                        "type": "persistence",
                        "mechanism": "service",
                        "name": rec.get("key", "").split("\\")[-1],
                        "trigger": f"start_type={rec.get('start_type')}",
                        "action": rec.get("data"),
                        "artifact_source": rec.get("artifact_source"),
                        "registry_key": rec.get("key"),
                    })
            if autoruns:
                out_path = os.path.join(out_dir, "persistence_runkeys.txt")
                n = _c.write_records_to_file(iter(autoruns), out_path)
                out_files.append(out_path); total += n
            if services:
                out_path = os.path.join(out_dir, "persistence_services.txt")
                n = _c.write_records_to_file(iter(services), out_path)
                out_files.append(out_path); total += n

    result = {"output_files": out_files, "record_count": total}
    if errors:
        result["errors"] = errors
    return result


def main() -> None:
    parser = _c.setup_cli(
        "Collect persistence artifacts (scheduled tasks + WMI subscriptions).",
        default_out="Disk_Artifacts/",
    )
    parser.add_argument("--tasks-dir", default=None,
                        help="Directory mirroring C:\\Windows\\System32\\Tasks")
    parser.add_argument("--wmi-dir", default=None,
                        help="Directory mirroring %%SystemRoot%%\\System32\\wbem\\Repository")
    parser.add_argument("--include-registry-persistence", action="store_true",
                        help="Also re-walk Run keys + services into separate files "
                             "(usually unnecessary — registry_collector does it).")
    parser.add_argument("--hive-dir", default=None,
                        help="Used only with --include-registry-persistence")
    args = parser.parse_args()
    config = _c.load_json(args.config) if args.config else {}
    section = config.setdefault("persistence", {})
    if args.tasks_dir:    section["tasks_dir"] = args.tasks_dir
    if args.wmi_dir:      section["wmi_dir"]   = args.wmi_dir
    if args.hive_dir:     section["hive_dir"]  = args.hive_dir
    section["include_registry_persistence"] = bool(args.include_registry_persistence)

    res = run_from_config(config, args.out if os.path.isdir(args.out) else "Disk_Artifacts")
    print(f"[persistence_collector] wrote {res['record_count']} records → {res['output_files']}")


if __name__ == "__main__":
    main()
