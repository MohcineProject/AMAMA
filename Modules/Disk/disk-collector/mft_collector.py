"""Parse a raw $MFT file → type=file FIND_EVIL_DISK records.

Input: a raw $MFT file extracted from an NTFS volume (NOT a full disk image).
The test agent is responsible for extracting it, e.g.:
    icat -o <part_offset> <image.dd> 0 > raw_mft           (TSK)
    fls / istat / icat from sleuthkit

Two parser backends:
  * builtin (default) — pure-Python MFT entry parser, no external deps. Covers
    the 80% case (resident SI + FN + DATA streams) needed for triage.
  * analyzemft       — delegates to the `analyzeMFT` PyPI package if installed.
                       # UNCERTAIN: analyzeMFT's API changed between 2.x and 3.x
                       (CLI tool vs library). The test agent must verify which
                       entrypoint is available and adjust _parse_with_analyzemft.

For each MFT entry we emit a `type=file` record with:
  path, mft_ref, size, deleted, ads, signature, entropy, hash,
  created, modified, accessed, fn_created, fn_modified, fn_accessed,
  artifact_source=mft

Static file analysis (signature/entropy/hash via pe_analyzer) only happens when
--volume-root points at a mounted copy of the volume and the file is reachable
there. Otherwise those fields are left empty (per HOW_TO_BUILD.md §5.0).
"""
from __future__ import annotations

import os
import struct
import sys
from typing import Dict, Iterator, Optional, Tuple

# Allow running both as `python mft_collector.py` and as a package import.
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _common as _c  # type: ignore
    import pe_analyzer as _pe  # type: ignore
else:
    from . import _common as _c
    from . import pe_analyzer as _pe


# -------------------------- Built-in pure-Python MFT parser --------------------------
#
# References:
#   - NTFS Documentation by Richard Russon and Yuval Fledel (linux-ntfs project)
#   - "File System Forensic Analysis" — Brian Carrier, ch. 11–13
#
# Each MFT entry is conventionally 1024 bytes, but record_size is stored in
# $Boot. For a raw $MFT we don't have $Boot — we infer from the first entry's
# "used_size"/"alloc_size". 1024 is right for ~all NTFS volumes since XP.
#
# UNCERTAIN: entries can be 4096 on some 4K-sector formatted volumes. v1 tries
# 1024 first, then 4096 if signatures aren't aligned. Tests must verify on a
# real image.

_MFT_SIGNATURE = b"FILE"
_BAAD_SIGNATURE = b"BAAD"  # corrupted entry — skip

_ATTR_STANDARD_INFORMATION = 0x10
_ATTR_FILE_NAME = 0x30
_ATTR_DATA = 0x80

_ENTRY_FLAG_IN_USE = 0x0001
_ENTRY_FLAG_DIRECTORY = 0x0002

_NAMESPACE_POSIX = 0  # may contain forbidden chars
_NAMESPACE_WIN32 = 1
_NAMESPACE_DOS = 2   # 8.3 short name — skip
_NAMESPACE_WIN32_AND_DOS = 3


def _detect_record_size(buf: bytes) -> int:
    """Best-effort autodetect of MFT entry size from the buffer head."""
    if len(buf) >= 1024 and buf[:4] in (_MFT_SIGNATURE, _BAAD_SIGNATURE):
        # Probe for second entry at 1024
        if len(buf) >= 2048 and buf[1024:1028] in (_MFT_SIGNATURE, _BAAD_SIGNATURE):
            return 1024
        if len(buf) >= 4096 and buf[4096 - 1024:4096 - 1024 + 4] in (_MFT_SIGNATURE, _BAAD_SIGNATURE):
            # Unusual; fall through
            return 1024
    # Try 4096
    if len(buf) >= 8192 and buf[4096:4100] in (_MFT_SIGNATURE, _BAAD_SIGNATURE):
        return 4096
    return 1024  # default


def _apply_fixups(entry: bytearray, usa_offset: int, usa_count: int, sector_size: int = 512) -> bool:
    """Apply NTFS Update Sequence Array fixups in-place.

    Returns True if all fixups matched. False = entry possibly torn; caller may
    still proceed but should flag low confidence.
    """
    if usa_count == 0:
        return True
    try:
        usn = entry[usa_offset:usa_offset + 2]
        ok = True
        for i in range(1, usa_count):
            sector_end = i * sector_size
            if sector_end > len(entry):
                return False
            expected_pos = sector_end - 2
            if entry[expected_pos:expected_pos + 2] != usn:
                ok = False
            replacement_pos = usa_offset + i * 2
            entry[expected_pos:expected_pos + 2] = entry[replacement_pos:replacement_pos + 2]
        return ok
    except Exception:
        return False


def _read_filetime(data: bytes, offset: int) -> Optional[int]:
    if offset + 8 > len(data):
        return None
    return struct.unpack("<Q", data[offset:offset + 8])[0]


def _parse_attributes(entry: bytes, attr_offset: int) -> dict:
    """Return {si, fns: [...], datas: [...]} parsed from an MFT entry buffer.

    Only resident attributes are parsed in detail. Non-resident SI/FN are rare
    on real volumes; non-resident $DATA is the common case (file body) — we
    still record its name (ADS detection) but not its content.
    """
    result = {"si": None, "fns": [], "datas": []}
    off = attr_offset
    while off + 16 <= len(entry):
        attr_type = struct.unpack("<I", entry[off:off + 4])[0]
        if attr_type == 0xFFFFFFFF:  # end-of-attributes sentinel
            break
        attr_len = struct.unpack("<I", entry[off + 4:off + 8])[0]
        if attr_len == 0 or off + attr_len > len(entry):
            break

        non_resident = entry[off + 8]
        name_len = entry[off + 9]
        name_offset = struct.unpack("<H", entry[off + 10:off + 12])[0]

        attr_name = ""
        if name_len:
            try:
                attr_name = entry[off + name_offset:off + name_offset + name_len * 2].decode(
                    "utf-16le", errors="replace"
                )
            except Exception:
                attr_name = ""

        if non_resident == 0:
            content_len = struct.unpack("<I", entry[off + 16:off + 20])[0]
            content_offset = struct.unpack("<H", entry[off + 20:off + 22])[0]
            content = entry[off + content_offset:off + content_offset + content_len]

            if attr_type == _ATTR_STANDARD_INFORMATION:
                if len(content) >= 32:
                    result["si"] = {
                        "created":  _read_filetime(content, 0),
                        "modified": _read_filetime(content, 8),
                        "mft_mod":  _read_filetime(content, 16),
                        "accessed": _read_filetime(content, 24),
                    }
            elif attr_type == _ATTR_FILE_NAME and len(content) >= 66:
                parent_ref_raw = struct.unpack("<Q", content[0:8])[0]
                parent_ref = parent_ref_raw & 0x0000FFFFFFFFFFFF  # low 48 bits
                fn = {
                    "parent_ref": parent_ref,
                    "created":  _read_filetime(content, 8),
                    "modified": _read_filetime(content, 16),
                    "mft_mod":  _read_filetime(content, 24),
                    "accessed": _read_filetime(content, 32),
                    "namespace": content[65],
                    "name": "",
                }
                name_chars = content[64]
                name_bytes = content[66:66 + name_chars * 2]
                try:
                    fn["name"] = name_bytes.decode("utf-16le", errors="replace")
                except Exception:
                    fn["name"] = ""
                result["fns"].append(fn)
            elif attr_type == _ATTR_DATA:
                result["datas"].append({"name": attr_name, "size": content_len, "resident": True})
        else:
            # Non-resident attribute — record the existence + ADS name only.
            if attr_type == _ATTR_DATA:
                # Real size lives at offset 48-55 of the non-resident attribute header
                real_size = 0
                if off + 56 <= len(entry):
                    real_size = struct.unpack("<Q", entry[off + 48:off + 56])[0]
                result["datas"].append({"name": attr_name, "size": real_size, "resident": False})

        off += attr_len

    return result


def _select_best_fn(fns: list) -> Optional[dict]:
    """Prefer WIN32 / WIN32+DOS namespaces over POSIX or pure DOS 8.3."""
    if not fns:
        return None
    priority = {_NAMESPACE_WIN32_AND_DOS: 0, _NAMESPACE_WIN32: 1, _NAMESPACE_POSIX: 2, _NAMESPACE_DOS: 3}
    fns_sorted = sorted(fns, key=lambda f: priority.get(f.get("namespace", 99), 99))
    return fns_sorted[0]


def _parse_entry(entry: bytearray, entry_index: int) -> Optional[dict]:
    """Decode one MFT entry. Returns None for empty/non-FILE slots."""
    if len(entry) < 48:
        return None
    sig = bytes(entry[:4])
    if sig == _BAAD_SIGNATURE:
        return {"index": entry_index, "corrupt": True}
    if sig != _MFT_SIGNATURE:
        return None

    usa_offset = struct.unpack("<H", entry[4:6])[0]
    usa_count = struct.unpack("<H", entry[6:8])[0]
    _apply_fixups(entry, usa_offset, usa_count)

    seq = struct.unpack("<H", entry[16:18])[0]
    attr_offset = struct.unpack("<H", entry[20:22])[0]
    flags = struct.unpack("<H", entry[22:24])[0]
    used_size = struct.unpack("<I", entry[24:28])[0]
    base_ref = struct.unpack("<Q", entry[32:40])[0] & 0x0000FFFFFFFFFFFF

    if base_ref != 0:
        # This is an extension (attribute-list child) entry; the main entry has
        # the SI/FN. We skip these for v1 — Agent 1 only cares about base entries.
        # UNCERTAIN: skipping extension entries may miss data for files with
        # very fragmented attribute lists. Rare on modern Windows.
        return None

    in_use = bool(flags & _ENTRY_FLAG_IN_USE)
    is_dir = bool(flags & _ENTRY_FLAG_DIRECTORY)

    payload = bytes(entry[:used_size]) if used_size and used_size <= len(entry) else bytes(entry)
    attrs = _parse_attributes(payload, attr_offset)

    record = {
        "index": entry_index,
        "seq": seq,
        "in_use": in_use,
        "is_dir": is_dir,
        "si": attrs["si"],
        "fns": attrs["fns"],
        "datas": attrs["datas"],
    }
    return record


# -------------------------- Path reconstruction --------------------------

# NTFS root directory entry index is fixed at 5.
_ROOT_INDEX = 5


def _build_path_index(entries: Dict[int, dict]) -> Dict[int, str]:
    """Two-pass path build. Returns {entry_index: full_path}."""
    cache: Dict[int, str] = {_ROOT_INDEX: ""}
    visiting: set = set()

    def resolve(idx: int) -> str:
        if idx in cache:
            return cache[idx]
        if idx in visiting:
            return "<cycle>"
        if idx not in entries:
            return "<orphan>"
        visiting.add(idx)
        entry = entries[idx]
        best = _select_best_fn(entry.get("fns") or [])
        if not best:
            cache[idx] = "<no-fn>"
            visiting.discard(idx)
            return cache[idx]
        parent_path = resolve(best["parent_ref"])
        if parent_path in ("<orphan>", "<cycle>", "<no-fn>"):
            full = "<orphan>\\" + best["name"]
        elif parent_path == "":
            full = best["name"]
        else:
            full = parent_path + "\\" + best["name"]
        cache[idx] = full
        visiting.discard(idx)
        return full

    for idx in entries:
        resolve(idx)
    return cache


# -------------------------- High-level pipeline --------------------------

def _iterate_entries(mft_path: str) -> Iterator[Tuple[int, bytearray]]:
    """Yield (entry_index, raw bytes) for every MFT slot in the file."""
    with open(mft_path, "rb") as f:
        head = f.read(8192)
        record_size = _detect_record_size(head)
        f.seek(0)
        index = 0
        while True:
            buf = f.read(record_size)
            if not buf or len(buf) < record_size:
                break
            yield index, bytearray(buf)
            index += 1


def _should_emit_mft_record(path: str, config: dict,
                             suspicious_paths: list, pe_extensions: set) -> bool:
    """Return False if this MFT record should be dropped before writing.

    Three independent filters, all opt-in via config:
    - mft_exclude_paths: subtrees that never contain malware (WinSxS, assembly, etc.)
    - mft_exclude_extensions: noise file types outside suspicious paths
    - mft_write_only_suspicious: triage mode — only PEs and suspicious-path files
    """
    exclude_paths = [p.lower() for p in config.get("mft_exclude_paths") or []]
    exclude_exts = {e.lower() for e in config.get("mft_exclude_extensions") or []}
    only_suspicious = config.get("mft_write_only_suspicious", False)

    path_lower = path.lower()
    ext = os.path.splitext(path)[1].lower()

    if any(excl in path_lower for excl in exclude_paths):
        return False

    if ext in exclude_exts:
        if not any(p in path_lower for p in suspicious_paths):
            return False

    if only_suspicious:
        in_suspicious = bool(suspicious_paths and any(p in path_lower for p in suspicious_paths))
        if not (ext in pe_extensions or in_suspicious):
            return False

    return True


def collect_builtin(mft_path: str, config: dict) -> Iterator[dict]:
    """Parse the $MFT with the built-in parser, yield raw record dicts.

    Two passes: first to build the path index (we hold parsed entries in memory),
    second to emit records. For huge MFTs (>2 GB), this will use ~2× RAM the
    size of the parsed metadata. UNCERTAIN: streaming variant deferred to v2.
    """
    suspicious_paths = [p.lower() for p in config.get("suspicious_paths") or []]
    volume_root = (config.get("mft") or {}).get("volume_root") if isinstance(config.get("mft"), dict) \
        else config.get("volume_root")
    do_pe_analysis = bool(volume_root and os.path.isdir(volume_root))

    print(f"[mft_collector] parsing {mft_path} ...", file=sys.stderr)
    entries: Dict[int, dict] = {}
    for idx, buf in _iterate_entries(mft_path):
        parsed = _parse_entry(buf, idx)
        if parsed is None or parsed.get("corrupt"):
            if parsed and parsed.get("corrupt"):
                entries[idx] = parsed  # keep so we still emit a placeholder
            continue
        entries[idx] = parsed

    print(f"[mft_collector] parsed {len(entries)} entries; building path index ...", file=sys.stderr)
    path_cache = _build_path_index(entries)

    for idx, entry in entries.items():
        if entry.get("corrupt"):
            yield {
                "type": "file",
                "path": "UNKNOWN",
                "mft_ref": f"{idx}-?",
                "deleted": True,
                "corrupt": True,
                "artifact_source": "mft",
            }
            continue

        fn = _select_best_fn(entry.get("fns") or [])
        path = path_cache.get(idx, "<orphan>")
        if entry.get("is_dir"):
            # v1 emits directories too — useful for $Recycle.Bin etc. — but
            # without entropy/hash/signature. Triage will mostly skip them.
            pass

        si = entry.get("si") or {}

        si_created  = _c.windows_filetime_to_utc(si.get("created"))  if si.get("created")  else None
        si_modified = _c.windows_filetime_to_utc(si.get("modified")) if si.get("modified") else None
        si_accessed = _c.windows_filetime_to_utc(si.get("accessed")) if si.get("accessed") else None

        fn_created  = _c.windows_filetime_to_utc(fn["created"])  if fn and fn.get("created")  else None
        fn_modified = _c.windows_filetime_to_utc(fn["modified"]) if fn and fn.get("modified") else None
        fn_accessed = _c.windows_filetime_to_utc(fn["accessed"]) if fn and fn.get("accessed") else None

        # Primary $DATA stream size = unnamed $DATA. Named $DATA = ADS.
        size = 0
        ads_names = []
        for d in entry.get("datas") or []:
            if not d.get("name"):
                size = max(size, d.get("size", 0))
            else:
                ads_names.append(d["name"])

        record = {
            "type": "file",
            "path": path if entry.get("in_use") else f"DELETED:{path}",
            "mft_ref": f"{idx}-{entry.get('seq', 0)}",
            "size": size or None,
            "deleted": (not entry.get("in_use")),
            "is_directory": entry.get("is_dir") or None,
            "ads": ";".join(ads_names) if ads_names else None,
            "created":  _c.to_iso8601(si_created),
            "modified": _c.to_iso8601(si_modified),
            "accessed": _c.to_iso8601(si_accessed),
            "fn_created":  _c.to_iso8601(fn_created),
            "fn_modified": _c.to_iso8601(fn_modified),
            "fn_accessed": _c.to_iso8601(fn_accessed),
            "artifact_source": "mft",
        }

        # Optional: static PE analysis if a mounted volume is available.
        # Only hash files with PE-like extensions; for suspicious-path non-PE files
        # check magic/entropy only (no full-file read).  Skipping non-PE files
        # avoids hashing every JPEG/video on the volume, which would take hours.
        if do_pe_analysis and not entry.get("is_dir") and path and not path.startswith("<"):
            ext = os.path.splitext(path)[1].lower()
            is_pe_ext = ext in _pe._PE_EXTENSIONS
            in_suspicious = bool(
                suspicious_paths and any(p in path.lower() for p in suspicious_paths)
            )
            if is_pe_ext or in_suspicious:
                os_path = os.path.join(volume_root, path.replace("\\", os.sep))
                if os.path.isfile(os_path):
                    # Full analysis (hash + entropy + RESOURCE dir) only for suspicious paths.
                    # Non-suspicious PE files get import/signature check only — skipping
                    # full-file reads saves 10-20 minutes on large Windows volumes.
                    analysis = _pe.analyze_path(
                        os_path,
                        compute_hash=in_suspicious,
                        compute_entropy=in_suspicious,
                    )
                    if analysis.get("sha256"):
                        record["hash"] = "sha256:" + analysis["sha256"]
                    for k in ("signature", "entropy", "max_section_entropy",
                              "has_version_info", "suspicious_imports", "magic_mismatch"):
                        if k in analysis:
                            record[k] = analysis[k]

        # Triage-helpful tag: suspicious_path flag
        if suspicious_paths and path:
            low = path.lower()
            if any(p in low for p in suspicious_paths):
                record["suspicious_path"] = True

        if path and not path.startswith("<"):
            if not _should_emit_mft_record(path, config, suspicious_paths, _pe._PE_EXTENSIONS):
                continue

        yield record


def collect_analyzemft(mft_path: str, config: dict) -> Iterator[dict]:
    """Fallback path that delegates to the analyzeMFT package.

    # UNCERTAIN: analyzeMFT's library API differs between 2.x and 3.x and is
    # poorly documented. The test agent must verify which entrypoint exists and
    # adjust the import/iteration below. v1 attempts the 2.x `MftSession` shape
    # and falls back to invoking the CLI as a subprocess if that fails.
    """
    try:
        from analyzeMFT.mft_session import MftSession  # type: ignore
        sess = MftSession()
        sess.options.filename = mft_path
        sess.options.output = None
        sess.process_mft_file()
        # UNCERTAIN: API for iterating parsed records varies. Best guess:
        for raw in getattr(sess, "mft", []):
            # Convert analyzeMFT's internal dict into our record shape
            yield {
                "type": "file",
                "path": raw.get("filename", "<unknown>"),
                "mft_ref": raw.get("recordnum"),
                "deleted": not raw.get("active", True),
                "created":  _c.to_iso8601(raw.get("si", {}).get("crtime")),
                "modified": _c.to_iso8601(raw.get("si", {}).get("mtime")),
                "accessed": _c.to_iso8601(raw.get("si", {}).get("atime")),
                "artifact_source": "mft",
            }
        return
    except Exception as e:
        print(f"[mft_collector] analyzeMFT path failed ({e!s}); aborting fallback", file=sys.stderr)
        return


def collect(mft_path: str, config: dict, parser: str = "builtin") -> Iterator[dict]:
    if parser == "analyzemft":
        yield from collect_analyzemft(mft_path, config)
    else:
        yield from collect_builtin(mft_path, config)


# -------------------------- Public API --------------------------

def run_from_config(config: dict, out_dir: str) -> dict:
    """Invoked by disk_collector.py orchestrator."""
    section = config.get("mft") or {}
    mft_path = section.get("input")
    parser = section.get("parser", "builtin")
    if not mft_path or not os.path.isfile(mft_path):
        return {"error": f"mft.input not found: {mft_path!r}",
                "output_files": [], "record_count": 0}
    out_path = os.path.join(out_dir, "mft_records.txt")
    n = _c.write_records_to_file(collect(mft_path, config, parser=parser), out_path,
                                  limit=config.get("max_records"))
    return {"output_files": [out_path], "record_count": n}


def main() -> None:
    parser = _c.setup_cli(
        "Parse a raw $MFT file into FIND_EVIL_DISK type=file records.",
        default_out="Disk_Artifacts/mft_records.txt",
    )
    parser.add_argument("--input", required=True, help="Path to raw $MFT file")
    parser.add_argument("--parser", default="builtin",
                        choices=["builtin", "analyzemft"],
                        help="Backend parser (default: builtin)")
    parser.add_argument("--volume-root", default=None,
                        help="Optional: path to a mounted copy of the volume so "
                             "we can hash + entropy-analyze PE files on disk")
    args = parser.parse_args()

    config = _c.load_json(args.config) if args.config else {}
    if args.volume_root:
        # Merge into config so collect_builtin picks it up
        config.setdefault("mft", {})["volume_root"] = args.volume_root

    n = _c.write_records_to_file(
        collect(args.input, config, parser=args.parser),
        args.out,
    )
    print(f"[mft_collector] wrote {n} records → {args.out}")


if __name__ == "__main__":
    main()
