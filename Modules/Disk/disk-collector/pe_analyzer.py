"""Static PE / file analysis helpers used by mft_collector.

Pure-Python: entropy, magic-vs-extension, PE signature/imports/VERSIONINFO,
SHA256. Designed to never raise on bad input — returns {} for unparsable files.

See HOW_TO_BUILD.md §4.6 for the source snippets borrowed here.
"""
from __future__ import annotations

import hashlib
import math
import os
from typing import Optional

try:
    import pefile  # type: ignore
    _HAS_PEFILE = True
except ImportError:
    pefile = None  # type: ignore
    _HAS_PEFILE = False


# Imports that indicate process injection / memory manipulation capability.
_SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "ZwUnmapViewOfSection",
    "SetWindowsHookEx",
    "QueueUserAPC",
    "NtCreateThreadEx",
    "RtlCreateUserThread",
    "VirtualProtect",
    "VirtualProtectEx",
}

# Extensions that LEGITIMATELY contain a PE. Any other extension + MZ header
# = mismatch (per HOW_TO_BUILD.md §4.6 "claimed_jpg_is_PE").
_PE_EXTENSIONS = {".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".drv", ".efi", ".mui"}

# UNCERTAIN: 500 MB cap on full-file hashing is arbitrary; tune after test agent
# reports performance on real images. We always hash in 1 MB chunks regardless.
_MAX_HASH_BYTES = 500 * 1024 * 1024
_HASH_CHUNK = 1024 * 1024


def file_entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence in bits, range [0, 8]."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = 0.0
    for f in freq:
        if f:
            p = f / n
            entropy -= p * math.log2(p)
    return entropy


def sha256_file(path: str) -> Optional[str]:
    """Streaming SHA256. Returns hex digest (no prefix) or None on read error."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            total = 0
            while True:
                chunk = f.read(_HASH_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_HASH_BYTES:
                    # UNCERTAIN: silently truncate or return None? v1 truncates and
                    # returns the partial hash; mark with a sentinel field in caller.
                    h.update(chunk)
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def magic_vs_extension(path: str, head: bytes) -> Optional[str]:
    """Return a short flag describing magic/extension mismatch, or None if consistent.

    Only flags the case the spec calls out: MZ header on a file whose extension
    is NOT in _PE_EXTENSIONS. Other formats (e.g. ELF on Windows) could be added.
    """
    if len(head) < 2:
        return None
    ext = os.path.splitext(path)[1].lower()
    if head[:2] == b"MZ" and ext and ext not in _PE_EXTENSIONS:
        return f"mismatch:claimed_{ext.lstrip('.') or 'noext'}_is_PE"
    return None


def _pe_signature(head: bytes) -> str:
    """Cheap signature classification from the first ~64 bytes.

    PE32 vs PE32+ requires reading the optional header; we defer to pefile for
    that. This is only used as a fallback when pefile isn't available.
    """
    if len(head) >= 2 and head[:2] == b"MZ":
        return "PE"
    return ""


def analyze_path(path: str, *, compute_hash: bool = True,
                  compute_entropy: bool = True) -> dict:
    """One-shot static analysis.

    Returns a dict with whatever fields could be computed; keys may be absent if
    the file is not a PE or pefile is unavailable. Never raises — non-PE files
    return at least {sha256, signature, magic_mismatch}.

    Caller (mft_collector) is responsible for deciding whether to include each
    field in the emitted record.

    compute_entropy=False skips the full-file entropy read and RESOURCE directory
    parsing (which can be slow for large legitimate DLLs).
    """
    result: dict = {}
    if not os.path.isfile(path):
        return result

    # Hash + magic bytes (cheap, always do these)
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
    except (OSError, PermissionError):
        return result

    if compute_hash:
        h = sha256_file(path)
        if h:
            result["sha256"] = h

    signature_guess = _pe_signature(head)
    if signature_guess:
        result["signature"] = signature_guess

    mismatch = magic_vs_extension(path, head)
    if mismatch:
        result["magic_mismatch"] = mismatch

    # Whole-file entropy on small files only; for big files we rely on per-section
    # entropy via pefile below. Skip when compute_entropy=False to avoid reading
    # entire legitimate DLLs that aren't in suspicious paths.
    if compute_entropy:
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        if size and size <= 32 * 1024 * 1024:
            try:
                with open(path, "rb") as f:
                    result["entropy"] = round(file_entropy(f.read()), 3)
            except (OSError, PermissionError):
                pass

    if not _HAS_PEFILE or signature_guess != "PE":
        return result

    # Per-section entropy + imports + (optionally) version info via pefile.
    # Skip RESOURCE directory when compute_entropy=False — it can be hundreds of MB
    # for shell32.dll/ntdll.dll and has_version_info is only useful for suspicious files.
    dirs_to_parse = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    if compute_entropy:
        dirs_to_parse.append(pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"])
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=dirs_to_parse)
    except Exception:
        return result

    try:
        section_entropies = [s.get_entropy() for s in pe.sections]
        if section_entropies:
            result["max_section_entropy"] = round(max(section_entropies), 3)
    except Exception:
        pass

    # PE32 vs PE32+: optional header magic 0x10b == PE32, 0x20b == PE32+
    try:
        magic = pe.OPTIONAL_HEADER.Magic
        result["signature"] = "PE32+" if magic == 0x20b else "PE32"
    except Exception:
        pass

    # VERSIONINFO presence — only available when RESOURCE directory was parsed.
    if compute_entropy:
        has_version = False
        try:
            if hasattr(pe, "VS_VERSIONINFO") and pe.VS_VERSIONINFO:
                has_version = True
            elif hasattr(pe, "FileInfo") and pe.FileInfo:
                has_version = True
        except Exception:
            pass
        result["has_version_info"] = has_version

    # Suspicious imports
    suspicious = []
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for imp in pe.DIRECTORY_ENTRY_IMPORT:
                for func in imp.imports:
                    if func.name:
                        name = func.name.decode(errors="replace")
                        if name in _SUSPICIOUS_IMPORTS:
                            suspicious.append(name)
    except Exception:
        pass
    if suspicious:
        # join for the key=value line format; semicolon to avoid spaces
        result["suspicious_imports"] = ";".join(sorted(set(suspicious)))

    try:
        pe.close()
    except Exception:
        pass

    return result
