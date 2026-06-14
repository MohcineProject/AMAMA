"""Deterministic entity-type normaliser — one source of truth (summary #11).

Per-module agents and scan-result emitters set an entity's ``type`` straight from
free-form LLM output. An *in-enum but wrong* type (e.g. ``domain: SDELETE.EXE``,
``file_path: 193.93.62.0/24``, ``file_path: SRL-FORGE\\fredr``) passes JSON-schema
validation — the value *is* in the enum — yet is semantically wrong, and the error
flows straight into the case graph and the final report.

This module infers the correct type from the value's *shape* and corrects mismatches,
logging every override for the audit trail. It is deliberately conservative: when the
shape is ambiguous it keeps the declared type rather than guessing, so types that
cannot be shape-detected (``pid``, ``mutex``) are preserved.
"""

from __future__ import annotations

import os
import re

# Canonical entity-type enum — mirrors Backbone/schemas/*.json.
ENTITY_TYPES: tuple[str, ...] = (
    "ip", "domain", "url",
    "hash_md5", "hash_sha1", "hash_sha256",
    "file_path", "image_name",
    "pid", "registry_key", "mutex", "user_sid",
)

_REGISTRY_RE = re.compile(r"^(hk(lm|cu|u|cr|cc)\\|hkey_)", re.IGNORECASE)
_URL_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
# IPv4 or IPv4 CIDR (matched against the leading token so a trailing annotation
# such as "193.93.62.0/24 (subnet)" still resolves to `ip`).
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_SID_RE = re.compile(r"^S-\d-\d+(?:-\d+)+$", re.IGNORECASE)
# UPN: user@host.tld (no path separators).
_UPN_RE = re.compile(r"^[^\s@\\/]+@[^\s@\\/]+\.[a-z]{2,}$", re.IGNORECASE)
# NetBIOS account: DOMAIN\user — exactly one backslash, no drive colon, no extension.
_NETBIOS_ACCT_RE = re.compile(r"^[A-Za-z0-9.\-]+\\[A-Za-z0-9._$\-]+$")
# Windows kernel-object namespaces — a ``Global\Foo`` value is a mutex/object, not
# a DOMAIN\user account, so it must not be coerced to user_sid.
_OBJECT_NS_RE = re.compile(r"^(global|local|session|basenamedobjects)\\", re.IGNORECASE)
# Dotted hostname with an alphabetic TLD.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_DRIVE_PATH_RE = re.compile(r"^[a-zA-Z]:[\\/]")
_POSIX_PATH_RE = re.compile(
    r"^/(?:usr|tmp|var|home|opt|etc|bin|sbin|root|mnt|proc|dev|srv|lib)\b", re.IGNORECASE
)
# Executable / script extensions that are NOT also common TLDs (`.com` is excluded
# on purpose so a domain like ``evil.com`` is not mislabelled ``image_name``).
_EXE_EXTS = {".exe", ".dll", ".sys", ".scr", ".bat", ".ps1", ".vbs", ".msi", ".cmd"}
_FILE_EXT_RE = re.compile(r"\.[A-Za-z0-9]{1,8}$")


def _ext(value: str) -> str:
    return os.path.splitext(value)[1].lower()


def _infer_type(value: str) -> str | None:
    """Infer the entity type from the value's shape. Returns None when unsure."""
    s = value.strip()
    if not s:
        return None

    if _REGISTRY_RE.match(s):
        return "registry_key"
    if _URL_RE.match(s):
        return "url"

    # IP / CIDR — test the leading token so trailing annotations don't block it.
    head = s.split()[0].rstrip(",;")
    if _IP_RE.match(head):
        return "ip"

    if _SID_RE.match(s) or _UPN_RE.match(s):
        return "user_sid"

    # Pure hex of a hash length (no separators ⇒ not a path).
    if _HEX_RE.match(s):
        n = len(s)
        if n == 32:
            return "hash_md5"
        if n == 40:
            return "hash_sha1"
        if n == 64:
            return "hash_sha256"

    # DOMAIN\user account (single backslash, not a drive path, not a kernel object).
    if ":" not in s and _NETBIOS_ACCT_RE.match(s) and not _OBJECT_NS_RE.match(s):
        return "user_sid"

    # Filesystem path — only when it clearly looks like one, so a mutex such as
    # ``Global\RAT_42`` (backslash but no drive/extension) is NOT clobbered.
    has_sep = "\\" in s or "/" in s
    if (
        _DRIVE_PATH_RE.match(s)
        or s.startswith("\\\\")
        or _POSIX_PATH_RE.match(s)
        or (has_sep and _FILE_EXT_RE.search(s))
    ):
        return "file_path"

    # Bare executable / library name (no separator) — checked BEFORE domain so
    # ``SDELETE.EXE`` resolves to image_name, not domain.
    if not has_sep and _ext(s) in _EXE_EXTS:
        return "image_name"

    # Dotted hostname with an alphabetic TLD.
    if not has_sep and _DOMAIN_RE.match(s):
        return "domain"

    return None


def normalize_entity_type(value: str, declared: str | None = None) -> str:
    """Return the shape-correct entity type for ``value``.

    When ``declared`` is given and the inferred type disagrees, the inferred type
    wins and the override is logged. When the shape is ambiguous (inference returns
    None) the declared type is kept (or ``image_name`` as a last-resort fallback,
    matching the modules' historical default).
    """
    inferred = _infer_type(value or "")

    if inferred is None:
        if declared in ENTITY_TYPES:
            return declared
        return "image_name"

    if declared and declared != inferred:
        print(
            f"[normalize] WARN: {value!r} declared {declared!r} → {inferred!r} "
            f"(value shape mismatch)",
            flush=True,
        )
    return inferred


def normalize_entity(entity: dict) -> dict:
    """Correct ``entity['type']`` in place from ``entity['value']``. Returns it."""
    if isinstance(entity, dict) and entity.get("value"):
        entity["type"] = normalize_entity_type(entity["value"], entity.get("type"))
    return entity
