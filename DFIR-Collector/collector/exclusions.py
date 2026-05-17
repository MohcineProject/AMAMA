"""
exclusions.py — 21-rule filter for known-benign Windows system processes.

Confidence: HIGH for rule structure; MEDIUM for field-level comparisons.

NEEDS TESTING areas:
- TEST-EXCL-01: Does Volatility return ImageFileName with or without ".exe"?
  This module assumes WITH ".exe". Volatility truncates ImageFileName at 14 chars,
  so "fontdrvhost.exe" (15) appears as "fontdrvhost.ex" and
  "SearchIndexer.exe" (17) appears as "SearchIndexer." — all rule comparisons
  use _name_matches() which accepts both the full and 14-char truncated forms.
- TEST-EXCL-02: Does the path column return a proper Win32 path like
  "C:\\Windows\\System32\\lsass.exe" or a device path? This module assumes
  Win32 path is in ProcessRecord.path (the 'Path' column from pstree).
  Path column is NOT truncated — full filename is present.
- TEST-EXCL-03: Is session == None correct for kernel processes (PID 4, etc.)?
  Volatility reports "N/A" for SessionId on kernel processes. The merge step
  should convert "N/A" to None. Verify this in merge.py.
- TEST-EXCL-04: Does svchost exclusion (Rule 10/11) correctly match all
  legitimate svchost instances? On a real dump, run the clean baseline and
  confirm all svchost entries are excluded.
- TEST-EXCL-05: The lsass "no children" check (Rule 9 hard override) requires
  the children_map. Confirm this is computed from AFTER exclusions are applied
  or BEFORE. Currently it is computed BEFORE exclusions, so a child that would
  itself be excluded still causes lsass to fail the no-children check.
  This is the CONSERVATIVE choice (safer, may produce false positives for
  lsass if it has an excluded child). NEEDS REVIEW.

Design choices:
1. The `is_excluded` function is called once per process BEFORE building the
   tree. It receives the full (pre-exclusion) record set.
2. Instance counting uses alive instances only (is_alive == True) for rules
   that say "exactly 1" without specifying exit-time conditions. Rules that
   explicitly mention ExitTime (Rules 4, 11) include terminated instances.
3. Parent lookup: we look up PPID in the raw records dict. If the parent was
   already excluded (e.g., a legitimate smss.exe was excluded), its children
   may fail the parent-name check. To prevent cascading false positives, we
   check parent name ONLY IF parent record exists in the dict; if it does not
   exist (parent already excluded or never collected), we consider the parent-
   name condition FAILED and do NOT exclude the child.
   ALTERNATIVE: resolve parent names from the raw pstree Audit path. Not chosen
   because that field may be empty.
4. Path matching: case-insensitive comparison on the Win32 path field.
   The expected paths in the rules are normalized to lowercase.
   Path values from pstree's 'Path' column are NOT truncated (only ImageFileName
   is truncated at 14 chars). So path comparisons are always against full names.
"""

from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict
from typing import Optional

from .merge import ProcessRecord

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Expected canonical Win32 paths — all lowercase for case-insensitive matching.
# NEEDS TESTING: verify actual path values returned by Volatility before
# trusting these comparisons (TEST-EXCL-02).
# ---------------------------------------------------------------------------
_SYS32 = r"c:\windows\system32"
_WBEM = rf"{_SYS32}\wbem"


def _path_in(path: str, directory: str) -> bool:
    """True if path starts with directory (case-insensitive)."""
    return path.lower().startswith(directory.lower())


def _path_is(path: str, expected: str) -> bool:
    """True if path exactly matches expected (case-insensitive)."""
    return path.lower() == expected.lower()


def _name_matches(actual: str, expected_full: str) -> bool:
    """
    Case-insensitive match that also accepts Volatility's 14-char truncated form.

    Volatility caps ImageFileName at 14 characters, so:
      fontdrvhost.exe  (15 chars) → fontdrvhost.ex
      SearchIndexer.exe (17 chars) → SearchIndexer.
    Returns True if actual equals expected_full OR its 14-char prefix.
    Path values from the 'Path' column are NOT affected (full names present).
    """
    a = actual.lower()
    e = expected_full.lower()
    return a == e or a == e[:14]


def _parent_name(
    record: ProcessRecord, all_records: dict[int, ProcessRecord]
) -> Optional[str]:
    """Return the ImageFileName of the parent process, or None if not found."""
    parent = all_records.get(record.ppid)
    if parent is None:
        return None
    return parent.image_lower


def _parent_cmd(
    record: ProcessRecord, all_records: dict[int, ProcessRecord]
) -> str:
    """Return the command line of the parent process."""
    parent = all_records.get(record.ppid)
    if parent is None:
        return ""
    return parent.cmd.lower()


def _children_of(pid: int, children_map: dict[int, list[int]]) -> list[int]:
    return children_map.get(pid, [])


# ---------------------------------------------------------------------------
# Pre-computation helpers
# ---------------------------------------------------------------------------

def _build_children_map(all_records: dict[int, ProcessRecord]) -> dict[int, list[int]]:
    cm: dict[int, list[int]] = defaultdict(list)
    for pid, rec in all_records.items():
        cm[rec.ppid].append(pid)
    return cm


def _alive_instance_count(image_lower: str, all_records: dict[int, ProcessRecord]) -> int:
    """Count alive instances whose ImageFileName matches image_lower exactly.

    Callers should pass r.image_lower (the actual observed name) rather than a
    hardcoded expected name, so that truncated names are compared like-for-like.
    """
    return sum(
        1 for r in all_records.values()
        if r.image_lower == image_lower and r.is_alive
    )


def _total_instance_count(image_lower: str, all_records: dict[int, ProcessRecord]) -> int:
    """Count all instances (alive + exited) matching image_lower exactly."""
    return sum(1 for r in all_records.values() if r.image_lower == image_lower)


# ---------------------------------------------------------------------------
# Hard overrides — any True means process is NOT excluded, regardless of rules.
# ---------------------------------------------------------------------------

def _override_wrong_path(record: ProcessRecord, expected_dir: str) -> bool:
    """True (override) if process path is NOT in the expected directory."""
    if not record.path:
        # Empty path — treat as NOT matching expected dir → override fires.
        # Exception: some kernel pseudo-processes have no path and that is expected;
        # the individual rules handle this via "path absent" condition.
        return True
    return not _path_in(record.path, expected_dir)


def _override_wow64(record: ProcessRecord) -> bool:
    """True (override) if WoW64 is True (32-bit on 64-bit host)."""
    return record.wow64


def _override_wrong_parent(
    record: ProcessRecord,
    all_records: dict[int, ProcessRecord],
    expected_parent: str,
    *,
    strict_parent: bool = True,
) -> bool:
    """True (override) if parent name does not match expected.

    Uses _name_matches so Volatility's 14-char truncation does not cause
    false mismatches (e.g. expected 'fontdrvhost.exe' vs actual 'fontdrvhost.ex').

    strict_parent: when True (default), a missing parent record causes the
    override to fire (conservative). Set False for processes whose parents
    (transient smss copies) are guaranteed to exit before the dump is taken —
    in that case a missing parent is expected and does NOT void exclusion.
    """
    parent_name = _parent_name(record, all_records)
    if parent_name is None:
        return strict_parent
    return not _name_matches(parent_name, expected_parent)


def _override_has_children(record: ProcessRecord, children_map: dict[int, list[int]]) -> bool:
    """True (override) if process has any child processes."""
    return len(_children_of(record.pid, children_map)) > 0


def _override_instance_count_exceeded(
    record: ProcessRecord, all_records: dict[int, ProcessRecord], max_alive: int
) -> bool:
    """True (override) if alive instance count for this image exceeds max_alive."""
    return _alive_instance_count(record.image_lower, all_records) > max_alive


def _override_should_have_exited(record: ProcessRecord) -> bool:
    """True (override) if rule requires ExitTime but process is still alive."""
    return record.is_alive


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def filter_excluded(all_records: dict[int, ProcessRecord]) -> dict[int, ProcessRecord]:
    """
    Return a new dict containing only records that are NOT excluded.

    Calls is_excluded() for each record. Pre-computes the children_map once.
    """
    children_map = _build_children_map(all_records)
    kept: dict[int, ProcessRecord] = {}
    excluded_count = 0

    for pid, rec in all_records.items():
        if is_excluded(rec, all_records, children_map):
            log.debug("Excluded PID %d (%s)", pid, rec.image)
            excluded_count += 1
        else:
            kept[pid] = rec

    log.info(
        "exclusions: %d excluded, %d remaining",
        excluded_count, len(kept)
    )
    return kept


def is_excluded(
    record: ProcessRecord,
    all_records: dict[int, ProcessRecord],
    children_map: dict[int, list[int]],
) -> bool:
    """
    Return True if this process matches a benign exclusion rule AND no hard
    override fires.

    Rules are tried in order 1-21; first match returns True.
    If no rule matches, returns False (process is kept for triage).
    """
    for rule_fn in _RULES:
        result = rule_fn(record, all_records, children_map)
        if result:
            return True
    return False


# ---------------------------------------------------------------------------
# Rule implementations
# ---------------------------------------------------------------------------

def _rule01_system(r, all_records, cm):
    """Rule 1 — System (Kernel) process."""
    if not _name_matches(r.image_lower, "system"):
        return False
    if r.pid != 4 or r.ppid != 0:
        return False
    if r.path:  # System has no path
        return False
    if r.wow64:
        return False
    if r.session is not None:  # session should be N/A → None
        return False
    # Exactly 1 instance
    if _total_instance_count(r.image_lower, all_records) != 1:
        return False
    return True


def _rule02_memcompression(r, all_records, cm):
    """Rule 2 — MemCompression (virtual process)."""
    if not _name_matches(r.image_lower, "memcompression"):
        return False
    if r.ppid != 4:
        return False
    if r.path:  # virtual process has no path
        return False
    if r.wow64:
        return False
    if r.session is not None:
        return False
    if _total_instance_count(r.image_lower, all_records) != 1:
        return False
    return True


def _rule03_smss_root(r, all_records, cm):
    """Rule 3 — smss.exe root instance (parent = System)."""
    if not _name_matches(r.image_lower, "smss.exe"):
        return False
    if _override_wow64(r):
        return False
    if not _path_is(r.path, rf"{_SYS32}\smss.exe"):
        return False
    # Parent must be System
    parent_name = _parent_name(r, all_records)
    if not _name_matches(parent_name or "", "system"):
        return False
    if r.session is not None:
        return False
    # Exactly 1 smss with System as parent
    count = sum(
        1 for rec in all_records.values()
        if _name_matches(rec.image_lower, "smss.exe")
        and _name_matches(_parent_name(rec, all_records) or "", "system")
    )
    if count != 1:
        return False
    return True


def _rule04_smss_transient(r, all_records, cm):
    """Rule 4 — smss.exe per-session transient copies (parent = smss.exe, already exited)."""
    if not _name_matches(r.image_lower, "smss.exe"):
        return False
    if _override_wow64(r):
        return False
    if not _path_is(r.path, rf"{_SYS32}\smss.exe"):
        return False
    parent_name = _parent_name(r, all_records)
    if not _name_matches(parent_name or "", "smss.exe"):
        return False
    # Must have exited
    if _override_should_have_exited(r):
        return False
    if r.threads != 0:
        return False
    return True


def _rule05_csrss(r, all_records, cm):
    """Rule 5 — csrss.exe (parent = smss.exe, proper cmd).

    Transient smss copies always exit before the dump, so their child csrss
    processes appear as orphans. strict_parent=False allows exclusion even
    when the parent record is absent.
    """
    if not _name_matches(r.image_lower, "csrss.exe"):
        return False
    if _override_wow64(r):
        return False
    if not _path_is(r.path, rf"{_SYS32}\csrss.exe"):
        return False
    if _override_wrong_parent(r, all_records, "smss.exe", strict_parent=False):
        return False
    # CmdLine must start with %SystemRoot%\system32\csrss.exe and contain ObjectDirectory=\Windows
    # NEEDS TESTING: cmd may be empty if pstree didn't recover it.
    # If cmd is empty we cannot verify this condition — treat as potentially suspicious.
    cmd = r.cmd.lower()
    if cmd:
        if not cmd.startswith("%systemroot%\\system32\\csrss.exe") and \
           not cmd.startswith("c:\\windows\\system32\\csrss.exe"):
            return False
        if "objectdirectory=\\windows" not in cmd:
            return False
    # At most 1 per session
    if r.session is not None:
        session_count = sum(
            1 for rec in all_records.values()
            if _name_matches(rec.image_lower, "csrss.exe") and rec.session == r.session
        )
        if session_count > 1:
            return False
    return True


def _rule06_wininit(r, all_records, cm):
    """Rule 6 — wininit.exe (parent = smss.exe, Session 0, exactly 1).

    Transient smss always exits before dump. strict_parent=False.
    """
    if not _name_matches(r.image_lower, "wininit.exe"):
        return False
    if _override_wow64(r):
        return False
    if not _path_is(r.path, rf"{_SYS32}\wininit.exe"):
        return False
    if _override_wrong_parent(r, all_records, "smss.exe", strict_parent=False):
        return False
    if r.session != 0:
        return False
    if _alive_instance_count(r.image_lower, all_records) != 1:
        return False
    return True


def _rule07_winlogon(r, all_records, cm):
    """Rule 7 — winlogon.exe (parent = smss.exe, Session >= 1).

    Transient smss always exits before dump. strict_parent=False.
    """
    if not _name_matches(r.image_lower, "winlogon.exe"):
        return False
    if _override_wow64(r):
        return False
    if not _path_is(r.path, rf"{_SYS32}\winlogon.exe"):
        return False
    if _override_wrong_parent(r, all_records, "smss.exe", strict_parent=False):
        return False
    if r.session is None or r.session < 1:
        return False
    # At most 1 per interactive session
    if r.session is not None:
        session_count = sum(
            1 for rec in all_records.values()
            if _name_matches(rec.image_lower, "winlogon.exe")
            and rec.session == r.session
            and rec.is_alive
        )
        if session_count > 1:
            return False
    return True


def _rule08_services(r, all_records, cm):
    """Rule 8 — services.exe (parent = wininit.exe, Session 0, exactly 1)."""
    if not _name_matches(r.image_lower, "services.exe"):
        return False
    if _override_wow64(r):
        return False
    if not _path_is(r.path, rf"{_SYS32}\services.exe"):
        return False
    if _override_wrong_parent(r, all_records, "wininit.exe"):
        return False
    if r.session != 0:
        return False
    if _alive_instance_count(r.image_lower, all_records) != 1:
        return False
    return True


def _rule09_lsass(r, all_records, cm):
    """Rule 9 — lsass.exe (parent = wininit.exe, Session 0, exactly 1, NO children)."""
    if not _name_matches(r.image_lower, "lsass.exe"):
        return False
    if _override_wow64(r):
        return False
    if not _path_is(r.path, rf"{_SYS32}\lsass.exe"):
        return False
    if _override_wrong_parent(r, all_records, "wininit.exe"):
        return False
    if r.session != 0:
        return False
    if _alive_instance_count(r.image_lower, all_records) != 1:
        return False
    # Hard override: lsass must have NO children
    # NEEDS TESTING (TEST-EXCL-05): children_map is built from all records
    # (pre-exclusion), so an excluded child still counts here. This is the
    # conservative choice — any child makes this rule fail.
    if _override_has_children(r, cm):
        return False
    return True


def _rule10_svchost_running(r, all_records, cm):
    """Rule 10 — svchost.exe running (parent = services.exe, has -k in cmd, still alive)."""
    if not _name_matches(r.image_lower, "svchost.exe"):
        return False
    if _override_wow64(r):
        return False
    if not _path_is(r.path, rf"{_SYS32}\svchost.exe"):
        return False
    if _override_wrong_parent(r, all_records, "services.exe"):
        return False
    if r.session != 0:
        return False
    if not r.is_alive:
        return False
    # CmdLine must contain -k
    # NEEDS TESTING: if cmd is empty (vol3_runner cmd gap), we cannot verify.
    # Conservative: if cmd is empty we do NOT exclude (safer).
    if r.cmd:
        if " -k " not in r.cmd.lower() and r.cmd.lower().endswith(" -k"):
            # "-k" could be at end too, handle both
            pass
        cmd_lower = r.cmd.lower()
        if "-k" not in cmd_lower:
            return False
    else:
        # cmd empty — cannot verify -k → do not exclude
        # NEEDS TESTING: on a clean dump, are svchost cmd lines always recovered?
        log.debug("PID %d svchost: cmd empty, cannot verify -k — not excluding", r.pid)
        return False
    return True


def _rule11_svchost_terminated(r, all_records, cm):
    """Rule 11 — svchost.exe terminated (parent = services.exe, exited, Threads=0)."""
    if not _name_matches(r.image_lower, "svchost.exe"):
        return False
    if _override_wow64(r):
        return False
    if not _path_is(r.path, rf"{_SYS32}\svchost.exe"):
        return False
    if _override_wrong_parent(r, all_records, "services.exe"):
        return False
    if r.session != 0:
        return False
    if _override_should_have_exited(r):  # inverted: must have exited
        return False
    if r.threads != 0:
        return False
    # Note: -k cmdline check is RELAXED for terminated instances (Rule 11)
    return True


def _rule12_fontdrvhost(r, all_records, cm):
    """Rule 12 — fontdrvhost.exe (parent = wininit.exe OR winlogon.exe).

    Vol3 truncates 'fontdrvhost.exe' (15 chars) to 'fontdrvhost.ex' (14 chars).
    _name_matches() handles both forms.
    """
    if not _name_matches(r.image_lower, "fontdrvhost.exe"):
        return False
    if _override_wow64(r):
        return False
    # Path column is NOT truncated — full filename present.
    if not _path_is(r.path, rf"{_SYS32}\fontdrvhost.exe"):
        return False
    parent_name = _parent_name(r, all_records)
    if not (
        _name_matches(parent_name or "", "wininit.exe")
        or _name_matches(parent_name or "", "winlogon.exe")
    ):
        return False
    # At most 1 per qualifying parent
    parent_pid = r.ppid
    siblings_with_same_parent = sum(
        1 for rec in all_records.values()
        if _name_matches(rec.image_lower, "fontdrvhost.exe") and rec.ppid == parent_pid
    )
    if siblings_with_same_parent > 1:
        return False
    return True


def _rule13_dwm(r, all_records, cm):
    """Rule 13 — dwm.exe (parent = winlogon.exe, Session >= 1)."""
    if not _name_matches(r.image_lower, "dwm.exe"):
        return False
    if _override_wow64(r):
        return False
    if not _path_is(r.path, rf"{_SYS32}\dwm.exe"):
        return False
    if _override_wrong_parent(r, all_records, "winlogon.exe"):
        return False
    if r.session is None or r.session < 1:
        return False
    # At most 1 per interactive session
    if r.session is not None:
        session_count = sum(
            1 for rec in all_records.values()
            if _name_matches(rec.image_lower, "dwm.exe")
            and rec.session == r.session
            and rec.is_alive
        )
        if session_count > 1:
            return False
    return True


def _rule14_logonui(r, all_records, cm):
    """Rule 14 — LogonUI.exe (parent = winlogon.exe, Session >= 1)."""
    if not _name_matches(r.image_lower, "logonui.exe"):
        return False
    if _override_wow64(r):
        return False
    if not _path_is(r.path, rf"{_SYS32}\logonui.exe"):
        return False
    if _override_wrong_parent(r, all_records, "winlogon.exe"):
        return False
    if r.session is None or r.session < 1:
        return False
    return True


def _rule15_spoolsv(r, all_records, cm):
    """Rule 15 — spoolsv.exe (parent = services.exe, Session 0, exactly 1)."""
    if not _name_matches(r.image_lower, "spoolsv.exe"):
        return False
    if _override_wow64(r):
        return False
    if not _path_is(r.path, rf"{_SYS32}\spoolsv.exe"):
        return False
    if _override_wrong_parent(r, all_records, "services.exe"):
        return False
    if r.session != 0:
        return False
    if _alive_instance_count(r.image_lower, all_records) != 1:
        return False
    return True


def _rule16_msdtc(r, all_records, cm):
    """Rule 16 — msdtc.exe (parent = services.exe, Session 0, exactly 1)."""
    if not _name_matches(r.image_lower, "msdtc.exe"):
        return False
    if _override_wow64(r):
        return False
    if not _path_is(r.path, rf"{_SYS32}\msdtc.exe"):
        return False
    if _override_wrong_parent(r, all_records, "services.exe"):
        return False
    if r.session != 0:
        return False
    if _alive_instance_count(r.image_lower, all_records) != 1:
        return False
    return True


def _rule17_searchindexer(r, all_records, cm):
    """Rule 17 — SearchIndexer.exe (parent = services.exe, /Embedding in cmd, exactly 1).

    Vol3 truncates 'SearchIndexer.exe' (17 chars) to 'SearchIndexer.' (14 chars).
    _name_matches() handles both forms.
    """
    if not _name_matches(r.image_lower, "searchindexer.exe"):
        return False
    if _override_wow64(r):
        return False
    # Path column is NOT truncated — full filename present.
    if not _path_is(r.path, rf"{_SYS32}\searchindexer.exe"):
        return False
    if _override_wrong_parent(r, all_records, "services.exe"):
        return False
    if r.session != 0:
        return False
    if r.cmd and "/embedding" not in r.cmd.lower():
        return False
    if _alive_instance_count(r.image_lower, all_records) != 1:
        return False
    return True


def _rule18_wmiprvse(r, all_records, cm):
    """Rule 18 — WmiPrvSE.exe (parent = svchost.exe with -k DcomLaunch, Session 0)."""
    if not _name_matches(r.image_lower, "wmiprvse.exe"):
        return False
    if _override_wow64(r):
        return False
    if not _path_is(r.path, rf"{_WBEM}\wmiprvse.exe"):
        return False
    parent_name = _parent_name(r, all_records)
    if not _name_matches(parent_name or "", "svchost.exe"):
        return False
    # Parent svchost must have -k DcomLaunch in its cmdline
    parent_cmd = _parent_cmd(r, all_records)
    if parent_cmd and "dcomlaunch" not in parent_cmd:
        return False
    if r.session != 0:
        return False
    return True


def _rule19_unsecapp(r, all_records, cm):
    """Rule 19 — unsecapp.exe (parent = svchost.exe, -Embedding in cmd)."""
    if not _name_matches(r.image_lower, "unsecapp.exe"):
        return False
    if _override_wow64(r):
        return False
    if not _path_is(r.path, rf"{_WBEM}\unsecapp.exe"):
        return False
    parent_name = _parent_name(r, all_records)
    if not _name_matches(parent_name or "", "svchost.exe"):
        return False
    if r.cmd and "-embedding" not in r.cmd.lower():
        return False
    return True


_GUID_RE = re.compile(
    r"/processid:\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}",
    re.IGNORECASE
)


def _rule20_dllhost(r, all_records, cm):
    """Rule 20 — dllhost.exe (parent = svchost.exe, CmdLine has /Processid:{GUID})."""
    if not _name_matches(r.image_lower, "dllhost.exe"):
        return False
    if _override_wow64(r):
        return False
    if not _path_is(r.path, rf"{_SYS32}\dllhost.exe"):
        return False
    parent_name = _parent_name(r, all_records)
    if not _name_matches(parent_name or "", "svchost.exe"):
        return False
    # CmdLine must match /Processid:{GUID}
    if r.cmd:
        if not _GUID_RE.search(r.cmd):
            return False
    # If cmd is empty, we can't verify — conservative: do not exclude.
    # NEEDS TESTING: is dllhost cmdline reliably recovered from the dump?
    elif not r.cmd:
        return False
    return True


def _rule21_conhost(r, all_records, cm):
    """
    Rule 21 — conhost.exe (proper path, WoW64=False, CmdLine 0x4/0x0/absent,
    parent must be in C:\\Windows\\ or C:\\Program Files\\).
    """
    if not _name_matches(r.image_lower, "conhost.exe"):
        return False
    if _override_wow64(r):
        return False
    if not _path_is(r.path, rf"{_SYS32}\conhost.exe"):
        return False
    # CmdLine: must be "0x4", "0x0", or empty/absent
    cmd = r.cmd.strip() if r.cmd else ""
    if cmd and cmd.lower() not in ("0x4", "0x0", r"\??\c:\windows\system32\conhost.exe 0x4",
                                    r"\??\c:\windows\system32\conhost.exe 0x0"):
        # Allow the full command line form that Volatility typically shows:
        # \??\C:\windows\system32\conhost.exe 0x4
        if cmd.lower() not in ("0x4", "0x0") and not cmd.endswith("0x4") and not cmd.endswith("0x0"):
            return False
    # Parent must be in C:\Windows\ or C:\Program Files\
    parent = all_records.get(r.ppid)
    if parent is None:
        return False
    parent_path = parent.path.lower()
    if not (parent_path.startswith(r"c:\windows") or parent_path.startswith(r"c:\program files")):
        return False
    return True


# Ordered list of all rule functions (Rule 1 through Rule 21)
_RULES = [
    _rule01_system,
    _rule02_memcompression,
    _rule03_smss_root,
    _rule04_smss_transient,
    _rule05_csrss,
    _rule06_wininit,
    _rule07_winlogon,
    _rule08_services,
    _rule09_lsass,
    _rule10_svchost_running,
    _rule11_svchost_terminated,
    _rule12_fontdrvhost,
    _rule13_dwm,
    _rule14_logonui,
    _rule15_spoolsv,
    _rule16_msdtc,
    _rule17_searchindexer,
    _rule18_wmiprvse,
    _rule19_unsecapp,
    _rule20_dllhost,
    _rule21_conhost,
]
