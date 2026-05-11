"""Canned fixture data for the dummy analysis pipeline.

These objects look like what each real stage would emit so the frontend can be
built and demoed against believable shapes. The story they tell, when read in
order, is a plausible (and intentionally messy enough to be interesting) Office
macro -> rundll32 -> staged C:\\ProgramData implant case.

Stage outputs are intentionally JSON-serialisable plain dicts so they can be
shipped verbatim through SSE without extra pydantic round-trips.
"""

from __future__ import annotations

from typing import Any


# ---- collector (script: runs volatility, produces a high-level summary) ----

COLLECTOR_PROGRESS: list[tuple[int, str]] = [
    (5, "Hashing memory image (sha256)"),
    (15, "Detecting profile: Win10x64_19041"),
    (30, "Plugin pslist..."),
    (45, "Plugin pstree..."),
    (60, "Plugin netscan..."),
    (75, "Plugin svcscan..."),
    (90, "Plugin filescan..."),
    (100, "Writing high-level summary"),
]

COLLECTOR_RESULT: dict[str, Any] = {
    "image_info": {
        "filename": "memory.raw",
        "size_bytes": 4_294_967_296,
        "sha256": "ab12f0e1c4d9a7b3e8d6c5f4a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3",
        "profile": "Win10x64_19041",
    },
    "plugins_run": [
        "pslist", "pstree", "netscan", "cmdline", "handles", "dlllist",
        "envars", "filescan", "registry_printkey", "amcache", "shimcache", "svcscan",
    ],
    "high_level": {
        "processes_total": 187,
        "network_connections": 42,
        "services_total": 198,
        "scheduled_tasks": 23,
        "unsigned_binaries": 6,
    },
    "duration_seconds": 3.4,
}


# ---- agent1: triage analyst (LLM) ----

AGENT1_PROGRESS: list[tuple[int, str]] = [
    (20, "Reading high-level summary"),
    (50, "Scoring processes / services / paths"),
    (80, "Composing triage shortlist"),
    (100, "Done"),
]

AGENT1_RESULT: dict[str, Any] = {
    "suspicious_processes": [
        {
            "pid": 4920,
            "name": "svchost.exe",
            "path": "C:\\Users\\Public\\svchost.exe",
            "reason": "Service host binary running outside System32 (path mismatch).",
        },
        {
            "pid": 6612,
            "name": "rundll32.exe",
            "path": "C:\\Windows\\System32\\rundll32.exe",
            "reason": "Spawned by an Office process with elevated privileges.",
        },
    ],
    "suspicious_services": [
        {
            "name": "WinHelpSvc",
            "binary": "C:\\ProgramData\\winhelp.exe",
            "start_type": "Auto",
            "reason": "Unsigned binary; name typo-squats legitimate Windows components.",
        }
    ],
    "suspicious_paths": [
        {
            "path": "C:\\Users\\Public\\Downloads\\update.ps1",
            "reason": "PowerShell script staged in a world-writable path.",
        },
        {
            "path": "C:\\ProgramData\\winhelp.exe",
            "reason": "Executable dropped in ProgramData root.",
        },
        {
            "path": "C:\\ProgramData\\winhelp.dll",
            "reason": "Unsigned DLL co-located with the suspicious EXE.",
        },
    ],
    "suspicious_tasks": [
        {
            "name": "\\Microsoft\\Windows\\Maintenance\\WinUpd",
            "command": "C:\\ProgramData\\winhelp.exe -u",
            "reason": "Scheduled task masquerading as a Windows Update component.",
        }
    ],
}


# ---- grep (script: targeted pulls feeding agent2) ----

GREP_PROGRESS: list[tuple[int, str]] = [
    (25, "PID-based grep: cmdline, privileges"),
    (55, "PID-based grep: handles, dlllist, envars"),
    (80, "Path-based grep: filescan, registry_printkey"),
    (100, "Packaging context for pivot analyst"),
]

GREP_RESULT: dict[str, Any] = {
    "pivots_by_pid": {
        "4920": {
            "cmdline": "C:\\Users\\Public\\svchost.exe -k netsvcs",
            "privileges": ["SeDebugPrivilege", "SeImpersonatePrivilege", "SeTcbPrivilege"],
            "handles": [
                "\\Device\\NamedPipe\\lsass",
                "\\Sessions\\1\\BaseNamedObjects\\winhelp_ctl",
            ],
            "dlllist": ["ntdll.dll", "kernel32.dll", "wininet.dll", "crypt32.dll"],
            "envars": {"USERNAME": "SYSTEM", "TEMP": "C:\\Windows\\TEMP"},
        },
        "6612": {
            "cmdline": "rundll32.exe \"C:\\ProgramData\\winhelp.dll\",Start",
            "privileges": ["SeDebugPrivilege"],
            "handles": [],
            "dlllist": [
                "ntdll.dll", "kernel32.dll", "C:\\ProgramData\\winhelp.dll",
            ],
            "envars": {"USERNAME": "alice"},
            "parent": {"pid": 6240, "name": "WINWORD.EXE"},
        },
    },
    "pivots_by_path": {
        "C:\\ProgramData\\winhelp.exe": {
            "filescan": [
                {"offset": "0xfa800c1d2210", "path": "C:\\ProgramData\\winhelp.exe"}
            ],
            "registry_printkey": [
                {
                    "key": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinHelpSvc",
                    "value": "ImagePath",
                    "data": "C:\\ProgramData\\winhelp.exe",
                }
            ],
        },
        "C:\\Users\\Public\\Downloads\\update.ps1": {
            "filescan": [
                {"offset": "0xfa800df81a90", "path": "C:\\Users\\Public\\Downloads\\update.ps1"}
            ],
            "registry_printkey": [],
        },
    },
}


# ---- agent2: pivot analyst (LLM) ----

AGENT2_PROGRESS: list[tuple[int, str]] = [
    (20, "Examining PID 4920 (svchost.exe)"),
    (45, "Examining PID 6612 (rundll32.exe)"),
    (70, "Examining WinHelpSvc service"),
    (90, "Examining update.ps1"),
    (100, "Final verdicts"),
]

AGENT2_RESULT: dict[str, Any] = {
    "verdicts": [
        {
            "subject": "svchost.exe (PID 4920)",
            "verdict": "confirmed_malicious",
            "confidence": 0.92,
            "rationale": (
                "svchost outside System32 + SeDebugPrivilege + handle to "
                "\\Device\\NamedPipe\\lsass is consistent with credential "
                "dumping. The '-k netsvcs' cmdline impersonates a legitimate "
                "service host but the binary path is wrong."
            ),
            "evidence_refs": [
                "pivots_by_pid.4920.cmdline",
                "pivots_by_pid.4920.privileges",
                "pivots_by_pid.4920.handles",
            ],
        },
        {
            "subject": "rundll32.exe (PID 6612) -> winhelp.dll",
            "verdict": "confirmed_malicious",
            "confidence": 0.88,
            "rationale": (
                "Spawned by WINWORD.EXE and loads an unsigned DLL from "
                "C:\\ProgramData. Classic Office-document initial access into a "
                "staged DLL."
            ),
            "evidence_refs": [
                "pivots_by_pid.6612.cmdline",
                "pivots_by_pid.6612.dlllist",
                "pivots_by_pid.6612.parent",
            ],
        },
        {
            "subject": "WinHelpSvc service",
            "verdict": "confirmed_malicious",
            "confidence": 0.85,
            "rationale": (
                "Auto-start service whose ImagePath points at the same "
                "ProgramData binary used by the scheduled task -- persistence "
                "with double redundancy."
            ),
            "evidence_refs": [
                "pivots_by_path.C:\\ProgramData\\winhelp.exe.registry_printkey"
            ],
        },
        {
            "subject": "update.ps1 in Public Downloads",
            "verdict": "needs_more_data",
            "confidence": 0.45,
            "rationale": (
                "Path is suspicious but no execution artifact "
                "(Prefetch/Amcache hit) was retrieved in this grep slice; "
                "rerun with widened time window."
            ),
            "evidence_refs": [],
        },
    ]
}


# ---- agent3: report writer (LLM) ----

AGENT3_PROGRESS: list[tuple[int, str]] = [
    (20, "Composing initial access section"),
    (40, "Composing execution chain"),
    (60, "Composing persistence + credential access"),
    (80, "Composing staging + files of interest"),
    (100, "Finalizing narrative"),
]

AGENT3_RESULT: dict[str, Any] = {
    "case": "INCIDENT_2025_08_08",
    "summary": (
        "Likely Office-document initial access dropping a staged DLL/EXE pair "
        "in C:\\ProgramData and establishing persistence via a fake service "
        "and a masquerading scheduled task. Credential-dumping behaviour was "
        "observed in memory."
    ),
    "sections": {
        "initial_access": (
            "WINWORD.EXE (PID 6240) spawned rundll32.exe (PID 6612) which "
            "loaded C:\\ProgramData\\winhelp.dll via "
            "rundll32.exe \"C:\\ProgramData\\winhelp.dll\",Start. This is "
            "consistent with a malicious Office document opened by user "
            "'alice'."
        ),
        "execution_chain": (
            "WINWORD.EXE -> rundll32.exe (winhelp.dll) -> deployed a fake "
            "svchost.exe in C:\\Users\\Public (PID 4920) running with "
            "SeDebugPrivilege."
        ),
        "persistence": (
            "Service 'WinHelpSvc' (Auto start, ImagePath = "
            "C:\\ProgramData\\winhelp.exe) and scheduled task "
            "\\Microsoft\\Windows\\Maintenance\\WinUpd (runs the same binary) "
            "provide redundant persistence."
        ),
        "credential_access": (
            "Fake svchost.exe held SeDebugPrivilege and a handle to "
            "\\Device\\NamedPipe\\lsass, consistent with attempted credential "
            "dumping against LSASS."
        ),
        "staging": (
            "Implant components staged under C:\\ProgramData "
            "(winhelp.exe, winhelp.dll). A PowerShell script update.ps1 was "
            "staged in C:\\Users\\Public\\Downloads but execution is not yet "
            "confirmed (downgraded to 'needs_more_data')."
        ),
        "files_of_interest": [
            "C:\\Users\\Public\\svchost.exe",
            "C:\\ProgramData\\winhelp.exe",
            "C:\\ProgramData\\winhelp.dll",
            "C:\\Users\\Public\\Downloads\\update.ps1",
        ],
    },
    "confidence_overall": 0.87,
}


# Ordered (stage_id, type, progress, result) for the runner.
PIPELINE: list[dict[str, Any]] = [
    {
        "stage": "collector",
        "kind": "script",
        "progress": COLLECTOR_PROGRESS,
        "result": COLLECTOR_RESULT,
    },
    {
        "stage": "agent1",
        "kind": "llm",
        "progress": AGENT1_PROGRESS,
        "result": AGENT1_RESULT,
    },
    {
        "stage": "grep",
        "kind": "script",
        "progress": GREP_PROGRESS,
        "result": GREP_RESULT,
    },
    {
        "stage": "agent2",
        "kind": "llm",
        "progress": AGENT2_PROGRESS,
        "result": AGENT2_RESULT,
    },
    {
        "stage": "agent3",
        "kind": "llm",
        "progress": AGENT3_PROGRESS,
        "result": AGENT3_RESULT,
    },
]
