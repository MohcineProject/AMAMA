"""
RAM Artifact Extractor — runs Volatility 3 plugins and saves raw TSV output to disk.

Three plugin tiers:
  MANDATORY_PLUGINS      (9)  — required by the collector; always run first (blocking).
  FAST_EXTENDED_PLUGINS  (15) — high-value analysis targets covering all pivot-grep
                                file lists; used in --fast mode (default).
  FULL_EXTENDED_PLUGINS  (~40)— comprehensive kernel/registry/malware sweep;
                                added on top of fast-extended in --full mode.

Fast mode = MANDATORY + FAST_EXTENDED   (24 plugins, ~5–10 min wall time, 4 workers)
Full mode = MANDATORY + FAST_EXTENDED + FULL_EXTENDED  (~65 plugins, ~15–25 min)

Public API:
  run_mandatory(image_path, artifacts_dir, ...)     — blocking, 9 plugins
  run_fast_extended(image_path, artifacts_dir, ...) — blocking, 15 plugins
  run_full_extended(image_path, artifacts_dir, ...) — blocking, ~55 plugins
  run_plugin_group(image_path, artifacts_dir, plugins, ...) — generic runner
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

VOL3_PATH = os.environ.get("VOL3_PATH", "/home/MyTools/volatility/volatility3/vol.py")
PYTHON = os.environ.get("VOL3_PYTHON", "python3")

# Images whose kernel symbol-table (ISF) cache has already been warmed this
# process. See _warmup_symbols() for why this matters.
_warmed_images: set[str] = set()


# ---------------------------------------------------------------------------
# Plugin tiers
# ---------------------------------------------------------------------------

MANDATORY_PLUGINS: dict[str, str] = {
    "windows.pstree.PsTree":    "pstree.txt",
    "windows.psscan.PsScan":    "psscan.txt",
    "windows.cmdline.CmdLine":  "cmdline.txt",
    "windows.dlllist.DllList":  "dlllist.txt",
    "windows.handles.Handles":  "handles.txt",
    "windows.privileges.Privs": "privileges.txt",
    "windows.netscan.NetScan":  "netscan.txt",
    "windows.netstat.NetStat":  "netstat.txt",
    "windows.getsids.GetSIDs":  "getsids.txt",
}

FAST_EXTENDED_PLUGINS: dict[str, str] = {
    "windows.pslist":                  "pslist.txt",
    # NOTE: classic windows.malfind dropped — windows.malware.malfind below is
    # the maintained, equivalent variant. Running both doubled the (image-size
    # dependent) memory scan cost for no extra coverage.
    "windows.ldrmodules":              "ldrmodules.txt",
    "windows.modules":                 "modules.txt",
    "windows.svcscan":                 "svcscan.txt",
    "windows.driverscan":              "driverscan.txt",
    "windows.sessions":                "sessions.txt",
    "windows.shimcachemem":            "shimcachemem.txt",
    "windows.malware.psxview":         "malware_psxview.txt",
    "windows.malware.malfind":         "malware_malfind.txt",
    "windows.malware.ldrmodules":      "malware_ldrmodules.txt",
    "windows.malware.hollowprocesses": "malware_hollowprocesses.txt",
    "windows.malware.pebmasquerade":   "malware_pebmasquerade.txt",
    "windows.registry.printkey":       "registry_printkey.txt",
    "windows.registry.hivelist":       "registry_hivelist.txt",
}

FULL_EXTENDED_PLUGINS: dict[str, str] = {
    "windows.info":                           "info.txt",
    "windows.kpcrs":                          "kpcrs.txt",
    "windows.statistics":                     "statistics.txt",
    "windows.cmdscan":                        "cmdscan.txt",
    "windows.consoles":                       "consoles.txt",
    "windows.envars":                         "envars.txt",
    "windows.joblinks":                       "joblinks.txt",
    "windows.threads":                        "threads.txt",
    "windows.thrdscan":                       "thrdscan.txt",
    "windows.modscan":                        "modscan.txt",
    "windows.unloadedmodules":                "unloadedmodules.txt",
    "windows.iat":                            "iat.txt",
    "windows.verinfo":                        "verinfo.txt",
    "windows.vadinfo":                        "vadinfo.txt",
    "windows.vadwalk":                        "vadwalk.txt",
    "windows.virtmap":                        "virtmap.txt",
    "windows.bigpools":                       "bigpools.txt",
    "windows.mutantscan":                     "mutantscan.txt",
    "windows.symlinkscan":                    "symlinkscan.txt",
    "windows.mbrscan":                        "mbrscan.txt",
    "windows.driverirp":                      "driverirp.txt",
    "windows.devicetree":                     "devicetree.txt",
    "windows.ssdt":                           "ssdt.txt",
    "windows.callbacks":                      "callbacks.txt",
    "windows.timers":                         "timers.txt",
    "windows.desktops":                       "desktops.txt",
    "windows.windowstations":                 "windowstations.txt",
    "windows.malware.processghosting":        "malware_processghosting.txt",
    "windows.malware.suspicious_threads":     "malware_suspicious_threads.txt",
    "windows.malware.directsystemcalls":      "malware_directsystemcalls.txt",
    "windows.malware.indirectsystemcalls":    "malware_indirectsystemcalls.txt",
    "windows.malware.drivermodule":           "malware_drivermodule.txt",
    "windows.malware.svcdiff":                "malware_svcdiff.txt",
    "windows.malware.skeletonkeycheck":       "malware_skeletonkeycheck.txt",
    "windows.registry.hivescan":              "registry_hivescan.txt",
    "windows.registry.amcache":               "registry_amcache.txt",
    "windows.registry.certificates":          "registry_certificates.txt",
    "windows.registry.scheduledtasks":        "registry_scheduledtasks.txt",
    "windows.registry.userassist":            "registry_userassist.txt",
    "windows.registry.hashdump":              "registry_hashdump.txt",
    "windows.registry.lsadump":               "registry_lsadump.txt",
    "windows.registry.cacheddump":            "registry_cacheddump.txt",
    "windows.registry.scheduled_tasks":       "registry_scheduled_tasks.txt",
    "windows.registry.getcellroutine":        "registry_getcellroutine.txt",
}


# ---------------------------------------------------------------------------
# Core runner
# ---------------------------------------------------------------------------

def _run_one_plugin(
    image_path: str,
    plugin: str,
    out_path: Path,
    vol_path: str,
    timeout: int,
) -> tuple[str, float, bool]:
    """Run one Volatility plugin and write stdout to out_path.

    Returns (plugin, elapsed_seconds, success).  Non-zero exit is tolerated
    when stdout is non-empty — some plugins write data then exit non-zero.
    """
    cmd = [PYTHON, vol_path, "-q", "-f", image_path, plugin]
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
        log.error("[extractor] %s timed out after %d s", plugin, timeout)
        out_path.write_text(f"# ERROR: timed out after {timeout}s\n", encoding="utf-8")
        return plugin, time.monotonic() - t0, False

    elapsed = time.monotonic() - t0
    stdout = proc.stdout or ""

    if proc.returncode != 0 and not stdout.strip():
        log.warning(
            "[extractor] %s exited %d (%.1f s) with no output; stderr: %s",
            plugin, proc.returncode, elapsed,
            (proc.stderr or "")[-300:].strip(),
        )
        out_path.write_text(
            f"# ERROR: plugin exited {proc.returncode}\n"
            f"# {(proc.stderr or '').strip()[-200:]}\n",
            encoding="utf-8",
        )
        return plugin, elapsed, False

    out_path.write_text(stdout, encoding="utf-8")

    if proc.returncode == 0:
        log.info("[extractor] %-45s  %.1f s  →  %s", plugin, elapsed, out_path.name)
    else:
        log.warning(
            "[extractor] %s exited %d (%.1f s) but produced output → %s",
            plugin, proc.returncode, elapsed, out_path.name,
        )
    return plugin, elapsed, proc.returncode == 0


def _warmup_symbols(image_path: str, vol_path: str, timeout: int = 600) -> None:
    """Build the kernel symbol-table (ISF) cache once, single-threaded.

    Volatility resolves (and on first contact with a new image, *constructs*)
    the kernel ISF symbol cache lazily. When several `vol.py` processes start
    against a cold cache simultaneously (our 4-worker pool), they race it and
    some bail out with "Unsatisfied requirement: kernel.symbol_table_name" —
    even though the image is fine. Running one fast plugin (windows.info) by
    itself first writes the cache to disk, so the subsequent parallel pool finds
    it warm. ~10s; best-effort (a failure here is non-fatal — the pool still
    runs, just without the guarantee).
    """
    if image_path in _warmed_images:
        return
    _warmed_images.add(image_path)
    cmd = [PYTHON, vol_path, "-q", "-f", image_path, "windows.info"]
    t0 = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        elapsed = time.monotonic() - t0
        if proc.returncode == 0:
            log.info("[extractor] symbol warm-up (windows.info) ok in %.1f s", elapsed)
        else:
            log.warning(
                "[extractor] symbol warm-up exited %d (%.1f s); stderr: %s",
                proc.returncode, elapsed, (proc.stderr or "")[-200:].strip(),
            )
    except subprocess.TimeoutExpired:
        log.warning("[extractor] symbol warm-up timed out after %d s", timeout)


def run_plugin_group(
    image_path: str,
    artifacts_dir: Path,
    plugins: dict[str, str],
    vol_path: str = VOL3_PATH,
    workers: int = 4,
    timeout: int = 3600,
    log_file: Optional[Path] = None,
) -> dict[str, bool]:
    """Run a {plugin: filename} dict in parallel via a thread pool.

    Writes each plugin's stdout to artifacts_dir/filename.
    Appends a timing summary to log_file (default: artifacts_dir/run_log.txt).
    Returns {plugin: success}.
    """
    artifacts_dir = Path(artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_file or (artifacts_dir / "run_log.txt")

    # Warm the symbol cache once (single-threaded) before launching the pool,
    # so concurrent vol.py workers don't race a cold ISF cache.
    _warmup_symbols(image_path, vol_path)

    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _append_log(log_path, f"\n=== Plugin group started {started} ({len(plugins)} plugins) ===\n")

    results: dict[str, bool] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {
            pool.submit(
                _run_one_plugin,
                image_path,
                plugin,
                artifacts_dir / filename,
                vol_path,
                timeout,
            ): (plugin, filename)
            for plugin, filename in plugins.items()
        }
        for fut in as_completed(future_map):
            plugin, filename = future_map[fut]
            try:
                _, elapsed, ok = fut.result()
            except Exception as exc:
                log.error("[extractor] %s raised: %s", plugin, exc)
                elapsed, ok = 0.0, False
            results[plugin] = ok
            status = "DONE " if ok else "ERROR"
            _append_log(log_path, f"[{status}] {plugin:50s} ({elapsed:6.1f}s) → {filename}\n")

    done = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    n_ok = sum(results.values())
    _append_log(
        log_path,
        f"=== Group complete {done}: {n_ok}/{len(plugins)} succeeded ===\n",
    )
    return results


def run_mandatory(
    image_path: str,
    artifacts_dir: Path,
    *,
    no_handles: bool = False,
    vol_path: str = VOL3_PATH,
    workers: int = 4,
    timeout: int = 3600,
) -> dict[str, bool]:
    """Run the 9 mandatory collector plugins (blocking, parallel).

    If no_handles=True, skips windows.handles.Handles so the collector starts
    faster; chunks will have empty handle fields.
    """
    _validate(image_path, vol_path)
    plugins = dict(MANDATORY_PLUGINS)
    if no_handles:
        plugins.pop("windows.handles.Handles", None)
    log.info("[extractor] Mandatory: %d plugins, workers=%d", len(plugins), workers)
    return run_plugin_group(image_path, Path(artifacts_dir), plugins, vol_path, workers, timeout)


def run_fast_extended(
    image_path: str,
    artifacts_dir: Path,
    *,
    vol_path: str = VOL3_PATH,
    workers: int = 4,
    timeout: int = 3600,
) -> dict[str, bool]:
    """Run the 15 high-value fast-extended plugins (blocking, parallel)."""
    _validate(image_path, vol_path)
    log.info("[extractor] Fast-extended: %d plugins, workers=%d", len(FAST_EXTENDED_PLUGINS), workers)
    return run_plugin_group(
        image_path, Path(artifacts_dir), FAST_EXTENDED_PLUGINS, vol_path, workers, timeout
    )


def run_full_extended(
    image_path: str,
    artifacts_dir: Path,
    *,
    vol_path: str = VOL3_PATH,
    workers: int = 4,
    timeout: int = 3600,
) -> dict[str, bool]:
    """Run fast-extended + full-extended plugins (~55 total, blocking, parallel)."""
    _validate(image_path, vol_path)
    all_extended = {**FAST_EXTENDED_PLUGINS, **FULL_EXTENDED_PLUGINS}
    log.info("[extractor] Full-extended: %d plugins, workers=%d", len(all_extended), workers)
    return run_plugin_group(
        image_path, Path(artifacts_dir), all_extended, vol_path, workers, timeout
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate(image_path: str, vol_path: str) -> None:
    if not Path(image_path).exists():
        raise FileNotFoundError(f"Memory image not found: {image_path}")
    if not Path(vol_path).exists():
        raise FileNotFoundError(
            f"Volatility 3 not found at: {vol_path}\n\n"
            "To fix, choose one option:\n"
            "  CLI flag  : --vol-path /path/to/volatility3/vol.py\n"
            "  Env var   : export VOL3_PATH=/path/to/volatility3/vol.py\n\n"
            "vol.py lives in the root of your Volatility 3 install directory.\n"
            "Example paths:\n"
            "  /opt/volatility3/vol.py\n"
            "  /home/<user>/tools/volatility3/vol.py\n"
            "  /usr/local/volatility3/vol.py"
        )


def _append_log(log_path: Path, text: str) -> None:
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(text)
