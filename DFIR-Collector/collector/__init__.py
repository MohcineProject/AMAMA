"""
collector — Volatility 3 process-forest extractor for FIND_EVIL Agent 1.

Public API:
    run_collector(...)
        Run the full pipeline and write OUTPUT_OF_COLLECTOR/chunk_NNN.txt files.
        Returns the number of chunk files written.

Modes:
    image_path   — production path: shell out to Volatility, parse TSV.
    folder_path  — dev path: read pre-computed TSV files from a folder.
                   Skips the slow Volatility run; useful for testing parsers and
                   exclusion rules against known-good output.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


def run_collector(
    *,
    image_path: Optional[str] = None,
    folder_path: Optional[str] = None,
    output_dir: str = "./OUTPUT_OF_COLLECTOR",
    max_chunk_tokens: int = 8000,
    include_handles: bool = True,
    force: bool = False,
) -> int:
    """
    Run the full collector pipeline and write chunk files into output_dir.

    Exactly one of image_path or folder_path must be provided.

    Args:
        image_path:       Path to Windows memory image (runs Vol3 via subprocess).
        folder_path:      Path to folder containing pre-computed TSV files
                          (pstree.txt, psscan.txt, cmdline.txt, dlllist.txt,
                          handles.txt, privileges.txt, netscan.txt, netstat.txt,
                          getsids.txt). Missing files produce empty plugin results.
        output_dir:       Folder to write chunk_NNN.txt files into.
                          Default: ./OUTPUT_OF_COLLECTOR
        max_chunk_tokens: Token budget per chunk (default 8000).
        include_handles:  Whether to include the handles plugin (default True).
                          Set False to shrink chunk sizes for large dumps.
        force:            If True, overwrite output_dir if it already exists.
                          If False (default), raise FileExistsError if it exists.

    Returns:
        Number of chunk files written.

    Raises:
        ValueError:       If neither or both of image_path/folder_path are given.
        FileExistsError:  If output_dir already exists and force=False.
        FileNotFoundError: If image_path or folder_path does not exist.
    """
    from .vol3_runner import run_all_plugins, load_from_folder
    from .merge import build_records
    from .exclusions import filter_excluded
    from .tree import build_dfs_order
    from .format_line import format_process_line
    from .chunker import write_chunks

    # Validate mode
    if image_path is None and folder_path is None:
        raise ValueError("Exactly one of image_path or folder_path must be provided.")
    if image_path is not None and folder_path is not None:
        raise ValueError("Provide either image_path or folder_path, not both.")

    # Validate source exists
    if image_path is not None:
        src = Path(image_path)
        if not src.exists():
            raise FileNotFoundError(f"Memory image not found: {image_path}")
        source_label = str(src)
    else:
        src = Path(folder_path)
        if not src.is_dir():
            raise FileNotFoundError(f"Folder not found: {folder_path}")
        source_label = str(src)

    # Prepare output directory
    out = Path(output_dir)
    if out.exists() and any(out.iterdir()):
        if not force:
            raise FileExistsError(
                f"Output directory already exists and is non-empty: {out}\n"
                "Pass force=True (or --force on CLI) to overwrite."
            )
        log.warning("Output directory %s already exists — overwriting (--force).", out)
    out.mkdir(parents=True, exist_ok=True)

    log.info("=== FIND_EVIL Collector pipeline starting ===")

    # Step 1: Collect raw plugin data
    if image_path is not None:
        log.info("Step 1/5: Running Volatility 3 against %s ...", image_path)
        raw = run_all_plugins(image_path, include_handles=include_handles)
    else:
        log.info("Step 1/5: Loading pre-computed TSV files from %s ...", folder_path)
        raw = load_from_folder(Path(folder_path), include_handles=include_handles)

    # Step 2: Merge into ProcessRecord objects
    log.info("Step 2/5: Merging plugin outputs...")
    all_records = build_records(raw)

    if not all_records:
        log.warning("No processes found — writing zero chunks.")
        return 0

    # Step 3: Apply exclusion rules
    log.info("Step 3/5: Applying exclusion rules...")
    filtered_records = filter_excluded(all_records)

    if not filtered_records:
        log.warning("All processes excluded — writing zero chunks.")
        return 0

    # Step 4: Build DFS-ordered process tree
    log.info("Step 4/5: Building DFS-ordered process tree...")
    nodes, intervals = build_dfs_order(filtered_records)

    # Step 5: Format lines and write chunks
    log.info("Step 5/5: Formatting %d processes and writing chunks...", len(nodes))
    lines = [format_process_line(n.depth, n.record) for n in nodes]
    n_chunks = write_chunks(
        lines=lines,
        intervals=intervals,
        output_dir=out,
        source_label=source_label,
        max_chunk_tokens=max_chunk_tokens,
    )

    log.info("=== Done: %d chunk file(s) written to %s ===", n_chunks, out)
    return n_chunks


__all__ = ["run_collector"]
