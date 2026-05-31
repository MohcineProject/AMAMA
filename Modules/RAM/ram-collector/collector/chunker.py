"""
chunker.py — Token-aware, subtree-safe chunk writer.

Algorithm summary:
1. Receive DFS-ordered lines and SubtreeIntervals from tree.py.
2. Greedy pack: accumulate root subtrees until the token budget is hit.
3. If a single root subtree exceeds the budget, emit it as a solo file (log warning).
4. Write each chunk to output_dir/chunk_NNN.txt.
5. First chunk has a header with image path + timestamp.
   Subsequent chunks have # CHUNK i/N headers.

Chunk-safety invariant: a parent process and ALL its descendants always
appear in the same chunk file. This is guaranteed because the atomic unit is a
root subtree, and no root subtree is ever split.
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .tree import SubtreeInterval

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Token estimator
# ---------------------------------------------------------------------------

def _make_token_estimator():
    """Return a function (text: str) -> int estimating token count."""
    try:
        import tiktoken
        enc = tiktoken.get_encoding("cl100k_base")
        log.info("Token estimator: using tiktoken cl100k_base")
        def estimate(text: str) -> int:
            return len(enc.encode(text))
        return estimate
    except ImportError:
        log.warning(
            "tiktoken not installed — using character/4 fallback for token estimation. "
            "pip install tiktoken for more accurate chunk boundaries."
        )
        def estimate(text: str) -> int:
            return math.ceil(len(text) / 4)
        return estimate


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_chunks(
    lines: list[str],
    intervals: list[SubtreeInterval],
    output_dir: Path,
    source_label: str,
    max_chunk_tokens: int = 8000,
    estimate_tokens=None,
) -> int:
    """
    Pack DFS-ordered lines into subtree-safe chunks and write chunk_NNN.txt files.

    Args:
        lines:            One string per process (from format_line.format_process_line).
        intervals:        SubtreeInterval list from tree.build_dfs_order — defines
                          the atomic units (root subtrees) that must not be split.
        output_dir:       Directory to write chunk_NNN.txt files into (must exist).
        source_label:     Human-readable label for the first chunk's header line
                          (image path or folder path).
        max_chunk_tokens: Token budget per chunk. Oversized single subtrees are
                          emitted solo with a WARNING.
        estimate_tokens:  Optional callable (str) -> int. If None, a new estimator
                          is created (tries tiktoken, falls back to char/4).

    Returns:
        Number of chunk files written.
    """
    if estimate_tokens is None:
        estimate_tokens = _make_token_estimator()

    timestamp = datetime.now(timezone.utc).isoformat()
    first_header = f"# FIND_EVIL Collector — {source_label} — {timestamp}\n"

    # Pre-compute token count for each root subtree
    subtree_texts: list[str] = []
    subtree_tokens: list[int] = []
    for iv in intervals:
        text = "".join(lines[iv.start:iv.end])
        subtree_texts.append(text)
        subtree_tokens.append(estimate_tokens(text))

    # Greedy pack into raw chunks
    raw_chunks: list[str] = []
    current_parts: list[str] = []
    current_tokens: int = 0

    for text, tokens in zip(subtree_texts, subtree_tokens):
        if tokens > max_chunk_tokens:
            # Flush current accumulation first
            if current_parts:
                raw_chunks.append("".join(current_parts))
                current_parts = []
                current_tokens = 0
            log.warning(
                "Root subtree has %d tokens (budget %d) — emitting as solo chunk.",
                tokens, max_chunk_tokens,
            )
            raw_chunks.append(text)
            continue

        if current_tokens + tokens > max_chunk_tokens and current_parts:
            raw_chunks.append("".join(current_parts))
            current_parts = []
            current_tokens = 0

        current_parts.append(text)
        current_tokens += tokens

    if current_parts:
        raw_chunks.append("".join(current_parts))

    total = len(raw_chunks)
    log.info("Packing complete: %d chunk(s) → %s", total, output_dir)

    # Write files
    width = len(str(total))  # zero-pad to consistent width
    for i, chunk_text in enumerate(raw_chunks):
        header = first_header if i == 0 else f"# CHUNK {i + 1}/{total}\n"
        chunk_num = str(i + 1).zfill(max(3, width))
        chunk_path = output_dir / f"chunk_{chunk_num}.txt"
        chunk_path.write_text(header + chunk_text, encoding="utf-8")
        log.debug("Wrote %s (%d chars)", chunk_path.name, len(header) + len(chunk_text))

    return total
