"""
tree.py — Build process forest from ProcessRecord dict and produce DFS order.

Confidence: HIGH — this is pure Python data structure manipulation.
No Volatility API involved; no testing against a real dump required to validate
the algorithm itself, but TEST-TREE-01 through TEST-TREE-04 in testing_guide.md
should be run to confirm the ordering matches what pstree would show manually.

Design choices:
1. ORPHAN HANDLING: If a process's PPID is not in the record set (parent was
   hidden, exited before capture, or excluded by our rules), the process is
   treated as a forest root and listed after all rooted trees. This matches the
   building plan's description.

2. SORT ORDER: Within siblings (processes sharing the same PPID), we sort by
   PID ascending. This produces a stable, reproducible ordering.
   ALTERNATIVE: sort by CreateTime. This was not chosen because CreateTime may
   be empty for some processes and the comparison would be fragile.

3. SUBTREE INTERVALS: Each root's subtree is represented as a (start, end)
   index pair into the flat DFS-ordered list. These intervals are the atomic
   units for the chunker. A parent is ALWAYS within [start, end) and ALL its
   descendants are within that same interval — the chunk-safety invariant.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass

from .merge import ProcessRecord

log = logging.getLogger(__name__)


@dataclass
class DFSNode:
    depth: int
    record: ProcessRecord


@dataclass
class SubtreeInterval:
    """Half-open interval [start, end) in the DFS-ordered list for one root subtree."""
    root_pid: int
    start: int  # inclusive
    end: int    # exclusive


def build_dfs_order(
    records: dict[int, ProcessRecord]
) -> tuple[list[DFSNode], list[SubtreeInterval]]:
    """
    Build DFS pre-order list of all processes and subtree intervals for each root.

    Returns:
        (nodes, intervals) where:
          nodes:     DFS-ordered list of (depth, ProcessRecord) pairs
          intervals: one SubtreeInterval per root subtree (in the same order
                     as the roots appear in `nodes`)
    """
    if not records:
        return [], []

    pid_set = set(records.keys())

    # Build parent → children adjacency
    children: dict[int, list[int]] = defaultdict(list)
    for pid, rec in records.items():
        if rec.ppid in pid_set:
            children[rec.ppid].append(pid)

    # Sort children by PID for deterministic ordering
    for parent_pid in children:
        children[parent_pid].sort()

    # Find roots: processes whose PPID is not in the record set
    # Include PPID == 0 explicitly as a root condition.
    root_pids: list[int] = []
    for pid, rec in records.items():
        if rec.ppid not in pid_set or rec.ppid == 0:
            root_pids.append(pid)
    root_pids.sort()

    # Warn if there are unexpectedly many roots (may indicate bad parent data)
    if len(root_pids) > 20:
        log.warning(
            "%d root processes found — many orphans may indicate vol3_runner "
            "failed to collect all process base data (PPID links broken).",
            len(root_pids)
        )

    nodes: list[DFSNode] = []
    intervals: list[SubtreeInterval] = []

    for root_pid in root_pids:
        start_idx = len(nodes)
        _dfs(root_pid, depth=0, records=records, children=children, nodes=nodes)
        end_idx = len(nodes)
        intervals.append(SubtreeInterval(
            root_pid=root_pid,
            start=start_idx,
            end=end_idx,
        ))

    log.info(
        "tree: %d processes in DFS order, %d root subtrees",
        len(nodes), len(intervals)
    )
    return nodes, intervals


def _dfs(
    pid: int,
    depth: int,
    records: dict[int, ProcessRecord],
    children: dict[int, list[int]],
    nodes: list[DFSNode],
) -> None:
    """Recursive DFS pre-order traversal. Pre-order = parent before children."""
    rec = records.get(pid)
    if rec is None:
        # Should not happen since roots are derived from records, but guard anyway
        log.debug("DFS encountered missing PID %d — skipping subtree", pid)
        return

    nodes.append(DFSNode(depth=depth, record=rec))

    for child_pid in children.get(pid, []):
        _dfs(child_pid, depth + 1, records, children, nodes)
