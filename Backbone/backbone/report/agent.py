"""Report agent — final incident narrative from case state."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from backbone.case_graph import CaseGraph


class ReportAgent:
    """Builds report.md from the case graph. LLM templating added later."""

    def __init__(self, *, use_llm: bool = False) -> None:
        self.use_llm = use_llm

    def build(self, graph: CaseGraph, out_path: Path) -> Path:
        summary = graph.summary_for_agent()
        lines = [
            f"# Incident Report — {graph.case_id}",
            "",
            "## Executive summary",
            "",
            f"- Entities tracked: **{summary['entity_count']}**",
            f"- Modules scanned: **{', '.join(summary['modules_scanned']) or 'none yet'}**",
            "",
            "_Report agent scaffold — full narrative generation not yet wired._",
            "",
        ]
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(lines), encoding="utf-8")
        return out_path
