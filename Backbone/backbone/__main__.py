"""CLI entry point for the Backbone orchestration layer."""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="backbone",
        description="Multi-module forensic investigation orchestrator",
    )
    sub = parser.add_subparsers(dest="command")

    run_parser = sub.add_parser("run", help="Run an investigation case")
    run_parser.add_argument("--case-id", required=True, help="Unique case identifier")
    run_parser.add_argument(
        "--config",
        default="config/orchestrator.yaml",
        help="Path to orchestrator config YAML",
    )

    sub.add_parser("version", help="Print package version")

    args = parser.parse_args(argv)

    if args.command == "version":
        from backbone import __version__

        print(__version__)
        return 0

    if args.command == "run":
        from backbone.orchestrator.loop import InvestigationLoop

        loop = InvestigationLoop.from_config(args.config, case_id=args.case_id)
        loop.run()
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
