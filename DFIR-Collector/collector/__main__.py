"""
CLI entry point for the FIND_EVIL collector.

Usage:
    python -m collector --image PATH [options]
    python -m collector --from-folder DIR [options]

Modes (mutually exclusive, exactly one required):
    --image PATH        Run Volatility 3 against a RAM dump (production; slow).
    --from-folder DIR   Read pre-computed Volatility TSV files from DIR (dev/test).

Output:
    --output-dir DIR    Folder to write chunk_NNN.txt files into.
                        Default: ./OUTPUT_OF_COLLECTOR
    --force             Overwrite the output folder if it already exists.

Tuning:
    --max-tokens N      Max tokens per chunk (default 8000).
    --no-handles        Skip the handles plugin to reduce chunk sizes.
                        The handles plugin is the heaviest (~49K rows on large dumps).

Diagnostics:
    --log-level LEVEL   DEBUG | INFO | WARNING | ERROR (default INFO).

Examples:
    # Production run against a real dump:
    python -m collector --image /tmp/evil_windows.elf --output-dir ./OUTPUT_OF_COLLECTOR

    # Dev run against pre-computed TSV outputs:
    python -m collector --from-folder /path/to/analysis_folder --output-dir /tmp/test_chunks

    # Strip handles for smaller chunks:
    python -m collector --image /tmp/evil.elf --no-handles --output-dir ./out
"""

from __future__ import annotations

import argparse
import logging
import sys

from . import run_collector


def main():
    parser = argparse.ArgumentParser(
        prog="collector",
        description="FIND_EVIL collector: extract process forest from a Windows RAM dump.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--image",
        metavar="PATH",
        help="Path to Windows memory image (.elf, .img, .vmem, …). "
             "Runs Volatility 3 via subprocess (production path — slow).",
    )
    mode_group.add_argument(
        "--from-folder",
        metavar="DIR",
        dest="from_folder",
        help="Directory containing pre-computed Volatility TSV files "
             "(pstree.txt, psscan.txt, cmdline.txt, dlllist.txt, handles.txt, "
             "privileges.txt, netscan.txt, netstat.txt, getsids.txt). "
             "Missing files produce empty plugin results with a WARNING.",
    )

    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        default="./OUTPUT_OF_COLLECTOR",
        help="Folder to write chunk_NNN.txt files into (default: ./OUTPUT_OF_COLLECTOR).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the output directory if it already exists.",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=8000,
        metavar="N",
        help="Token budget per chunk (default: 8000).",
    )
    parser.add_argument(
        "--no-handles",
        action="store_true",
        help="Skip the windows.handles plugin. Greatly reduces chunk sizes on "
             "dumps with large handle tables (~49K rows). Useful if chunks "
             "exceed the token budget.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO).",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        stream=sys.stderr,
    )

    try:
        n_chunks = run_collector(
            image_path=args.image,
            folder_path=args.from_folder,
            output_dir=args.output_dir,
            max_chunk_tokens=args.max_tokens,
            include_handles=not args.no_handles,
            force=args.force,
        )
    except (ValueError, FileNotFoundError, FileExistsError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    if n_chunks == 0:
        print("No chunks written — check logs for errors.", file=sys.stderr)
        sys.exit(1)

    print(f"Done. {n_chunks} chunk file(s) written to: {args.output_dir}", file=sys.stderr)


if __name__ == "__main__":
    main()
