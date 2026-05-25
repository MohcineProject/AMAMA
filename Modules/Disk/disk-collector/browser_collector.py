"""Browser history collector: Chrome / Edge / Firefox.

Opens SQLite databases in read-only mode (immutable=1) so forensic integrity
is preserved — no journal files are written, no mtime updates.

Output: Disk_Artifacts/browser_history.txt — one record per visit + one record
per download. The same file holds rows from all three browsers; the `browser`
field distinguishes.

# UNCERTAIN: Edge (Chromium-based, 2020+) uses the same schema as Chrome.
# Legacy Edge (EdgeHTML) used WebCacheV01.dat (ESE). v1 covers Chromium-Edge
# via the --browser-name flag. The test agent should add a --webcache flag if
# legacy Edge support is required.
"""
from __future__ import annotations

import os
import sqlite3
import sys
from typing import Iterator, List, Optional

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _common as _c  # type: ignore
else:
    from . import _common as _c


def _open_ro(path: str) -> sqlite3.Connection:
    """Open SQLite read-only; never touches the file."""
    uri = f"file:{path}?mode=ro&immutable=1"
    return sqlite3.connect(uri, uri=True)


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    cur = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    )
    return cur.fetchone() is not None


def _column_names(conn: sqlite3.Connection, table: str) -> set:
    try:
        cur = conn.execute(f"PRAGMA table_info({table})")
        return {row[1] for row in cur.fetchall()}
    except sqlite3.DatabaseError:
        return set()


# -------------------------- Chrome / Edge --------------------------

def collect_chromium(history_path: str, browser_name: str = "chrome") -> Iterator[dict]:
    """Yields visit + download records from a Chromium-family History SQLite."""
    if not os.path.isfile(history_path):
        return
    try:
        conn = _open_ro(history_path)
    except sqlite3.DatabaseError as e:
        print(f"[browser_collector] {browser_name} open failed: {e}", file=sys.stderr)
        return

    try:
        # URLs
        if _table_exists(conn, "urls"):
            cols = _column_names(conn, "urls")
            select = ["url", "title", "visit_count", "last_visit_time"]
            select = [c for c in select if c in cols]
            if select:
                q = f"SELECT {', '.join(select)} FROM urls ORDER BY last_visit_time DESC"
                try:
                    for row in conn.execute(q):
                        d = dict(zip(select, row))
                        yield {
                            "type": "browser",
                            "browser": browser_name,
                            "event": "visit",
                            "url": d.get("url"),
                            "title": d.get("title"),
                            "visit_count": d.get("visit_count"),
                            "visit_time": _c.to_iso8601(
                                _c.chrome_webkit_us_to_utc(d.get("last_visit_time") or 0)
                            ),
                            "artifact_source": "chromium_history",
                        }
                except sqlite3.DatabaseError as e:
                    print(f"[browser_collector] urls query failed: {e}", file=sys.stderr)

        # Downloads
        if _table_exists(conn, "downloads"):
            cols = _column_names(conn, "downloads")
            select = ["target_path", "tab_url", "start_time", "end_time", "received_bytes"]
            select = [c for c in select if c in cols]
            if select:
                q = f"SELECT {', '.join(select)} FROM downloads ORDER BY start_time DESC"
                try:
                    for row in conn.execute(q):
                        d = dict(zip(select, row))
                        yield {
                            "type": "browser",
                            "browser": browser_name,
                            "event": "download",
                            "download_path": d.get("target_path"),
                            "url": d.get("tab_url"),
                            "download_start": _c.to_iso8601(
                                _c.chrome_webkit_us_to_utc(d.get("start_time") or 0)
                            ),
                            "download_end": _c.to_iso8601(
                                _c.chrome_webkit_us_to_utc(d.get("end_time") or 0)
                            ),
                            "received_bytes": d.get("received_bytes"),
                            "artifact_source": "chromium_history",
                        }
                except sqlite3.DatabaseError as e:
                    print(f"[browser_collector] downloads query failed: {e}", file=sys.stderr)
    finally:
        conn.close()


# -------------------------- Firefox --------------------------

def collect_firefox(places_path: str) -> Iterator[dict]:
    """Yields visit + download records from Firefox places.sqlite."""
    if not os.path.isfile(places_path):
        return
    try:
        conn = _open_ro(places_path)
    except sqlite3.DatabaseError as e:
        print(f"[browser_collector] firefox open failed: {e}", file=sys.stderr)
        return

    try:
        if _table_exists(conn, "moz_places"):
            cols = _column_names(conn, "moz_places")
            select = ["url", "title", "visit_count", "last_visit_date"]
            select = [c for c in select if c in cols]
            if select:
                q = f"SELECT {', '.join(select)} FROM moz_places ORDER BY last_visit_date DESC"
                try:
                    for row in conn.execute(q):
                        d = dict(zip(select, row))
                        yield {
                            "type": "browser",
                            "browser": "firefox",
                            "event": "visit",
                            "url": d.get("url"),
                            "title": d.get("title"),
                            "visit_count": d.get("visit_count"),
                            "visit_time": _c.to_iso8601(
                                _c.firefox_unix_us_to_utc(d.get("last_visit_date") or 0)
                            ),
                            "artifact_source": "firefox_places",
                        }
                except sqlite3.DatabaseError as e:
                    print(f"[browser_collector] moz_places query failed: {e}", file=sys.stderr)

        # Downloads on modern Firefox live in moz_annos with attribute id
        # pointing to "downloads/destinationFileURI". Legacy schemas had a
        # dedicated moz_downloads table.
        if _table_exists(conn, "moz_downloads"):
            try:
                for row in conn.execute(
                    "SELECT name, source, target, startTime FROM moz_downloads"
                ):
                    yield {
                        "type": "browser",
                        "browser": "firefox",
                        "event": "download",
                        "download_path": row[2],
                        "url": row[1],
                        "download_start": _c.to_iso8601(
                            _c.firefox_unix_us_to_utc(row[3] or 0)
                        ),
                        "artifact_source": "firefox_places_legacy",
                    }
            except sqlite3.DatabaseError:
                pass
        elif _table_exists(conn, "moz_annos") and _table_exists(conn, "moz_anno_attributes"):
            # Modern schema
            try:
                for row in conn.execute(
                    """
                    SELECT mp.url, ma.content, ma.dateAdded
                    FROM moz_annos ma
                    JOIN moz_anno_attributes maa ON ma.anno_attribute_id = maa.id
                    JOIN moz_places mp ON ma.place_id = mp.id
                    WHERE maa.name = 'downloads/destinationFileURI'
                    ORDER BY ma.dateAdded DESC
                    """
                ):
                    yield {
                        "type": "browser",
                        "browser": "firefox",
                        "event": "download",
                        "download_path": row[1],
                        "url": row[0],
                        "download_start": _c.to_iso8601(
                            _c.firefox_unix_us_to_utc(row[2] or 0)
                        ),
                        "artifact_source": "firefox_places_annos",
                    }
            except sqlite3.DatabaseError as e:
                # UNCERTAIN: some Firefox schemas are missing JOIN columns
                print(f"[browser_collector] firefox downloads query failed: {e}",
                      file=sys.stderr)
    finally:
        conn.close()


# -------------------------- Public API --------------------------

def run_from_config(config: dict, out_dir: str) -> dict:
    section = config.get("browser") or {}
    chrome_path = section.get("chrome_history")
    chrome_name = section.get("chrome_browser_name", "chrome")
    firefox_path = section.get("firefox_places")

    records: List[dict] = []
    errors: List[str] = []

    if chrome_path:
        try:
            records.extend(collect_chromium(chrome_path, chrome_name))
        except Exception as e:
            errors.append(f"chromium: {e}")
    if firefox_path:
        try:
            records.extend(collect_firefox(firefox_path))
        except Exception as e:
            errors.append(f"firefox: {e}")

    if not records and not errors:
        # Emit empty file so downstream tools find the path (matches the
        # expected output set in HOW_TO_BUILD.md §5.2).
        out_path = os.path.join(out_dir, "browser_history.txt")
        with _c.open_records_writer(out_path):
            pass
        return {"output_files": [out_path], "record_count": 0}

    limit = config.get("max_records")
    out_path = os.path.join(out_dir, "browser_history.txt")
    n = _c.write_records_to_file(iter(records), out_path, limit=limit)
    result = {"output_files": [out_path], "record_count": n}
    if errors:
        result["errors"] = errors
    return result


def main() -> None:
    parser = _c.setup_cli(
        "Collect browser history & downloads (Chrome/Edge/Firefox).",
        default_out="Disk_Artifacts/browser_history.txt",
    )
    parser.add_argument("--chrome-history", default=None, help="Path to Chromium History SQLite")
    parser.add_argument("--browser-name", default="chrome", choices=["chrome", "edge", "brave"],
                        help="Tag for Chromium-family records")
    parser.add_argument("--firefox-places", default=None, help="Path to Firefox places.sqlite")
    args = parser.parse_args()
    config = _c.load_json(args.config) if args.config else {}
    section = config.setdefault("browser", {})
    if args.chrome_history:  section["chrome_history"]      = args.chrome_history
    if args.browser_name:    section["chrome_browser_name"] = args.browser_name
    if args.firefox_places:  section["firefox_places"]      = args.firefox_places

    # If --out is a directory, write inside; if it's a file path, override.
    out_dir = args.out if os.path.isdir(args.out) else "Disk_Artifacts"
    res = run_from_config(config, out_dir)
    print(f"[browser_collector] wrote {res['record_count']} records → {res['output_files']}")


if __name__ == "__main__":
    main()
