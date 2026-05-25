# Tests TODO — Disk DFIR Pipeline

## 0. Environment setup

- [x] `pip install -r requirements.txt` — **DONE.** All packages installed including
      native builds (Python 3.12 on Ubuntu 24.04 requires a virtualenv (PEP 668).
      Use `.venv/bin/python` / `.venv/bin/pip` for all commands.)
- [x] Extract artifacts from the disk image — **DONE via mounter.**
      NTFS mounted at `/tmp/dfir_ntfs`. Artifacts in `Disk_Artifacts/`.

## 1. `_common.py`

- [ ] `windows_filetime_to_utc(0)` → returns `None` (not 1601-01-01; we treat 0 as null).
- [ ] `windows_filetime_to_utc(116444736000000000)` → datetime equal to 1970-01-01T00:00:00Z.
- [ ] `windows_filetime_to_utc(132514560000000000)` → ~2021-01-01T00:00:00Z (sanity check).
- [ ] `chrome_webkit_us_to_utc(13298904000000000)` → ~2022-06-30 (Chrome epoch sanity).
- [ ] `firefox_unix_us_to_utc(1700000000000000)` → ~2023-11-14 (Firefox epoch sanity).
- [ ] `format_find_evil_record("file", path="C:\\a b\\x.exe", entropy=7.5)`
       → `path` is double-quoted because of the space; `entropy=7.5` is unquoted.
- [ ] `format_find_evil_record("file", path="x", deleted=False)`
       → emits `deleted=false` (lowercased boolean).
- [ ] Empty / None / "" fields are dropped — verify the record line does NOT
      contain `key=` with nothing after it.
- [ ] Round-trip: write 100 synthetic records, then read them back with a regex
      `^type=(\w+)\s+(.*)$` — every line parses cleanly, no record dropped.

---

## 3. `mft_collector.py` (built-in parser)

- [X] Run against the extracted `$MFT`: 
      `python disk-collector/mft_collector.py --input INPUT_DISK/raw_mft --out Disk_Artifacts/mft_records.txt`
- [ ] Record count is within ±5% of `analyzeMFT` reference output for the same
      file. If the numbers differ wildly, investigate `_detect_record_size()`
      (the entry-size detector). `# UNCERTAIN:` flag in source.
- [ ] At least one record has `deleted=true` (any image has these).
- [ ] At least one record has `ads=Zone.Identifier` (download a file, then test).
- [ ] At least one record has both SI (`created`/`modified`/`accessed`) and FN
      (`fn_created`/`fn_modified`/`fn_accessed`) populated — these come from
      different attributes.
- [ ] Path reconstruction sanity: pick a known-deep file (e.g. `C:\Windows\System32\drivers\etc\hosts`)
      and verify the emitted `path` field matches (minus drive letter).
- [ ] Orphan files (parent ref pointing nowhere) appear with path prefix `<orphan>\`.
      Confirm count is < 1% of total.
- [ ] `--volume-root` flag: mount the image, point `--volume-root` at the
      mount, verify a sample of records have `hash`, `entropy`,
      `max_section_entropy` populated for PE files.
---

## 4. `eventlog_collector.py`

- [ ] Run: `python disk-collector/eventlog_collector.py --evtx-dir INPUT_DISK/evtx --config disk-collector/config.example.json`
- [ ] All four output files (`eventlog_security/system/application/sysmon.txt`)
      are created when corresponding evtx files exist.
- [ ] An ID 4624 event has populated `user`, `logon_id`, `logon_type`, `src_ip`.
- [ ] An ID 4688 event has populated `process`, `parent_process`, `cmdline`
      (if audit-process-creation w/ cmdline was enabled — note in results).
- [ ] An ID 1102 event is ALWAYS emitted, even if `high_signal_event_ids` is
      restricted to a small list (test by temporarily editing config).
- [ ] An ID 7045 event has `service_name`, `image_path` populated.
- [ ] Sysmon ID 1 events have `parent_process`, `cmdline`, `hashes`.
- [ ] All `time` fields are ISO8601 UTC with `Z` suffix (no `+00:00` leakage).

---
## 5. `execution_collector.py`

- [ ] Run: `python disk-collector/execution_collector.py --prefetch-dir INPUT_DISK/prefetch --amcache INPUT_DISK/hives/Amcache.hve --system-hive INPUT_DISK/hives/SYSTEM`

### Prefetch
- [ ] With `pyscca` installed: each .pf produces one record with `path`,
      `last_run`, `run_count`. Spot-check 3-5 against PECmd.exe output.
- [ ] Without `pyscca`: uncompressed prefetch (Win 7) still parses; compressed
      (Win 10 MAM signature) emits a record with `needs_libscca=true`.

### Amcache
- [ ] Records exist from `Root\InventoryApplicationFile` (modern schema).
- [ ] `hash` field has `sha1:` prefix (NOT sha256). Verify ONE hash matches
      the SHA1 of the actual file (e.g. notepad.exe).
- [ ] Legacy schema fallback (`Root\File\<vol>\<id>`) emits records on a Win 8
      image. (Optional — only Win 10+ images are common.)

### Shimcache
- [ ] Run against a Win10 SYSTEM hive → records emit with `last_modified` set.
- [ ] Compare 10 records against `AppCompatCacheParser.exe` (Eric Zimmerman)
      for the same SYSTEM hive. Path strings should match exactly.
- [ ] `# UNCERTAIN:` magic-byte format detection — if the hive isn't Win10 or
      Win7, the collector logs "unknown shimcache magic" and skips. Document
      which Windows versions need a new parser branch.

### `# UNCERTAIN:` flags to verify
- [ ] Amcache `FileId`: confirm SHA1 (not first-31MB-hash) on a known file.
      If wrong, document and update the collector.

---

## 7. `persistence_collector.py`

- [ ] Run: `python disk-collector/persistence_collector.py --tasks-dir INPUT_DISK/Tasks --wmi-dir INPUT_DISK/wbem`
- [ ] `scheduled_tasks.txt` has records for known tasks (e.g.
      `\Microsoft\Windows\Defrag\ScheduledDefrag`).
- [ ] Both `<Triggers>` and `<Actions>` were parsed — confirm `trigger_types`
      lists actual trigger element names (e.g. `CalendarTrigger;LogonTrigger`).
- [ ] `action` field contains the `<Command>` path.
- [ ] `wmi_subscriptions.txt` has placeholder records with
      `needs_full_parser=true`. No crashes on malformed `OBJECTS.DATA`.
- [ ] With `--include-registry-persistence`: produces extra files
      `persistence_runkeys.txt` and `persistence_services.txt` containing the
      same data as `registry_autoruns.txt` and `registry_services.txt` but
      reshaped as `type=persistence`. Verify no double-write when this flag
      is OFF (default).

---

## 8. `browser_collector.py`

- [ ] Run: `python disk-collector/browser_collector.py --chrome-history INPUT_DISK/chrome/History --firefox-places INPUT_DISK/firefox/places.sqlite`
- [ ] SQLite opened read-only — verify by `ls -la` on the History file before
      and after; mtime must NOT change, no `-journal` or `-wal` file appears.
- [ ] At least one Chrome visit record has `visit_time` parsing to a sensible
      date (within last 5 years if it's a current install).
- [ ] At least one download record has `download_path` populated.
- [ ] Edge support: `--browser-name edge` against an Edge `History` file —
      records tagged `browser=edge`.
- [ ] Firefox: at least one `moz_places` row produces a record with a sensible
      `visit_time` (NOT 1601).
- [ ] Firefox downloads: confirm whether `moz_annos` query path works on the
      test Firefox profile. Newer Firefox versions may have changed the
      attribute name. (`# UNCERTAIN:` in source.)
- [ ] Empty input (hand-crafted empty SQLite with the right tables) → emits an
      empty `browser_history.txt` (0 records) without crashing.

---

## 9. `disk_collector.py` orchestrator

- [ ] `python disk-collector/disk_collector.py --config disk-collector/config.example.json`
      runs every sub-collector against `INPUT_DISK/`.
- [ ] JSON summary lists each collector with `output_files` and `record_count`.
- [ ] `--only mft browser` runs only those two; the other four are absent from
      the summary.
- [ ] If `INPUT_DISK/raw_mft` is intentionally missing, the MFT collector
      reports `error` in summary but the others still run.
- [ ] `--summary-out summary.json` writes the same JSON to disk.
- [ ] Sum of `record_count` across collectors equals `grep -c "^type=" Disk_Artifacts/*.txt`.

---

## 10. Cross-cutting integrity

- [ ] Every file in `Disk_Artifacts/` is valid UTF-8 (`file --mime-encoding`).
- [ ] Every non-empty line starts with `type=`.
- [ ] No timestamp prior to 1700 or after 2100 anywhere in the output
      (catches FILETIME conversion bugs):
      ```bash
      grep -E "created=\"?(1[0-6][0-9]{2}|21[0-9]{2}|22)" Disk_Artifacts/*.txt
      ```
      Expected: empty output.
- [ ] No record line longer than 8192 bytes (would break Agent 1's token
      budget). Find offenders:
      ```bash
      awk 'length > 8192 {print FILENAME ":" NR ": " length}' Disk_Artifacts/*.txt
      ```
- [ ] Round-trip parsing: a record written by the collector can be re-parsed
      with the same `escape_field` rules (double quotes, backslash escaping).

---

## 11. Things the codegen agent flagged as uncertain (consolidated)

These were tagged `# UNCERTAIN:` in source. Confirm each:

- `_common.py`: writing a record with no `type` field — silent skip vs raise?
- `pe_analyzer.py`: 500 MB SHA256 truncation cap, 32 MB whole-file entropy cap.
- `mft_collector.py`: 
  - MFT entry size detection (1024 vs 4096)
  - `analyzeMFT` library API stability (2.x vs 3.x)
  - Extension entry skipping (`base_ref != 0`)
- `registry_collector.py`: 
  - `HKLM\SYSTEM\Select\Current` resolution fallback to `ControlSet001`
  - Per-user NTUSER.DAT discovery via nested directories
- `eventlog_collector.py`:
  - Per-EventData-name lookup case sensitivity across OS versions
  - Sysmon vs native XML schema differences
- `execution_collector.py`:
  - Amcache `FileId` → SHA1 vs partial-file hash semantics
  - Shimcache magic-byte format detection (Win 7 vs 8 vs 10 vs 11)
  - Prefetch without `pyscca`: Win10 MAM-compressed files cannot be parsed
- `persistence_collector.py`:
  - WMI repository parsing is a placeholder; decide whether to integrate
    `python-cim` or shell to PowerShell
- `browser_collector.py`:
  - Edge legacy (EdgeHTML/WebCacheV01.dat) not supported
  - Firefox `moz_annos` join may not work on all schema versions

---

## 12. `disk-image-mounter/mount_image.py`

Run all tests on the SIFT workstation. Sections 13.1 can run without root or a
real image; sections 13.2 onward require root and the SIFT toolchain.

### 12.1 Unit tests — no root, no disk image required

These test the pure-Python parsing functions in isolation. Write a small
`disk-image-mounter/test_mount_image.py` that imports `mount_image` and
calls each function with synthetic input.

**mmls parsing:**
- [ ] `test_parse_mmls_mbr` — feed synthetic MBR mmls stdout with two NTFS
      rows, one Meta row, and one `-------` Unallocated row. Assert: 2
      `PartitionInfo` objects returned; Meta and Unallocated rows excluded;
      `start_sector` and `length_sectors` match the input values.
- [ ] `test_parse_mmls_gpt` — feed GPT mmls output where the Description
      column says "Basic data partition". Assert: rows parsed correctly
      (the regex does not depend on description content).
- [ ] `test_parse_mmls_empty` — feed empty / header-only string. Assert:
      returns `[]`, no exception.
- [ ] `test_parse_mmls_zero_length` — include a row with `Length=0`. Assert:
      that row is excluded from results.

**fsstat parsing:**
- [ ] `test_detect_fs_ntfs` — feed synthetic fsstat stdout containing
      `"File System Type: NTFS"`. Assert: returns `"ntfs"`.
- [ ] `test_detect_fs_ext4` — feed `"File System Type: Ext4"`. Assert:
      returns `"ext4"`.
- [ ] `test_detect_fs_xfs` — feed `"File System Type: XFS"`. Assert:
      returns `"xfs"`.
- [ ] `test_detect_fs_unknown` — feed stdout with no `File System Type:`
      line. Assert: returns `"unknown"`, no exception.

**BitLocker detection:**
- [ ] `test_bitlocker_detected` — construct a 512-byte buffer with
      `bytes([0xEB, 0x58, 0x90, 0x2D, 0x46, 0x56, 0x45, 0x2D, 0x46, 0x53, 0x2D])`
      at offset 3. Write it to a temp file, call `check_bitlocker(path, 0)`.
      Assert: returns `True`.
- [ ] `test_bitlocker_not_detected` — 512 bytes of zeros. Assert: `False`.

**Partition / OS selection:**
- [ ] `test_select_windows_partition_largest` — list with two NTFS partitions
      (sizes 1 GB and 50 GB) and one ext4. Assert: the 50 GB NTFS is returned.
- [ ] `test_select_windows_partition_no_ntfs` — list with only ext4. Assert:
      raises `ValueError`.
- [ ] `test_determine_os_windows` — partition list with only `fstype="ntfs"`.
      Assert: `"windows"`.
- [ ] `test_determine_os_linux` — list with `fstype="ext4"`. Assert: `"linux"`.
- [ ] `test_determine_os_mixed` — list with both `ntfs` and `ext4`. Assert:
      `"linux"` (Linux filesystem presence takes precedence as a safety gate).
- [ ] `test_determine_os_unknown` — list with `fstype="unknown"` and
      `fstype="bitlocker"` only. Assert: `"unknown"`.

**Browser discovery:**
- [ ] `test_discover_chrome` — create a tempdir tree containing
      `Users/alice/AppData/Local/Google/Chrome/User Data/Default/History`.
      Call `discover_browsers(tempdir)`. Assert: `chrome_history` points to
      that file, `chrome_browser_name == "chrome"`.
- [ ] `test_discover_edge` — same tree but with Edge path
      (`Microsoft/Edge/User Data/Default/History`), no Chrome. Assert:
      `chrome_browser_name == "edge"`.
- [ ] `test_discover_firefox` — tree with Firefox
      `Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/abc.default/places.sqlite`.
      Assert: `firefox_places` points to it.
- [ ] `test_discover_none` — empty tempdir. Assert: both values `None`, no
      exception, no crash.
- [ ] `test_discover_multiuser_picks_newest` — two Chrome History files for
      different users. Touch one to be newer. Assert: the newer one is selected.

**Config generation:**
- [ ] `test_build_config_paths` — call `build_config("/mnt/test", "/tmp/mft",
      {"chrome_history": None, "chrome_browser_name": "chrome",
      "firefox_places": None})`. Assert:
      - `config["mft"]["input"]` is an absolute path ending in `mft`
      - `config["mft"]["volume_root"] == "/mnt/test"`
      - `config["registry"]["hive_dir"]` starts with `/mnt/test`
      - No path contains the string `INPUT_DISK` (template placeholders replaced)
      - `config["browser"]["chrome_history"]` is `None` (not the string "null")
      - All tuning keys (`high_signal_event_ids`, `suspicious_paths`, etc.) present
- [ ] `test_build_config_loads_template` — if `config.example.json` is present,
      the tuning keys should match the template values (not the built-in defaults).

**Image directory scanning:**
- [ ] `test_scan_no_files` — tempdir with no image files. Assert: `SystemExit(1)`.
- [ ] `test_scan_multiple_files` — tempdir with two `.e01` files. Assert:
      `SystemExit(1)`, error message lists both files.
- [ ] `test_scan_one_file` — tempdir with `disk.e01`. Assert: returns a `Path`
      equal to that file.
- [ ] `test_scan_nonexistent_dir` — path that does not exist. Assert:
      `SystemExit(1)`.

---

### 12.2 Tool availability check (SIFT, no image needed)

Confirm the SIFT toolchain is present:
- [x] `ewfmount` found at `/usr/bin/ewfmount` (from `libewf-tools`, not `ewf-tools`).
      **Note:** `sudo apt install ewf-tools` fails due to `libewf` vs `libewf2` conflict
      on Ubuntu 24.04; `libewf-tools` is already present on SIFT and provides the binary.
- [x] `mmls` found at `/usr/bin/mmls` — OK.
- [x] `icat` found at `/usr/bin/icat` — OK.
- [x] `fsstat` found at `/usr/bin/fsstat` — OK.
- [x] `losetup` — pre-installed, present.
- [x] `ntfs-3g` found at `/usr/bin/ntfs-3g` — OK.
      **Note:** `ntfs-3g` alone is insufficient for this image (see §13.6).
      The kernel `ntfs3` driver is used as fallback.
- [x] `qemu-nbd` found at `/usr/bin/qemu-nbd` — OK.

---

### 12.3 Integration test — synthetic NTFS image (root required)

Create a minimal test image with one NTFS partition:

```bash
dd if=/dev/zero of=/tmp/test_ntfs.img bs=1M count=200
parted /tmp/test_ntfs.img mklabel msdos mkpart primary ntfs 1MiB 199MiB
LOOP=$(sudo losetup -Pf --show /tmp/test_ntfs.img)
sudo mkntfs -Q -F ${LOOP}p1
sudo losetup -d $LOOP
mkdir -p /tmp/test_images && cp /tmp/test_ntfs.img /tmp/test_images/disk.img
```

- [ ] `sudo python disk-image-mounter/mount_image.py --image-dir /tmp/test_images
      --out-config /tmp/test_config.json --mft-out /tmp/INPUT_DISK/raw_mft`
      exits 0.
- [ ] `/tmp/INPUT_DISK/raw_mft` exists and `wc -c` shows > 0 bytes.
- [ ] `/tmp/dfir_ntfs` is a mountpoint (`mountpoint /tmp/dfir_ntfs` exits 0).
- [ ] `/tmp/dfir_mount_state.json` exists and contains valid JSON with
      `ntfs_mount` and `disk_loop` keys set to non-null strings.
- [ ] `/tmp/test_config.json` is valid JSON. `jq '.mft.input' /tmp/test_config.json`
      returns an absolute path. `jq '.mft.volume_root' …` returns `/tmp/dfir_ntfs`.
- [ ] No placeholder paths remain:
      `grep -c 'INPUT_DISK' /tmp/test_config.json` → 0.
- [ ] `sudo python disk-image-mounter/mount_image.py --umount` exits 0;
      `mountpoint /tmp/dfir_ntfs` exits 1 (no longer mounted);
      `/tmp/dfir_mount_state.json` is gone.
-
### 12.4 Full end-to-end test

- [] **Mounter** — exits 0.
- [] **MFT** works.
- [] **Registry (Python)** — 42 autorun records. Services blocked by NK record error.
- [] **Event logs ** 
- [] **Execution (Python)**
- [] **Persistence**
- [] **Browser** 

### 12.5 Zimmerman tools — integration tests

**Critical:** always invoke via `.dll`, not `.exe`. The `.exe` files are Windows-only PE binaries.

```bash
# CORRECT on Linux:
dotnet /opt/zimmermantools/RECmd/RECmd.dll --help
dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll --help
dotnet /opt/zimmermantools/AppCompatCacheParser.dll --help
dotnet /opt/zimmermantools/MFTECmd.dll --help
dotnet /opt/zimmermantools/SQLECmd/SQLECmd.dll --help
dotnet /opt/zimmermantools/LECmd.dll --help

# WRONG — fails with "Bad IL format":
dotnet /opt/zimmermantools/AppCompatCacheParser.exe
```

- [x] RECmd.dll `--help` exits 0 — ✅ CONFIRMED
- [x] EvtxECmd.dll `--help` exits 0 — ✅ CONFIRMED
- [x] AppCompatCacheParser.dll `--help` exits 0 — ✅ CONFIRMED
- [x] AmcacheParser.dll `--help` exits 0 — ✅ CONFIRMED
- [x] RECmd + DFIRBatch.reb against mounted hives → 19,481 CSV records — ✅ CONFIRMED
- [x] AppCompatCacheParser against SYSTEM hive → 527 shimcache records — ✅ CONFIRMED
- [x] EvtxECmd against winevt/Logs → 556,997 events — ✅ CONFIRMED (session 4)
- [ ] `dotnet /opt/zimmermantools/MFTECmd.dll -f INPUT_DISK/raw_mft --csv /tmp/mft_out/` — not yet run
- [ ] `dotnet /opt/zimmermantools/SQLECmd/SQLECmd.dll -d /tmp/dfir_ntfs/Users/nfury/AppData --maps /opt/zimmermantools/SQLECmd/Maps/ --csv /tmp/sql_out/` — not yet run
- [ ] `dotnet /opt/zimmermantools/LECmd.dll -d "/tmp/dfir_ntfs/Users/nfury" --csv /tmp/lnk_out/` — not yet run

---

### 12.6 Event log archive age filter

- [ ] Set `max_archive_age_days: 30` in `config.json`, run eventlog without `--max-records` — verify only recent archives are read.
- [ ] `--triage-mode` auto-sets `max_archive_age_days: 30`.

---

## 13. `preprocess.py` — deterministic noise reduction  ← SESSION 6 BUILT

### 13.1 Unit tests (run with `python scripts/preprocess.py --test`)

- [x] **Publisher whitelist unit tests (18 total)** — ALL PASS. Run:
      ```bash
      cd disk-agentic-architecture && python scripts/preprocess.py --test
      ```
      Tests include:
      - GoogleUpdate.exe under `\Program Files (x86)\Google\` → whitelisted (Rule 3)
      - `C:\ProgramData\sysmon\Auto_Update.bat` → kept (Rule 1: suspicious path ProgramData)


### 13.2 Integration tests (run against real Disk_Artifacts/)

**Note (session 7):** `preprocess.py` now writes THREE files instead of one TRIAGE_INPUT.txt.
The command and expected outputs below reflect the new multi-file architecture.

- [x] **Preprocess runs without error (session 6 baseline, before 3-file split):**
      ```bash
      cd disk-agentic-architecture && ./../.venv/bin/python scripts/preprocess.py
      ```
      Session 6 output (single file, pre-split): `~864 rows, ~309 KB`

- [ ] **Preprocess produces 3 files (session 7 — re-run needed after whitelist fix):**
      ```bash
      cd disk-agentic-architecture && ./../.venv/bin/python scripts/preprocess.py
      ls -lh output/TRIAGE_INPUT_*.txt
      ```
      Expected:
      - `TRIAGE_INPUT_PERSISTENCE.txt` — persistence/execution/browser records after whitelist
      - `TRIAGE_INPUT_EVENTS.txt` — deduplicated event summaries
      - `TRIAGE_INPUT_MFT.txt` — MFT stats block + scored top-N records
      - Old `TRIAGE_INPUT.txt` is no longer created

- [x] **TRIAGE_INPUT_PERSISTENCE.txt content (session 6 baseline):**
      Key survivors include:
      - `Update_Sysmon_Rules` scheduled task (ProgramData, author=rsydow-a) ← CRITICAL FINDING
      - `dismhost.exe` in `rsydow-a\AppData\Local\Temp\` (shimcache)
      - `bginfo.bat` in `C:\ProgramData\...\Startup\` (shimcache)
      - `perfmonsvc64.exe` download from `technicalbird.com` (browser_history)
      - All browser history visits (264 rows) — kept for phishing detection

- [x] **TRIAGE_INPUT_EVENTS.txt content (session 6 baseline):** 549 deduplicated rows from 151,905 raw events.
      Key signals include:
      - Event 1102 (Security log cleared) at 2018-05-03 ← anti-forensics
      - Event 4648 (explicit credentials) targeting SHIELDBASE.LAN\Administrator
      - 4624 Type 10 (RDP) from BASE-RD-01/BASE-ADMIN (172.16.5.26)
      - 4732 rsydow-a added to Remote Desktop Users group
      - Sysmon event 3: rsydow-a wsmprovhost.exe on "Socks Proxy Port"

- [ ] **TRIAGE_INPUT_MFT.txt content:** stats block present + scored records. Currently 0 rows
      because mft_records.txt for base-wkstn-05 has not been regenerated.
      When available: `TRIAGE_INPUT_MFT.txt` should be < 100 KB (down from 13 MB source).

- [ ] **When mft_records.txt is available:** re-run preprocess and verify MFT scoring produces
      records in TRIAGE_INPUT_MFT.txt. Use `dotnet /opt/zimmermantools/MFTECmd.dll` to generate
      mft_records.txt.

- [ ] **Whitelist fix verification (session 7):** After re-running preprocess, confirm no
      `ProgramData\Microsoft\` or `Windows\System32\` files appear in top-scored MFT records.

### 13.3 Whitelist regression tests

The whitelist logic has several rules that can interact. After any edit to `preprocess.py`
or `config.json`, re-run `--test` and verify these key behaviors:

| Input | Expected output | Rule applied |
|---|---|---|
| `path=C:\Windows\System32\svchost.exe` | WHITELISTED | Rule 3: canonical path |
| `path=C:\Windows\SysWOW64\cmd.exe` | WHITELISTED | Rule 3: canonical path |
| `path=C:\Windows\ehome\ehrec.exe` | WHITELISTED | Rule 3: `c:\windows\ehome` prefix |
| `path=%ProgramFiles%\Windows Sidebar\Sidebar.exe` | WHITELISTED | Rule 3: env-var expansion |
| `path=%SystemRoot%\ehome\mcupdate.exe` | WHITELISTED | Rule 3: env-var expansion → c:\windows |
| `path=C:\Program Files\VMware\VMware Tools\vmtoolsd.exe` | WHITELISTED | Rule 3: vmware prefix |
| `action=aitagent` (bare filename, run_as=S-1-5-18) | WHITELISTED | Rule 3b: bare filename + SYSTEM |
| `path=C:\ProgramData\sysmon\sysmon64.exe` | **KEPT** | Rule 1: ProgramData is suspicious |
| `path=C:\Users\nfury\AppData\Local\Temp\evil.exe` | **KEPT** | Rule 1: AppData\Local\Temp is suspicious |
| `category=Services` (any data) | DROPPED | Category filter before whitelist |
| `category="User Activity"` (any data) | DROPPED | Category filter before whitelist |
| `category="Program Execution"` (MuiCache) | DROPPED | Category filter before whitelist |

---

## 14. `pivot_search.py` — multi-key grep  ← SESSION 6 BUILT

### 14.1 Unit tests (run with `python scripts/pivot_search.py --test`)

- [x] **16 unit tests — ALL PASS.** Run:
      ```bash
      cd disk-agentic-architecture && python scripts/pivot_search.py --test
      ```
### 14.3 Edge case tests

- [ ] Finding with an empty `secondary` field — no crash, search still uses `key` field.
- [ ] Finding with a hash key — search uses exact word-boundary match (no false positives on partial hashes).
- [ ] Artifact file that doesn't exist in `Disk_Artifacts/` — skipped silently, no error.
- [ ] Finding with a path containing parentheses (e.g., `Program Files (x86)`) — regex escaping works.

---

## 15. `triage_agent.py`

**Note (session 7):** `triage_agent.py` now requires `--mode persistence|events|mft`. There is no
single-agent fallback mode. Each mode reads its own input file and writes its own output file.

### 15.1 Dry-run test (no API key required)

- [ ] **Dry-run works for persistence mode:**
      ```bash
      cd disk-agentic-architecture && ./../.venv/bin/python scripts/triage_agent.py --mode persistence --no-llm
      ```
      Output: `agent1_persistence.md` system prompt + `TRIAGE_INPUT_PERSISTENCE.txt` content. No API call.

- [ ] **Dry-run works for events mode:**
      ```bash
      ./../.venv/bin/python scripts/triage_agent.py --mode events --no-llm
      ```

- [ ] **Dry-run works for mft mode:**
      ```bash
      ./../.venv/bin/python scripts/triage_agent.py --mode mft --no-llm
      ```

- [ ] **No `--mode` → error:** `python scripts/triage_agent.py` (no flag) exits with argparse error. Does NOT silently run in legacy single-agent mode.

### 15.2 Live test (requires `ANTHROPIC_API_KEY`)

Run each agent mode separately or via `run_pipeline.py`:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
cd disk-agentic-architecture
./../.venv/bin/python scripts/triage_agent.py --mode persistence
./../.venv/bin/python scripts/triage_agent.py --mode events
./../.venv/bin/python scripts/triage_agent.py --mode mft
```

- [ ] **`output/triage_persistence.txt`** starts with `=== TRIAGE REPORT ===`, contains `[FINDING]` blocks with `triage_source: persistence`.
- [ ] **`output/triage_events.txt`** — same, with `triage_source: events`.
- [ ] **`output/triage_mft.txt`** — same, with `triage_source: mft` (may be empty if mft_records.txt not yet available).

- [ ] **Required findings (persistence):**
      - `perfmonsvc64.exe` download from `technicalbird.com` — CRITICAL (malicious dropper), prefix P
      - `Update_Sysmon_Rules` scheduled task, author=rsydow-a — HIGH/CRITICAL, prefix P

- [ ] **Required findings (events):**
      - Event 1102 (security log cleared) — HIGH (anti-forensics), prefix E
      - 4624 Type 10 (RDP) logons from BASE-RD-01 — MEDIUM/HIGH, prefix E
      - rsydow-a added to Remote Desktop Users (4732) — HIGH, prefix E
      - Sysmon event 3: wsmprovhost.exe on Socks Proxy Port — HIGH/CRITICAL, prefix E

- [ ] **Output format is valid:** every `[FINDING]` block has `type:`, `key:`, `secondary:`, `severity:`, `reasons:`, `source:`, `triage_source:` fields.

- [ ] **No hallucinations:** every `key:` value in each triage file can be grepped and found in the corresponding TRIAGE_INPUT_*.txt verbatim.

- [ ] **`logs/llm_trace.json` is created** for each mode and contains the full request/response for audit.

---

## 16. End-to-end pipeline test  ← SESSION 6 BUILT

### 16.1 Full pipeline run

```bash
cd disk-agentic-architecture
export ANTHROPIC_API_KEY=sk-ant-...
python scripts/run_pipeline.py
```

Or resuming from a specific stage (e.g., after preprocess is already done):
```bash
python scripts/run_pipeline.py --from-stage 2
```

### 16.2 Stage-by-stage verification

- [ ] **Stage 1 (preprocess):** All three files exist:
      - `output/TRIAGE_INPUT_PERSISTENCE.txt` — < 500 KB
      - `output/TRIAGE_INPUT_EVENTS.txt` — < 500 KB
      - `output/TRIAGE_INPUT_MFT.txt` — < 100 KB, starts with `=== MFT SUMMARY ===`
      - `output/audit/mft_filtered.jsonl` — exists (records below threshold)
- [ ] **Stage 2a–2c (3 triage agents):**
      - `output/triage_persistence.txt` — contains `[FINDING]` blocks with `triage_source: persistence`
      - `output/triage_events.txt` — contains `[FINDING]` blocks with `triage_source: events`
      - `output/triage_mft.txt` — exists (may have 0 findings if mft_records.txt not present)
- [ ] **Stage 2d (merge):** `output/triage_combined.txt` exists, contains findings from all 3 sources, total count = sum of individual counts.
- [ ] **Stage 3 (pivot_search):** `output/pivot.txt` exists, contains `=== FINDING` headers matching `triage_combined.txt` finding count.
- [ ] **Stage 4 (pivot_analyst):** `output/analyst.txt` exists, contains at least one `[CONFIRMED]` or `[INCONCLUSIVE]` block.

### 16.3 IOC traceability audit (critical)

For every `Key Evidence:` line in `analyst.txt`:
```bash
grep -F "<evidence_line_excerpt>" Disk_Artifacts/*.txt
```
Every evidence line must exist verbatim in a source artifact file. Any line
that cannot be found is a hallucination — investigate and add a test.

### 16.4 `--from-stage` behavior

- [ ] `--from-stage 2` skips preprocess (uses existing 3 TRIAGE_INPUT_*.txt files), runs all 3 triage agents + merge + pivot.
- [ ] `--from-stage 3` skips preprocess + all 3 agents (uses existing `triage_combined.txt`), runs pivot + Agent 2.
- [ ] `--from-stage 4` skips everything except Agent 2 (useful for re-running analysis with different prompt).

---

## 17. MFT Anomaly Scorer (preprocess.py) ← SESSION 7 TARGET

### 17.1 Scoring rule unit tests (run with `python scripts/preprocess.py --test`)

Each rule is tested in isolation with a synthetic MFT record dict:

- [ ] **+4 exec ext in temp path**: record with `path=C:\Users\nfury\AppData\Local\Temp\evil.exe` → score includes +4
- [ ] **+4 exec ext in Downloads**: record with `path=C:\Users\nfury\Downloads\tool.ps1` → score includes +4
- [ ] **+4 does NOT apply to benign ext in temp**: `path=C:\Temp\readme.txt` → score does NOT include +4
- [ ] **+3 high entropy outside Program Files**: `entropy=7.5 path=C:\Users\nfury\AppData\Roaming\svc.exe` → score includes +3
- [ ] **+3 high entropy suppressed inside Program Files**: `entropy=7.5 path=C:\Program Files\App\svc.dll` → score does NOT include +3
- [ ] **+3 SI/FN delta > 60s**: `created=2020-11-15T23:00:00Z fn_created=2020-11-10T00:00:00Z` → score includes +3
- [ ] **+3 SI/FN delta ≤ 60s**: delta of 30 seconds → score does NOT include +3
- [ ] **+2 attack window**: `created` falls within `attack_window_start/end` configured in config → score includes +2; NULL config → no bonus
- [ ] **+2 known-bad parent — Recycle.Bin**: `path=C:\$Recycle.Bin\S-1-5-21-...\evil.exe` → score includes +2
- [ ] **+2 Zone.Identifier absent on executable**: exec ext + `ads=` (empty) → score includes +2
- [ ] **+2 Zone.Identifier present**: exec ext + `ads=Zone.Identifier` → score does NOT include +2
- [ ] **-5 NSRL match**: `nsrl_match=true` → score decremented by 5
- [ ] **NSRL can produce negative total**: high-entropy exe with NSRL match → final score may be ≤ 0
- [ ] **+1 path depth > 8 in system dir**: path with 9+ backslashes under `windows\` → score includes +1
- [ ] **+1 depth ≤ 8 suppressed**: path with 8 backslashes → score does NOT include +1

### 17.2 Threshold and top-N filtering

- [ ] With `mft_scoring.threshold=3` and 1000 synthetic records: exactly those with score ≥ 3 appear in output
- [ ] With `mft_scoring.top_n=10` and 100 records all scoring ≥ 3: only the top 10 highest-scoring records appear
- [ ] Records with score < threshold are written to `audit/mft_filtered.jsonl` (count matches total_records − filtered_in)
- [ ] `audit/mft_filtered.jsonl` entries are valid JSON lines with at least `path` and `score` fields

### 17.3 Integration test — real mft_records.txt

- [ ] Run `python scripts/preprocess.py` with `Disk_Artifacts/mft_records.txt` present:
      `TRIAGE_INPUT_MFT.txt` exists and is < 100 KB (down from 13 MB source)
- [ ] `audit/mft_filtered.jsonl` exists and `wc -l` = total_mft_records − filtered_in (within ±5% for partial lines)
- [ ] Known suspicious records survive: any record from `\AppData\Local\Temp\` with a PE extension should have score ≥ 4 and appear in the output

---

## 18. Specialized Triage Agent Prompts ← SESSION 7 TARGET

### 18.1 Prompt dry-run tests (no API key required)

For each mode, `--no-llm` should print the correct prompt file and correct input file, then exit without error:

- [ ] `python scripts/triage_agent.py --mode persistence --no-llm` — prints `agent1_persistence.md` content + `TRIAGE_INPUT_PERSISTENCE.txt` content; exits 0
- [ ] `python scripts/triage_agent.py --mode events --no-llm` — prints `agent1_events.md` content + `TRIAGE_INPUT_EVENTS.txt` content; exits 0
- [ ] `python scripts/triage_agent.py --mode mft --no-llm` — prints `agent1_mft.md` content + `TRIAGE_INPUT_MFT.txt` content; exits 0
- [ ] `python scripts/triage_agent.py` (no `--mode`) — exits with a clear error message, does not silently run in legacy mode

### 18.2 Prompt content sanity checks

- [ ] `agent1_persistence.md` system prompt: contains the words "persistence", "shimcache", "scheduled task", "browser" — covers all 4 artifact categories in its input
- [ ] `agent1_persistence.md` explicitly tells the agent NOT to reason about authentication events or MFT structure
- [ ] `agent1_events.md` system prompt: contains "4625", "4624", "1102", "lateral movement"
- [ ] `agent1_events.md` explicitly tells the agent NOT to reason about file paths or registry persistence
- [ ] `agent1_mft.md` system prompt: contains "entropy", "Zone.Identifier", "timestomp", "stats block"
- [ ] `agent1_mft.md` instructs the agent to use the stats block for macro context
- [ ] All three prompts use the same `[FINDING]` output block format (type, key, secondary, severity, reasons, source)

### 18.3 Finding ID prefix verification

- [ ] `triage_persistence.txt` findings have IDs beginning with `P` (e.g., `P001`)
- [ ] `triage_events.txt` findings have IDs beginning with `E` (e.g., `E001`)
- [ ] `triage_mft.txt` findings have IDs beginning with `M` (e.g., `M001`)

---
*This document is maintained as the canonical test and decision record. Update it after every session.*