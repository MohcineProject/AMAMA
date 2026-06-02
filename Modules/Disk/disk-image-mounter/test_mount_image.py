"""
Unit tests for mount_image.py pure-Python parsing functions.
No root access, no disk image, and no real subprocess calls required.

Run:
    cd Modules/Disk
    .venv/bin/python -m pytest disk-image-mounter/test_mount_image.py -v
    # or:
    .venv/bin/python disk-image-mounter/test_mount_image.py
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Insert disk-image-mounter dir so `import mount_image` works without install
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mount_image  # noqa: E402


def _fake_run(stdout: str, returncode: int = 0):
    """Return a mock that replaces mount_image._run, yielding synthetic stdout."""
    result = MagicMock(spec=subprocess.CompletedProcess)
    result.returncode = returncode
    result.stdout = stdout
    result.stderr = ""
    return MagicMock(return_value=result)


# ---------------------------------------------------------------------------
# Helpers: populate _TOOLS so functions don't KeyError before _run is called
# ---------------------------------------------------------------------------
_FAKE_TOOLS = {
    "mmls":   "mmls",
    "fsstat": "fsstat",
    "icat":   "icat",
    "losetup":"losetup",
    "mount":  "mount",
    "umount": "umount",
    "fusermount": "fusermount",
    "ewfmount": "ewfmount",
    "qemu-nbd": "qemu-nbd",
    "modprobe": "modprobe",
    "partprobe": "partprobe",
    "ntfs-3g": "ntfs-3g",
}

MBR_MMLS_OUTPUT = """\
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0020483071   0020481024   NTFS / exFAT (0x07)
003:  000:001   0020483072   0104857599   0084374528   NTFS / exFAT (0x07)
"""

GPT_MMLS_OUTPUT = """\
GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  Meta      0000000001   0000000001   0000000001   GPT Header
003:  Meta      0000000002   0000000033   0000000032   Partition Table
004:  000:000   0000002048   0000534527   0000532480   Basic data partition
"""

EMPTY_MMLS_OUTPUT = """\
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
"""

ZERO_LENGTH_MMLS_OUTPUT = """\
DOS Partition Table
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  000:000   0000000000   0000000000   0000000000   Zero-length entry
002:  000:001   0000002048   0020483071   0020481024   NTFS / exFAT (0x07)
"""


# ===========================================================================
# 1. mmls parsing
# ===========================================================================

class TestParseMmls(unittest.TestCase):

    def _call(self, stdout, returncode=0):
        with patch.object(mount_image, "_TOOLS", _FAKE_TOOLS), \
             patch("mount_image._run", _fake_run(stdout, returncode)):
            return mount_image.parse_mmls("/fake/block")

    def test_parse_mmls_mbr(self):
        parts = self._call(MBR_MMLS_OUTPUT)
        self.assertEqual(len(parts), 2, f"Expected 2 partitions, got {len(parts)}: {parts}")
        self.assertEqual(parts[0].start_sector, 2048)
        self.assertEqual(parts[0].length_sectors, 20481024)
        self.assertEqual(parts[1].start_sector, 20483072)
        self.assertEqual(parts[1].length_sectors, 84374528)

    def test_parse_mmls_gpt(self):
        parts = self._call(GPT_MMLS_OUTPUT)
        self.assertEqual(len(parts), 1, f"Expected 1 partition, got {len(parts)}: {parts}")
        self.assertEqual(parts[0].start_sector, 2048)
        self.assertEqual(parts[0].description, "Basic data partition")

    def test_parse_mmls_empty(self):
        parts = self._call(EMPTY_MMLS_OUTPUT)
        self.assertEqual(parts, [], "Expected empty list for header-only mmls output")

    def test_parse_mmls_zero_length(self):
        parts = self._call(ZERO_LENGTH_MMLS_OUTPUT)
        self.assertEqual(len(parts), 1, "Zero-length row should be excluded")
        self.assertEqual(parts[0].start_sector, 2048)

    def test_parse_mmls_subprocess_fails(self):
        parts = self._call("", returncode=1)
        self.assertEqual(parts, [], "Non-zero returncode should return empty list")


# ===========================================================================
# 2. fsstat filesystem type detection
# ===========================================================================

class TestDetectFsType(unittest.TestCase):

    def _call(self, stdout):
        with patch.object(mount_image, "_TOOLS", _FAKE_TOOLS), \
             patch("mount_image._run", _fake_run(stdout)):
            return mount_image.detect_fs_type("/fake/block", 2048)

    def test_detect_fs_ntfs(self):
        out = "File System Type: NTFS\nSome other line"
        self.assertEqual(self._call(out), "ntfs")

    def test_detect_fs_ext4(self):
        out = "File System Type: Ext4\nVolume Name: test"
        self.assertEqual(self._call(out), "ext4")

    def test_detect_fs_xfs(self):
        out = "File System Type: XFS"
        self.assertEqual(self._call(out), "xfs")

    def test_detect_fs_unknown(self):
        out = "Some output\nNo filesystem line here"
        self.assertEqual(self._call(out), "unknown")


# ===========================================================================
# 3. BitLocker detection
# ===========================================================================

class TestCheckBitlocker(unittest.TestCase):

    def test_bitlocker_detected(self):
        sector = bytearray(512)
        sector[3:14] = mount_image._BITLOCKER_SIG
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(bytes(sector))
            fname = f.name
        try:
            self.assertTrue(mount_image.check_bitlocker(fname, 0))
        finally:
            os.unlink(fname)

    def test_bitlocker_not_detected(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * 512)
            fname = f.name
        try:
            self.assertFalse(mount_image.check_bitlocker(fname, 0))
        finally:
            os.unlink(fname)

    def test_bitlocker_missing_file(self):
        self.assertFalse(mount_image.check_bitlocker("/nonexistent/path", 0))


# ===========================================================================
# 4. Partition / OS selection — pure functions
# ===========================================================================

class TestSelectWindowsPartition(unittest.TestCase):

    def _ntfs(self, sectors):
        return mount_image.PartitionInfo(start_sector=2048, length_sectors=sectors,
                                         description="NTFS", fstype="ntfs")

    def _ext4(self, sectors):
        return mount_image.PartitionInfo(start_sector=4096, length_sectors=sectors,
                                         description="ext4", fstype="ext4")

    def test_select_largest_ntfs(self):
        small  = self._ntfs(2_097_152)   # ~1 GB
        large  = self._ntfs(104_857_600) # ~50 GB
        linux  = self._ext4(20_971_520)
        result = mount_image.select_windows_partition([small, linux, large])
        self.assertEqual(result.length_sectors, 104_857_600)

    def test_select_no_ntfs_raises(self):
        with self.assertRaises(ValueError):
            mount_image.select_windows_partition([self._ext4(10_000_000)])

    def test_select_single_ntfs(self):
        p = self._ntfs(50_000_000)
        self.assertIs(mount_image.select_windows_partition([p]), p)


class TestDetermineOs(unittest.TestCase):

    def _part(self, fstype):
        return mount_image.PartitionInfo(start_sector=0, length_sectors=1,
                                         description="test", fstype=fstype)

    def test_windows(self):
        self.assertEqual(mount_image.determine_os([self._part("ntfs")]), "windows")

    def test_linux_ext4(self):
        self.assertEqual(mount_image.determine_os([self._part("ext4")]), "linux")

    def test_mixed_linux_wins(self):
        # Linux filesystem presence takes precedence
        parts = [self._part("ntfs"), self._part("ext4")]
        self.assertEqual(mount_image.determine_os(parts), "linux")

    def test_unknown(self):
        parts = [self._part("unknown"), self._part("bitlocker")]
        self.assertEqual(mount_image.determine_os(parts), "unknown")

    def test_xfs_is_linux(self):
        self.assertEqual(mount_image.determine_os([self._part("xfs")]), "linux")


# ===========================================================================
# 5. Browser discovery
# ===========================================================================

class TestDiscoverBrowsers(unittest.TestCase):

    def _make_file(self, base, *parts):
        path = os.path.join(base, *parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        Path(path).touch()
        return path

    def test_discover_chrome(self):
        with tempfile.TemporaryDirectory() as d:
            self._make_file(d, "Users", "alice", "AppData", "Local",
                            "Google", "Chrome", "User Data", "Default", "History")
            r = mount_image.discover_browsers(d)
            self.assertIsNotNone(r["chrome_history"])
            self.assertEqual(r["chrome_browser_name"], "chrome")
            self.assertIsNone(r["firefox_places"])

    def test_discover_edge(self):
        with tempfile.TemporaryDirectory() as d:
            self._make_file(d, "Users", "alice", "AppData", "Local",
                            "Microsoft", "Edge", "User Data", "Default", "History")
            r = mount_image.discover_browsers(d)
            self.assertIsNotNone(r["chrome_history"])
            self.assertEqual(r["chrome_browser_name"], "edge")

    def test_discover_firefox(self):
        with tempfile.TemporaryDirectory() as d:
            self._make_file(d, "Users", "alice", "AppData", "Roaming",
                            "Mozilla", "Firefox", "Profiles", "abc.default", "places.sqlite")
            r = mount_image.discover_browsers(d)
            self.assertIsNotNone(r["firefox_places"])
            self.assertTrue(r["firefox_places"].endswith("places.sqlite"))

    def test_discover_none(self):
        with tempfile.TemporaryDirectory() as d:
            r = mount_image.discover_browsers(d)
            self.assertIsNone(r["chrome_history"])
            self.assertIsNone(r["firefox_places"])

    def test_discover_multiuser_picks_newest(self):
        with tempfile.TemporaryDirectory() as d:
            older = self._make_file(d, "Users", "alice", "AppData", "Local",
                                    "Google", "Chrome", "User Data", "Default", "History")
            # Small delay to ensure mtime difference
            time.sleep(0.05)
            newer = self._make_file(d, "Users", "bob", "AppData", "Local",
                                    "Google", "Chrome", "User Data", "Default", "History")
            # Touch newer to ensure it has a more recent mtime
            os.utime(newer, None)
            r = mount_image.discover_browsers(d)
            self.assertEqual(r["chrome_history"], newer,
                             f"Expected newest ({newer}) but got {r['chrome_history']}")


# ===========================================================================
# 6. Image directory scanning
# ===========================================================================

class TestScanImageDir(unittest.TestCase):

    def test_scan_no_files(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SystemExit) as ctx:
                mount_image.scan_image_dir(d)
            self.assertEqual(ctx.exception.code, 1)

    def test_scan_multiple_files(self):
        with tempfile.TemporaryDirectory() as d:
            Path(os.path.join(d, "disk1.e01")).touch()
            Path(os.path.join(d, "disk2.e01")).touch()
            with self.assertRaises(SystemExit) as ctx:
                mount_image.scan_image_dir(d)
            self.assertEqual(ctx.exception.code, 1)

    def test_scan_one_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(os.path.join(d, "disk.e01"))
            p.touch()
            result = mount_image.scan_image_dir(d)
            self.assertEqual(result, p)

    def test_scan_nonexistent_dir(self):
        with self.assertRaises(SystemExit) as ctx:
            mount_image.scan_image_dir("/nonexistent/dir/that/does/not/exist")
        self.assertEqual(ctx.exception.code, 1)

    def test_scan_ignores_non_image_files(self):
        with tempfile.TemporaryDirectory() as d:
            Path(os.path.join(d, "README.txt")).touch()
            Path(os.path.join(d, "notes.pdf")).touch()
            p = Path(os.path.join(d, "disk.dd"))
            p.touch()
            result = mount_image.scan_image_dir(d)
            self.assertEqual(result, p)


# ===========================================================================
# 7. Config generation
# ===========================================================================

class TestBuildConfig(unittest.TestCase):

    def test_build_config_paths(self):
        with tempfile.TemporaryDirectory() as ntfs:
            with tempfile.NamedTemporaryFile(suffix=".mft", delete=False) as mf:
                mft_path = mf.name
            try:
                browsers = {
                    "chrome_history":      None,
                    "chrome_browser_name": "chrome",
                    "firefox_places":      None,
                }
                cfg = mount_image.build_config(ntfs, mft_path, browsers)

                # mft.input must be absolute and point to our mft file
                self.assertTrue(os.path.isabs(cfg["mft"]["input"]))
                self.assertEqual(cfg["mft"]["input"], os.path.abspath(mft_path))

                # volume_root must be the ntfs mount
                self.assertEqual(cfg["mft"]["volume_root"], ntfs)

                # registry hive_dir must be under ntfs mount
                self.assertTrue(cfg["registry"]["hive_dir"].startswith(ntfs))

                # eventlog dir under ntfs mount
                self.assertTrue(cfg["eventlog"]["evtx_dir"].startswith(ntfs))

                # No INPUT_DISK placeholders
                cfg_str = json.dumps(cfg)
                self.assertNotIn("INPUT_DISK", cfg_str,
                                 "config.json must not contain INPUT_DISK placeholder")

                # Browser None should be Python None, not string "null"
                self.assertIsNone(cfg["browser"]["chrome_history"])
                self.assertNotEqual(cfg["browser"]["chrome_history"], "null")

            finally:
                os.unlink(mft_path)

    def test_build_config_all_sections_present(self):
        with tempfile.TemporaryDirectory() as ntfs:
            with tempfile.NamedTemporaryFile(suffix=".mft", delete=False) as mf:
                mft_path = mf.name
            try:
                browsers = {
                    "chrome_history":      None,
                    "chrome_browser_name": "chrome",
                    "firefox_places":      None,
                }
                cfg = mount_image.build_config(ntfs, mft_path, browsers)
                for section in ("mft", "registry", "eventlog", "execution",
                                "persistence", "browser"):
                    self.assertIn(section, cfg, f"Missing config section: {section}")
            finally:
                os.unlink(mft_path)


# ===========================================================================
# 8. System user directory filter (_is_system_user_dir)
# ===========================================================================

class TestIsSystemUserDir(unittest.TestCase):

    def test_known_system_dirs(self):
        for name in ("Public", "Default", "Default User", "All Users"):
            self.assertTrue(mount_image._is_system_user_dir(name), f"{name!r} should be system")

    def test_dotnet_dirs(self):
        for name in (".NET v4.5", ".NET v4.5 Classic", ".NET v2.0"):
            self.assertTrue(mount_image._is_system_user_dir(name), f"{name!r} should be system")

    def test_service_accounts(self):
        for name in ("NetworkService", "LocalService", "systemprofile",
                     "MSSQL$SQLEXPRESS", "IIS_IUSRS"):
            self.assertTrue(mount_image._is_system_user_dir(name), f"{name!r} should be system")

    def test_real_users_not_filtered(self):
        for name in ("Administrator", "alice", "rsydow", "rsydow-a", "nfury", "jsmith"):
            self.assertFalse(mount_image._is_system_user_dir(name),
                             f"{name!r} should NOT be filtered as system")


# ===========================================================================
# Run standalone (without pytest)
# ===========================================================================

if __name__ == "__main__":
    loader  = unittest.TestLoader()
    suite   = loader.loadTestsFromModule(sys.modules[__name__])
    runner  = unittest.TextTestRunner(verbosity=2)
    result  = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
