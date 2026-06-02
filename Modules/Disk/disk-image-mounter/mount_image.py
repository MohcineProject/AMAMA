#!/usr/bin/env python3
"""
Forensic disk image mounter — SIFT workstation (Linux only).

Automates the steps required before running disk-collector:
  1. Scans Disk_image/ for a supported forensic image (.e01, .dd, .vmdk, ...)
  2. Mounts it with the appropriate tool (ewfmount / losetup / qemu-nbd)
  3. Detects OS type from partition filesystem types
  4. If a Linux disk is detected → exits cleanly (pipeline is Windows-only)
  5. Extracts the raw $MFT with icat
  6. Mounts the NTFS partition read-only with ntfs-3g
  7. Auto-discovers Chrome / Edge / Firefox artifacts under Users/
  8. Writes a ready-to-use config.json for disk-collector

Must be run as root (sudo).

Usage:
    sudo python disk-image-mounter/mount_image.py
    sudo python disk-image-mounter/mount_image.py --image-dir Disk_image --out-config config.json
    sudo python disk-image-mounter/mount_image.py --umount
"""
from __future__ import annotations

import argparse
import glob as _glob
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="[mount_image] %(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Path constants (relative to project root)
# ---------------------------------------------------------------------------

_MODULE_DIR = Path(__file__).parent.resolve()
_PROJECT_ROOT = _MODULE_DIR.parent
_CONFIG_TEMPLATE = _PROJECT_ROOT / "disk-collector" / "config.example.json"

DEFAULT_IMAGE_DIR  = str(_PROJECT_ROOT / "Disk_image")
DEFAULT_EWF_MOUNT  = "/tmp/dfir_ewf"
DEFAULT_NTFS_MOUNT = "/tmp/dfir_ntfs"
DEFAULT_STATE_FILE = "/tmp/dfir_mount_state.json"
DEFAULT_MFT_OUT    = str(_PROJECT_ROOT / "INPUT_DISK" / "raw_mft")
DEFAULT_CONFIG_OUT = str(_PROJECT_ROOT / "config.json")

# ---------------------------------------------------------------------------
# Image format sets
# ---------------------------------------------------------------------------

_EWF_EXTS  = {".e01", ".ex01"}
_DD_EXTS   = {".dd", ".img", ".raw"}
_VMDK_EXTS = {".vmdk", ".vhd", ".vhdx"}
SUPPORTED_EXTS = _EWF_EXTS | _DD_EXTS | _VMDK_EXTS

# ---------------------------------------------------------------------------
# Filesystem type sets for OS detection
# ---------------------------------------------------------------------------

_LINUX_FS   = {"ext2", "ext3", "ext4", "xfs", "btrfs", "jfs", "reiserfs"}
_WINDOWS_FS = {"ntfs"}

# ---------------------------------------------------------------------------
# BitLocker VBR signature (bytes 3-13 of the Volume Boot Record)
# Hex: EB 58 90 2D 46 56 45 2D 46 53 2D  →  "ëX.-FVE-FS-"
# ---------------------------------------------------------------------------

_BITLOCKER_SIG = bytes([
    0xEB, 0x58, 0x90, 0x2D, 0x46, 0x56, 0x45, 0x2D, 0x46, 0x53, 0x2D,
])

# ---------------------------------------------------------------------------
# Tool → install package mapping (for clear error messages)
# ---------------------------------------------------------------------------

_TOOL_PKG = {
    "ewfmount":  "ewf-tools      (sudo apt install ewf-tools)",
    "mmls":      "sleuthkit      (sudo apt install sleuthkit)",
    "fsstat":    "sleuthkit      (sudo apt install sleuthkit)",
    "icat":      "sleuthkit      (sudo apt install sleuthkit)",
    "losetup":   "util-linux     (pre-installed)",
    "mount":     "util-linux     (pre-installed)",
    "umount":    "util-linux     (pre-installed)",
    "fusermount":"fuse           (sudo apt install fuse)",
    "qemu-nbd":  "qemu-utils     (sudo apt install qemu-utils)",
    "modprobe":  "kmod           (pre-installed)",
    "partprobe": "parted         (sudo apt install parted)",
    "ntfs-3g":   "ntfs-3g        (sudo apt install ntfs-3g)",
}

_TOOLS_FOR_FMT: Dict[str, set] = {
    "ewf":  {"ewfmount", "mmls", "fsstat", "icat", "losetup",
              "mount", "umount", "fusermount", "ntfs-3g"},
    "dd":   {"losetup", "mmls", "fsstat", "icat",
              "mount", "umount", "ntfs-3g"},
    "vmdk": {"qemu-nbd", "modprobe", "partprobe", "mmls", "fsstat", "icat",
              "mount", "umount", "ntfs-3g"},
}

# ---------------------------------------------------------------------------
# Regex parsers
# ---------------------------------------------------------------------------

# Matches only real data partition rows from mmls output.
# Slot column for real partitions looks like "000:001"; Meta and ------- rows are skipped.
_MMLS_LINE = re.compile(
    r"^\d{3}:\s+"       # row index "002:  "
    r"(\d+:\d+)\s+"     # Slot: only real partitions (e.g. "000:001")
    r"(\d+)\s+"         # Start sector
    r"(\d+)\s+"         # End sector
    r"(\d+)\s+"         # Length in sectors
    r"(.+)$"            # Description
)

_FSSTAT_FS_TYPE = re.compile(r"^File System Type:\s+(.+)$", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PartitionInfo:
    start_sector:   int
    length_sectors: int
    description:    str
    fstype:         str  = "unknown"
    bitlocker:      bool = False

    @property
    def size_gb(self) -> float:
        return (self.length_sectors * 512) / (1024 ** 3)

    @property
    def offset_bytes(self) -> int:
        return self.start_sector * 512

    @property
    def size_bytes(self) -> int:
        return self.length_sectors * 512


@dataclass
class MountState:
    """Tracks every mount/device created so cleanup is deterministic."""
    ewf_path:   Optional[str] = None  # EWF FUSE mount dir  → fusermount -u
    part_loop:  Optional[str] = None  # explicit partition loop device → losetup -d
    disk_loop:  Optional[str] = None  # full-disk loop device (DD)    → losetup -d
    nbd_device: Optional[str] = None  # qemu-nbd device (VMDK)        → qemu-nbd --disconnect
    ntfs_mount: Optional[str] = None  # ntfs-3g mount point            → umount


# Module-level state accessible by signal handlers and _die()
_STATE = MountState()
_TOOLS: Dict[str, str] = {}

# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def _run(
    cmd: List[str],
    desc: str,
    fatal:   bool = True,
    capture: bool = True,
    timeout: int  = 60,
) -> subprocess.CompletedProcess:
    log.debug("$ %s", " ".join(str(c) for c in cmd))
    result = subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout)
    if result.returncode != 0 and fatal:
        stderr = result.stderr.strip() if result.stderr else ""
        _die(f"{desc} failed (exit {result.returncode}). {stderr}")
    return result


def _die(msg: str) -> None:
    log.error(msg)
    cleanup(_STATE, _TOOLS)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

def check_root() -> None:
    if os.geteuid() != 0:
        log.error(
            "This script must be run as root.\n"
            "  sudo python disk-image-mounter/mount_image.py"
        )
        sys.exit(1)


def find_tools(fmt: str) -> Dict[str, str]:
    """Locate all tools required for the given image format.
    Exits with an install guide if any are missing."""
    needed = _TOOLS_FOR_FMT[fmt]
    tools:   Dict[str, str] = {}
    missing: List[str]      = []

    for name in needed:
        path = shutil.which(name)
        if path:
            tools[name] = path
        else:
            missing.append(name)

    if missing:
        log.error("Missing required tools — install them first:")
        by_pkg: Dict[str, List[str]] = {}
        for t in missing:
            pkg = _TOOL_PKG.get(t, "unknown package")
            by_pkg.setdefault(pkg, []).append(t)
        for pkg, names in by_pkg.items():
            log.error("  %-40s  ← %s", pkg, ", ".join(names))
        sys.exit(1)

    return tools


# ---------------------------------------------------------------------------
# Image discovery
# ---------------------------------------------------------------------------

def scan_image_dir(image_dir: str) -> Path:
    """Find exactly one supported image file in image_dir. Exits on 0 or >1."""
    try:
        candidates = [
            p for p in Path(image_dir).iterdir()
            if p.is_file() and p.suffix.lower() in SUPPORTED_EXTS
        ]
    except FileNotFoundError:
        log.error("Image directory not found: %s", image_dir)
        sys.exit(1)

    if not candidates:
        log.error(
            "No supported image found in %s.\n"
            "  Supported: %s\n"
            "  Drop one image file into that directory and retry.",
            image_dir, ", ".join(sorted(SUPPORTED_EXTS)),
        )
        sys.exit(1)

    if len(candidates) > 1:
        log.error(
            "Multiple image files found in %s — place exactly one image:\n  %s",
            image_dir,
            "\n  ".join(str(p) for p in sorted(candidates)),
        )
        sys.exit(1)

    return candidates[0]


def image_format(image_path: Path) -> str:
    ext = image_path.suffix.lower()
    if ext in _EWF_EXTS:
        return "ewf"
    if ext in _DD_EXTS:
        return "dd"
    return "vmdk"


# ---------------------------------------------------------------------------
# Image mounting  (each function returns the raw-block path for mmls/icat)
# ---------------------------------------------------------------------------

def mount_ewf(image_path: Path, ewf_mount: str) -> str:
    """ewfmount → /tmp/dfir_ewf/; returns /tmp/dfir_ewf/ewf1."""
    os.makedirs(ewf_mount, exist_ok=True)
    _run([_TOOLS["ewfmount"], str(image_path), ewf_mount],
         "ewfmount", capture=True, timeout=60)
    _STATE.ewf_path = ewf_mount

    ewf1 = os.path.join(ewf_mount, "ewf1")
    for _ in range(20):   # poll up to 10 s for the FUSE mount
        if os.path.exists(ewf1):
            log.info("EWF mounted → %s", ewf1)
            return ewf1
        time.sleep(0.5)

    _die(f"ewfmount succeeded but {ewf1} did not appear after 10 s. Is the image valid?")


def mount_dd(image_path: Path) -> str:
    """losetup -Pf --show → /dev/loopN; returns that device path."""
    result = _run(
        [_TOOLS["losetup"], "-Pf", "--show", str(image_path)],
        "losetup",
    )
    dev = result.stdout.strip()
    _STATE.disk_loop = dev
    log.info("Loop device: %s", dev)
    return dev


def mount_vmdk(image_path: Path) -> str:
    """qemu-nbd -r -c /dev/nbd0 + partprobe; returns /dev/nbd0."""
    # Load nbd kernel module (ignore error if already loaded)
    subprocess.run(
        [_TOOLS.get("modprobe", "modprobe"), "nbd", "max_part=8"],
        capture_output=True,
    )

    nbd = "/dev/nbd0"
    _run([_TOOLS["qemu-nbd"], "-r", "-c", nbd, str(image_path)], "qemu-nbd")
    _STATE.nbd_device = nbd

    _run([_TOOLS["partprobe"], nbd], "partprobe", fatal=False)

    # Poll briefly for partition devices
    for _ in range(10):
        if _glob.glob(f"{nbd}p*"):
            break
        time.sleep(0.5)

    log.info("NBD device: %s", nbd)
    return nbd


# ---------------------------------------------------------------------------
# Partition analysis
# ---------------------------------------------------------------------------

def parse_mmls(raw_block: str) -> List[PartitionInfo]:
    """Run mmls and parse stdout. Returns only real data-partition rows."""
    result = _run([_TOOLS["mmls"], raw_block], "mmls", fatal=False)
    if result.returncode != 0:
        return []

    partitions: List[PartitionInfo] = []
    for line in result.stdout.splitlines():
        m = _MMLS_LINE.match(line.strip())
        if not m:
            continue
        start  = int(m.group(2))
        length = int(m.group(4))
        desc   = m.group(5).strip()
        if length == 0:
            continue
        partitions.append(PartitionInfo(
            start_sector=start,
            length_sectors=length,
            description=desc,
        ))
    return partitions


def detect_fs_type(raw_block: str, start_sector: int) -> str:
    """fsstat -o <sector> → normalized filesystem type string."""
    result = _run(
        [_TOOLS["fsstat"], "-o", str(start_sector), raw_block],
        "fsstat",
        fatal=False,
        timeout=30,
    )
    for line in result.stdout.splitlines():
        m = _FSSTAT_FS_TYPE.match(line.strip())
        if not m:
            continue
        raw = m.group(1).strip().lower()
        for fs in ("ntfs", "ext4", "ext3", "ext2", "xfs", "btrfs",
                   "fat32", "fat16", "fat", "exfat", "jfs", "reiserfs"):
            if fs in raw:
                return fs
        return raw  # pass through unrecognized types verbatim
    return "unknown"


def check_bitlocker(raw_block: str, start_sector: int) -> bool:
    """Read the first sector of the partition and check for the FVE signature."""
    try:
        with open(raw_block, "rb") as f:
            f.seek(start_sector * 512)
            sector = f.read(512)
    except OSError:
        return False
    return len(sector) >= 14 and sector[3:14] == _BITLOCKER_SIG


def detect_partitions(raw_block: str) -> List[PartitionInfo]:
    """mmls → fsstat per partition → BitLocker check. Returns annotated list."""
    partitions = parse_mmls(raw_block)

    if not partitions:
        # Might be a raw partition image with no partition table; try offset 0.
        log.info("mmls found no partitions — trying fsstat at offset 0 ...")
        fstype = detect_fs_type(raw_block, 0)
        if fstype != "unknown":
            log.info("Treating whole device as a single partition (fstype=%s).", fstype)
            try:
                size_sectors = os.path.getsize(raw_block) // 512
            except OSError:
                size_sectors = 0
            p = PartitionInfo(
                start_sector=0,
                length_sectors=size_sectors,
                description="(whole device)",
                fstype=fstype,
            )
            return [p]
        _die(
            f"No partitions found in {raw_block} and fsstat at offset 0 failed.\n"
            "  Is this a valid disk image? (corrupt image, unsupported format, or wrong path)"
        )

    bitlocker_warnings: List[str] = []
    for part in partitions:
        if check_bitlocker(raw_block, part.start_sector):
            part.fstype    = "bitlocker"
            part.bitlocker = True
            bitlocker_warnings.append(
                f"  sector {part.start_sector:>10d} ({part.size_gb:.1f} GB) — BitLocker"
            )
            continue
        part.fstype = detect_fs_type(raw_block, part.start_sector)
        log.debug(
            "  partition sector=%-10d  size=%.1f GB  fstype=%-10s  %s",
            part.start_sector, part.size_gb, part.fstype, part.description,
        )

    if bitlocker_warnings:
        log.warning(
            "BitLocker-encrypted partition(s) detected — cannot be mounted without a recovery key:\n%s\n"
            "  To decrypt first:  sudo apt install dislocker\n"
            "  Then:  dislocker -V /dev/sdX -p <recovery_key> -- /tmp/dfir_decrypt",
            "\n".join(bitlocker_warnings),
        )

    return partitions


# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

def determine_os(partitions: List[PartitionInfo]) -> str:
    """Returns 'windows', 'linux', or 'unknown' based on filesystem types."""
    fstypes = {p.fstype for p in partitions}
    if fstypes & _LINUX_FS:
        return "linux"
    if fstypes & _WINDOWS_FS:
        return "windows"
    return "unknown"


def select_windows_partition(partitions: List[PartitionInfo]) -> PartitionInfo:
    """Pick the largest NTFS partition — almost always the C: drive."""
    ntfs = [p for p in partitions if p.fstype == "ntfs"]
    if not ntfs:
        raise ValueError("No NTFS partition found")
    return max(ntfs, key=lambda p: p.length_sectors)


# ---------------------------------------------------------------------------
# $MFT extraction
# ---------------------------------------------------------------------------

def extract_mft(raw_block: str, part: PartitionInfo, out_path: str) -> None:
    """icat -o <sector> <raw_block> 0 → out_path (inode 0 = $MFT in NTFS)."""
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    log.info("Extracting $MFT (sector offset %d) → %s ...", part.start_sector, out_path)

    with open(out_path, "wb") as out_f:
        result = subprocess.run(
            [_TOOLS["icat"], "-o", str(part.start_sector), raw_block, "0"],
            stdout=out_f,
            stderr=subprocess.PIPE,
            timeout=600,   # large MFTs can take a few minutes
        )

    if result.returncode != 0:
        _die(
            "icat failed: "
            + result.stderr.decode(errors="replace").strip()
        )

    size = os.path.getsize(out_path)
    if size == 0:
        _die(
            f"icat produced an empty $MFT at {out_path}.\n"
            "  Verify the partition offset is correct. "
            f"Expected NTFS at sector {part.start_sector}."
        )
    log.info("$MFT extracted: %d bytes (%.1f MB)", size, size / 1024 / 1024)


# ---------------------------------------------------------------------------
# NTFS mounting
# ---------------------------------------------------------------------------

def _find_partition_device(disk_dev: str, start_sector: int) -> Optional[str]:
    """Match start_sector → /dev/loopNpY or /dev/nbd0pY via sysfs."""
    dev_name  = os.path.basename(disk_dev)   # "loop3" or "nbd0"
    sys_block = f"/sys/block/{dev_name}"
    if not os.path.isdir(sys_block):
        return None
    for entry in sorted(os.listdir(sys_block)):
        if not entry.startswith(dev_name):
            continue
        start_file = f"{sys_block}/{entry}/start"
        if not os.path.exists(start_file):
            continue
        try:
            with open(start_file) as f:
                if int(f.read().strip()) == start_sector:
                    return f"/dev/{entry}"
        except (ValueError, OSError):
            continue
    return None


def _make_partition_loop(raw_block: str, part: PartitionInfo) -> str:
    """Create an offset-bounded loop device for a specific partition."""
    result = _run([
        _TOOLS["losetup"],
        "-o", str(part.offset_bytes),
        f"--sizelimit={part.size_bytes}",
        "-f", "--show",
        raw_block,
    ], "losetup (partition)")
    dev = result.stdout.strip()
    _STATE.part_loop = dev
    return dev


def mount_ntfs(raw_block: str, part: PartitionInfo, fmt: str, ntfs_mount: str) -> None:
    """Mount the Windows NTFS partition read-only at ntfs_mount."""
    os.makedirs(ntfs_mount, exist_ok=True)

    if fmt == "ewf":
        # ewf1 is a FUSE file — create an explicit loop device for the partition
        # so ntfs-3g receives a real block device (more reliable than mount -o loop).
        if part.start_sector == 0 and part.description == "(whole device)":
            # Bare partition image (no MBR/GPT): os.path.getsize() on the EWF FUSE
            # file can be a few KB smaller than the NTFS volume record, causing
            # "Failed to read last sector" with --sizelimit.  Skip the limit and let
            # ntfs-3g use the loop device's full extent instead.
            result = _run([
                _TOOLS["losetup"], "-f", "--show", raw_block,
            ], "losetup (whole-device, no sizelimit)")
            part_dev = result.stdout.strip()
            _STATE.part_loop = part_dev
        else:
            part_dev = _make_partition_loop(raw_block, part)
        log.info("EWF partition loop device: %s", part_dev)

    else:  # "dd" or "vmdk"
        # Partition devices were created by losetup -Pf or qemu-nbd + partprobe.
        # Locate the right one via sysfs.
        part_dev = _find_partition_device(raw_block, part.start_sector)
        if part_dev is None:
            log.warning(
                "Partition device for %s at sector %d not found via sysfs. "
                "Falling back to losetup offset mount.",
                raw_block, part.start_sector,
            )
            part_dev = _make_partition_loop(raw_block, part)
        log.info("Partition device: %s", part_dev)

    log.info("Mounting NTFS read-only at %s ...", ntfs_mount)
    result = _run([
        _TOOLS["mount"], "-t", "ntfs-3g",
        "-o", "ro,noexec,nosuid",
        part_dev, ntfs_mount,
    ], "mount ntfs-3g", fatal=False, timeout=30)

    if result.returncode != 0:
        stderr = result.stderr.strip()
        # ntfs-3g refuses to mount hibernated volumes — retry with a hint
        if any(kw in stderr.lower() for kw in ("hiberfil", "hibernate", "fast shutdown")):
            log.warning(
                "Windows appears to have been hibernated or fast-shutdown. "
                "Retrying mount in read-only recovery mode ..."
            )
            _run([
                _TOOLS["mount"], "-t", "ntfs-3g",
                "-o", "ro,noexec,nosuid,remove_hiberfile",
                part_dev, ntfs_mount,
            ], "mount ntfs-3g (recovery)")
        elif "last sector" in stderr.lower() or (
            "invalid argument" in stderr.lower() and "read last sector" in stderr.lower()
        ):
            # NTFS volume size in boot sector exceeds the actual image extent by a few
            # sectors (common with EWF/E01 captures).  ntfs-3g is strict; the kernel
            # ntfs3 driver tolerates the mismatch.
            log.warning(
                "ntfs-3g: NTFS volume size exceeds image extent (sector mismatch). "
                "Retrying with kernel ntfs3 driver ..."
            )
            _run([
                _TOOLS["mount"], "-t", "ntfs3",
                "-o", "ro,noexec,nosuid",
                part_dev, ntfs_mount,
            ], "mount ntfs3 (kernel driver)")
        else:
            _die(f"ntfs-3g mount failed: {stderr}")

    _STATE.ntfs_mount = ntfs_mount

    # Sanity check: confirm this is the Windows system partition
    win_sys = os.path.join(ntfs_mount, "Windows", "System32")
    if not os.path.isdir(win_sys):
        log.warning(
            "%s not found on the mounted partition. "
            "This may not be the Windows system drive. "
            "Continuing — some collector paths may produce empty output.",
            win_sys,
        )
    else:
        log.info("Windows/System32 verified at %s", ntfs_mount)


# ---------------------------------------------------------------------------
# Browser artifact discovery
# ---------------------------------------------------------------------------

def discover_browsers(ntfs_mount: str) -> Dict[str, Optional[str]]:
    """Glob for Chrome, Edge, and Firefox artifacts under Users/."""
    results: Dict[str, Optional[str]] = {
        "chrome_history":      None,
        "chrome_browser_name": "chrome",
        "firefox_places":      None,
    }

    # Chrome
    chrome_hits = _glob.glob(os.path.join(
        ntfs_mount, "Users", "*", "AppData", "Local",
        "Google", "Chrome", "User Data", "Default", "History",
    ))
    # Edge (Chromium-based) — same SQLite schema as Chrome
    edge_hits = _glob.glob(os.path.join(
        ntfs_mount, "Users", "*", "AppData", "Local",
        "Microsoft", "Edge", "User Data", "Default", "History",
    ))

    def _newest(paths: List[str]) -> str:
        return max(paths, key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0)

    if chrome_hits:
        best = _newest(chrome_hits)
        results["chrome_history"]      = best
        results["chrome_browser_name"] = "chrome"
        log.info("Chrome history: %s", best)
        if len(chrome_hits) > 1:
            log.warning(
                "Multiple Chrome profiles found (%d); using most recently modified.",
                len(chrome_hits),
            )
    elif edge_hits:
        best = _newest(edge_hits)
        results["chrome_history"]      = best
        results["chrome_browser_name"] = "edge"
        log.info("Edge history: %s", best)
    else:
        log.warning("No Chrome or Edge History file found under Users/.")

    # Firefox
    ff_hits = _glob.glob(os.path.join(
        ntfs_mount, "Users", "*", "AppData", "Roaming",
        "Mozilla", "Firefox", "Profiles", "*", "places.sqlite",
    ))
    if ff_hits:
        best = _newest(ff_hits)
        results["firefox_places"] = best
        log.info("Firefox places.sqlite: %s", best)
        if len(ff_hits) > 1:
            log.warning(
                "Multiple Firefox profiles found (%d); using most recently modified.",
                len(ff_hits),
            )
    else:
        log.warning("No Firefox places.sqlite found under Users/.")

    return results


# ---------------------------------------------------------------------------
# Username and Amcache discovery (helpers for build_config)
# ---------------------------------------------------------------------------

_SYSTEM_USER_DIRS = {"Public", "Default", "Default User", "All Users"}

# Patterns for non-human user directories that Windows places under Users/
# on various configurations (server roles, .NET framework, service accounts).
_SYSTEM_USER_PATTERNS = (
    ".NET",          # .NET v4.5, .NET v4.5 Classic, etc.
    "NetworkService",
    "LocalService",
    "systemprofile",
    "MSSQL",
    "IIS",
)


def _is_system_user_dir(name: str) -> bool:
    if name in _SYSTEM_USER_DIRS:
        return True
    for pat in _SYSTEM_USER_PATTERNS:
        if name.startswith(pat):
            return True
    return False


def _discover_username(ntfs_mount: str, browsers: Dict[str, Optional[str]]) -> Optional[str]:
    """Derive the primary Windows username from browser paths or Users/ directory."""
    users_root = os.path.join(ntfs_mount, "Users")

    # Prefer browser path — already identifies the most-active user
    for key in ("chrome_history", "firefox_places"):
        path = browsers.get(key)
        if path:
            try:
                rel = os.path.relpath(path, users_root)
                parts = rel.split(os.sep)
                if parts and parts[0] and parts[0] != "..":
                    return parts[0]
            except ValueError:
                pass

    # Fallback: list Users/ and skip system/service accounts
    try:
        candidates = [
            d for d in os.listdir(users_root)
            if os.path.isdir(os.path.join(users_root, d)) and not _is_system_user_dir(d)
        ]
        if candidates:
            if len(candidates) > 1:
                log.warning(
                    "Multiple user directories found: %s — picking %s. "
                    "Override appdata_dir in config.json if wrong.",
                    candidates, candidates[0],
                )
            return candidates[0]
    except OSError:
        pass

    log.warning("Could not discover a Windows username under %s.", users_root)
    return None


def _find_amcache(ntfs_mount: str) -> str:
    """Return the Amcache.hve path, probing both case variants (ntfs3 is case-sensitive)."""
    for variant in ("AppCompat", "appcompat"):
        path = os.path.join(ntfs_mount, "Windows", variant, "Programs", "Amcache.hve")
        if os.path.exists(path):
            return path
    # Neither exists yet (image not mounted, or absent) — use the Windows-standard casing
    return os.path.join(ntfs_mount, "Windows", "AppCompat", "Programs", "Amcache.hve")


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------

def build_config(
    ntfs_mount: str,
    mft_out:    str,
    browsers:   Dict[str, Optional[str]],
) -> dict:
    """Generate the collector config dict. Loads tuning defaults from config.example.json."""
    config: dict = {}

    if _CONFIG_TEMPLATE.exists():
        try:
            with open(_CONFIG_TEMPLATE, encoding="utf-8") as f:
                config = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Could not load %s (%s). Using built-in defaults.", _CONFIG_TEMPLATE, exc)

    def _p(*parts: str) -> str:
        return os.path.join(*parts)

    config["mft"] = {
        "input":       os.path.abspath(mft_out),
        "parser":      "builtin",
        "volume_root": ntfs_mount,
    }
    config["registry"] = {
        "hive_dir": _p(ntfs_mount, "Windows", "System32", "config"),
    }
    config["eventlog"] = {
        "evtx_dir": _p(ntfs_mount, "Windows", "System32", "winevt", "Logs"),
    }
    config["execution"] = {
        "prefetch_dir": _p(ntfs_mount, "Windows", "Prefetch"),
        "amcache":      _find_amcache(ntfs_mount),
        "system_hive":  _p(ntfs_mount, "Windows", "System32", "config", "SYSTEM"),
    }
    config["persistence"] = {
        "hive_dir":  _p(ntfs_mount, "Windows", "System32", "config"),
        "tasks_dir": _p(ntfs_mount, "Windows", "System32", "Tasks"),
        "wmi_dir":   _p(ntfs_mount, "Windows", "System32", "wbem", "Repository"),
    }
    config["browser"] = {
        "chrome_history":      browsers.get("chrome_history"),
        "chrome_browser_name": browsers.get("chrome_browser_name", "chrome"),
        "firefox_places":      browsers.get("firefox_places"),
    }

    # Ensure tuning keys are present (template values take precedence)
    config.setdefault("high_signal_event_ids", [
        4624, 4625, 4648, 4672, 4688, 4697, 4698, 4720, 4732,
        5140, 7045, 1102, 104, 1, 3, 11, 13,
    ])
    config.setdefault("always_emit_event_ids", [1102, 104])
    config.setdefault("suspicious_paths", [
        "AppData\\Roaming", "AppData\\Local\\Temp", "\\Temp\\",
        "\\Downloads\\", "ProgramData", "\\Users\\Public\\", "\\$Recycle.Bin\\",
    ])
    config.setdefault("entropy_threshold", 7.2)
    config.setdefault("si_fn_mismatch_threshold_seconds", 2)
    config.setdefault("mft_exclude_paths", [
        "Windows\\WinSxS", "Windows\\assembly", "Windows\\Installer",
        "Windows\\SoftwareDistribution", "Windows\\servicing",
        "Windows\\System32\\DriverStore", "Windows\\System32\\CatRoot",
        "Windows\\System32\\spool",
    ])
    config.setdefault("mft_exclude_extensions", [
        ".cat", ".mum", ".manifest", ".mui",
        ".ico", ".cur", ".ani",
        ".fon", ".ttf", ".otf", ".ttc",
        ".nls", ".etl", ".bin",
    ])
    config.setdefault("mft_write_only_suspicious", False)
    config.setdefault("max_archive_age_days", None)

    # zimmerman_tools: static keys from template, dynamic paths always overwritten
    username = _discover_username(ntfs_mount, browsers)
    appdata_dir = _p(ntfs_mount, "Users", username, "AppData") if username else None
    if username:
        log.info("Discovered Windows username: %s", username)
    zim: dict = config.get("zimmerman_tools", {})
    zim.setdefault("base_dir", "/opt/zimmermantools")
    zim.setdefault("regedit_batch",
                   "/opt/zimmermantools/RECmd/BatchExamples/DFIRBatch.reb")
    zim.setdefault("user_hive_filename", "NTUSER.DAT")
    zim["ntuser_search_dirs"] = [_p(ntfs_mount, "Users")]
    zim["appdata_dir"] = appdata_dir
    config["zimmerman_tools"] = zim

    return config


# ---------------------------------------------------------------------------
# Mount state persistence (for --umount)
# ---------------------------------------------------------------------------

def _save_state(state: MountState) -> None:
    data = {
        "ntfs_mount": state.ntfs_mount,
        "part_loop":  state.part_loop,
        "ewf_path":   state.ewf_path,
        "disk_loop":  state.disk_loop,
        "nbd_device": state.nbd_device,
    }
    try:
        with open(DEFAULT_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        log.info("Mount state saved → %s", DEFAULT_STATE_FILE)
    except OSError as exc:
        log.warning("Could not save mount state: %s", exc)


def _load_state() -> MountState:
    if not os.path.exists(DEFAULT_STATE_FILE):
        log.error(
            "No mount state file at %s — nothing to unmount.\n"
            "  (If you mounted manually, unmount with: umount %s && fusermount -u %s)",
            DEFAULT_STATE_FILE, DEFAULT_NTFS_MOUNT, DEFAULT_EWF_MOUNT,
        )
        sys.exit(1)
    with open(DEFAULT_STATE_FILE, encoding="utf-8") as f:
        data = json.load(f)
    return MountState(
        ntfs_mount=data.get("ntfs_mount"),
        part_loop =data.get("part_loop"),
        ewf_path  =data.get("ewf_path"),
        disk_loop =data.get("disk_loop"),
        nbd_device=data.get("nbd_device"),
    )


# ---------------------------------------------------------------------------
# Cleanup  (reverse-order, each step independent)
# ---------------------------------------------------------------------------

def cleanup(state: MountState, tools: Dict[str, str]) -> None:
    """Unmount all resources tracked in state. Each step is wrapped independently."""

    def _try(cmd: List[str], label: str) -> None:
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=15)
            if r.returncode == 0:
                log.info("Cleaned up: %s", label)
            else:
                log.warning("Cleanup '%s' returned %d", label, r.returncode)
        except Exception as exc:  # noqa: BLE001
            log.warning("Cleanup '%s' raised: %s", label, exc)

    u  = tools.get("umount",    "umount")
    fm = tools.get("fusermount","fusermount")
    lo = tools.get("losetup",   "losetup")
    qn = tools.get("qemu-nbd",  "qemu-nbd")

    if state.ntfs_mount:
        _try([u, "-l", state.ntfs_mount], f"umount {state.ntfs_mount}")

    if state.part_loop:
        _try([lo, "-d", state.part_loop], f"losetup -d {state.part_loop}")

    if state.ewf_path:
        _try([fm, "-u", state.ewf_path], f"fusermount -u {state.ewf_path}")

    if state.disk_loop:
        _try([lo, "-d", state.disk_loop], f"losetup -d {state.disk_loop}")

    if state.nbd_device:
        _try([qn, "--disconnect", state.nbd_device],
             f"qemu-nbd --disconnect {state.nbd_device}")

    try:
        if os.path.exists(DEFAULT_STATE_FILE):
            os.unlink(DEFAULT_STATE_FILE)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------

def _signal_handler(sig: int, _frame) -> None:
    log.warning("Signal %d received — cleaning up ...", sig)
    cleanup(_STATE, _TOOLS)
    sys.exit(1)


signal.signal(signal.SIGTERM, _signal_handler)
signal.signal(signal.SIGINT,  _signal_handler)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(
    image_path:   Path,
    partitions:   List[PartitionInfo],
    windows_part: PartitionInfo,
    mft_out:      str,
    ntfs_mount:   str,
    config_out:   str,
    browsers:     Dict[str, Optional[str]],
) -> None:
    sep = "-" * 68
    log.info(sep)
    log.info("MOUNT COMPLETE")
    log.info(sep)
    log.info("Image         : %s", image_path)
    log.info("Partitions    :")
    for p in partitions:
        sel = "  ← selected (C:)" if p.start_sector == windows_part.start_sector else ""
        log.info(
            "  sector=%-10d  %5.1f GB  %-10s  %s%s",
            p.start_sector, p.size_gb, p.fstype, p.description, sel,
        )
    log.info("$MFT          : %s (%.1f MB)",
             mft_out, os.path.getsize(mft_out) / 1024 / 1024)
    log.info("NTFS mount    : %s", ntfs_mount)
    log.info("Chrome/Edge   : %s", browsers.get("chrome_history") or "(not found)")
    log.info("Firefox       : %s", browsers.get("firefox_places") or "(not found)")
    log.info("Config        : %s", config_out)
    log.info(sep)
    log.info("Next step:")
    log.info("  python disk-collector/disk_collector.py --config %s --out-dir Disk_Artifacts/",
             config_out)
    log.info("When finished:")
    log.info("  sudo python disk-image-mounter/mount_image.py --umount")
    log.info(sep)


# ---------------------------------------------------------------------------
# --umount mode
# ---------------------------------------------------------------------------

def do_umount() -> None:
    state = _load_state()
    tools: Dict[str, str] = {}
    for name in ("umount", "fusermount", "losetup", "qemu-nbd"):
        path = shutil.which(name)
        if path:
            tools[name] = path
    cleanup(state, tools)
    log.info("Unmount complete.")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mount a forensic disk image and generate config.json for disk-collector.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--image-dir",  default=DEFAULT_IMAGE_DIR,
                        help="Directory containing the disk image")
    parser.add_argument("--out-config", default=DEFAULT_CONFIG_OUT,
                        help="Output path for generated config.json")
    parser.add_argument("--ntfs-mount", default=DEFAULT_NTFS_MOUNT,
                        help="Mount point for the NTFS Windows partition")
    parser.add_argument("--ewf-mount",  default=DEFAULT_EWF_MOUNT,
                        help="Mount point for EWF (e01) images")
    parser.add_argument("--mft-out",    default=DEFAULT_MFT_OUT,
                        help="Output path for extracted raw $MFT")
    parser.add_argument("--umount", action="store_true",
                        help="Unmount a previously mounted image")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    check_root()

    if args.umount:
        do_umount()
        return

    # ---- Step 1: locate image ----
    image_path = scan_image_dir(args.image_dir)
    fmt = image_format(image_path)
    log.info("Image: %s  (format: %s)", image_path, fmt)

    # ---- Step 2: locate tools ----
    global _TOOLS
    _TOOLS = find_tools(fmt)

    try:
        # ---- Step 3: mount image → raw block ----
        if fmt == "ewf":
            raw_block = mount_ewf(image_path, args.ewf_mount)
        elif fmt == "dd":
            raw_block = mount_dd(image_path)
        else:
            raw_block = mount_vmdk(image_path)

        # ---- Step 4: partition analysis ----
        log.info("Analyzing partition table ...")
        partitions = detect_partitions(raw_block)

        # ---- Step 5: OS gate ----
        os_type = determine_os(partitions)
        log.info("Detected OS type: %s", os_type)

        if os_type == "linux":
            log.info(
                "Linux disk image detected.\n"
                "  This pipeline only supports Windows (NTFS) images.\n"
                "  Cleaning up and exiting."
            )
            cleanup(_STATE, _TOOLS)
            sys.exit(0)

        if os_type == "unknown":
            bitlocker_count = sum(1 for p in partitions if p.bitlocker)
            if bitlocker_count:
                _die(
                    f"{bitlocker_count} BitLocker-encrypted partition(s) found and no other "
                    "readable filesystem detected.\n"
                    "  Decrypt first with dislocker, then re-run this script."
                )
            fstypes = ", ".join(sorted({p.fstype for p in partitions}))
            _die(
                f"Cannot determine OS type from partition filesystem types: {fstypes}.\n"
                "  This image may be corrupt, encrypted, or an unsupported format."
            )

        # ---- Step 6: select Windows partition ----
        windows_part = select_windows_partition(partitions)
        log.info(
            "Selected Windows partition: sector=%d  size=%.1f GB  fstype=%s",
            windows_part.start_sector, windows_part.size_gb, windows_part.fstype,
        )

        # ---- Step 7: extract $MFT ----
        extract_mft(raw_block, windows_part, args.mft_out)

        # ---- Step 8: mount NTFS ----
        mount_ntfs(raw_block, windows_part, fmt, args.ntfs_mount)

        # ---- Step 9: browser discovery ----
        browsers = discover_browsers(args.ntfs_mount)

        # ---- Step 10: write config.json ----
        config = build_config(args.ntfs_mount, args.mft_out, browsers)
        config_out = os.path.abspath(args.out_config)
        os.makedirs(os.path.dirname(config_out) or ".", exist_ok=True)
        with open(config_out, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        log.info("config.json written → %s", config_out)

        # ---- Step 11: persist mount state for --umount ----
        _save_state(_STATE)

        # ---- Step 12: human-readable summary ----
        print_summary(
            image_path, partitions, windows_part,
            args.mft_out, args.ntfs_mount, config_out, browsers,
        )

    except Exception as exc:  # noqa: BLE001
        log.error("Unexpected error: %s", exc, exc_info=args.verbose)
        cleanup(_STATE, _TOOLS)
        sys.exit(1)


if __name__ == "__main__":
    main()
