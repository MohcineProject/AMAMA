#!/usr/bin/env bash
# install.sh — One-command setup for the Disk DFIR module.
#
# Usage:
#   sudo bash install.sh [--no-dotnet] [--no-zimmerman]
#
# Flags:
#   --no-dotnet      Skip .NET 9.0 installation (Python fallbacks will be used
#                    for registry, event log, and execution collectors)
#   --no-zimmerman   Skip Zimmerman tools download (implies --no-dotnet effect
#                    on Zimmerman-dependent collectors)
#
# What this script does:
#   1. Install APT system packages (ewf-tools, sleuthkit, ntfs-3g, etc.)
#   2. Create a Python virtual environment at ./venv and install pip packages
#   3. Optionally install .NET 9.0 SDK from Microsoft APT repository
#   4. Optionally download Zimmerman forensic tools to /opt/zimmermantools/
#   5. Run --check-deps to print a final status summary
#
# Idempotent: safe to re-run. Existing installations are detected and skipped.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
ZIMM_DIR="/opt/zimmermantools"
ZIMM_DLL_CHECK="$ZIMM_DIR/RECmd/RECmd.dll"
# Individual net9 zips — the old All_6.0.zip bundle no longer exists on Backblaze.
ZIMM_BASE_URL="https://download.ericzimmermanstools.com/net9"
ZIMM_TOOLS=("AppCompatCacheParser" "AmcacheParser" "RECmd" "EvtxECmd")

INSTALL_DOTNET=true
INSTALL_ZIMMERMAN=true

# ── Argument parsing ─────────────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --no-dotnet)      INSTALL_DOTNET=false; INSTALL_ZIMMERMAN=false ;;
        --no-zimmerman)   INSTALL_ZIMMERMAN=false ;;
        -h|--help)
            echo "Usage: sudo bash install.sh [--no-dotnet] [--no-zimmerman]"
            exit 0 ;;
        *)
            echo "Unknown argument: $arg"
            exit 1 ;;
    esac
done

# ── Root check ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (sudo bash install.sh)"
    exit 1
fi

echo "========================================================"
echo " Disk DFIR Module — Dependency Installer"
echo "========================================================"
echo ""

# ── Step 1: APT packages ─────────────────────────────────────────────────────
# Target: SIFT Workstation (Ubuntu 24.04). Most forensic tools are pre-installed.
# This step ensures any gaps are filled.
echo "[1/5] Installing system packages via apt-get..."
apt-get update -qq

# SIFT uses libewf-tools (from its PPA); standard Ubuntu 24.04 has ewf-tools
EWF_PKG="libewf-tools"
apt-cache show libewf-tools &>/dev/null || EWF_PKG="ewf-tools"

apt-get install -y \
    "$EWF_PKG" \
    sleuthkit \
    fuse3 \
    ntfs-3g \
    qemu-utils \
    parted \
    unzip \
    wget \
    python3 \
    python3-venv \
    python3-pip 2>&1 | grep -v "already the newest"
echo "      System packages: OK"
echo ""

# ── Step 2: Python virtual environment ───────────────────────────────────────
echo "[2/5] Setting up Python virtual environment at $VENV_DIR ..."
if [[ ! -f "$VENV_DIR/bin/python" ]]; then
    python3 -m venv "$VENV_DIR"
    echo "      Created venv."
else
    echo "      Venv already exists — skipping creation."
fi

echo "      Installing pip packages from requirements.txt ..."
"$VENV_DIR/bin/pip" install --upgrade pip --quiet
"$VENV_DIR/bin/pip" install -r "$SCRIPT_DIR/requirements.txt" --quiet
echo "      Python packages: OK"
echo ""

# ── Step 3: .NET 9.0 (optional) ──────────────────────────────────────────────
if [[ "$INSTALL_DOTNET" == "true" ]]; then
    echo "[3/5] Installing .NET 9.0 SDK ..."
    if command -v dotnet &>/dev/null && dotnet --version &>/dev/null; then
        echo "      dotnet $(dotnet --version) already installed — skipping."
    else
        # Detect Ubuntu version
        UBUNTU_VERSION=$(lsb_release -rs 2>/dev/null || echo "24.04")
        MICROSOFT_PKG="packages-microsoft-prod.deb"
        MICROSOFT_URL="https://packages.microsoft.com/config/ubuntu/${UBUNTU_VERSION}/${MICROSOFT_PKG}"

        echo "      Adding Microsoft APT repository for Ubuntu ${UBUNTU_VERSION} ..."
        TMP_DEB="$(mktemp /tmp/microsoft-XXXXXX.deb)"
        if wget -q "$MICROSOFT_URL" -O "$TMP_DEB"; then
            dpkg -i "$TMP_DEB" 2>/dev/null || true
            rm -f "$TMP_DEB"
            apt-get update -qq
            apt-get install -y dotnet-sdk-9.0
            echo "      .NET $(dotnet --version): OK"
        else
            echo "      WARNING: Could not download Microsoft repo package from:"
            echo "        $MICROSOFT_URL"
            echo "      Manual install: https://learn.microsoft.com/dotnet/core/install/linux-ubuntu"
            echo "      Continuing without .NET — Python fallbacks will be used."
            INSTALL_DOTNET=false
            INSTALL_ZIMMERMAN=false
        fi
    fi
else
    echo "[3/5] Skipping .NET installation (--no-dotnet)"
    echo "      WARNING: Python fallbacks will be used for registry, event log,"
    echo "      and execution collectors. Shimcache coverage limited to Win10/11."
fi
echo ""

# ── Step 4: Zimmerman tools (optional) ───────────────────────────────────────
if [[ "$INSTALL_ZIMMERMAN" == "true" ]]; then
    echo "[4/5] Installing Eric Zimmerman forensic tools to $ZIMM_DIR ..."
    if [[ -f "$ZIMM_DLL_CHECK" ]]; then
        echo "      Zimmerman tools already installed — skipping download."
    else
        if ! command -v dotnet &>/dev/null; then
            echo "      WARNING: dotnet not available — skipping Zimmerman tools."
        else
            mkdir -p "$ZIMM_DIR"
            DOWNLOAD_FAILED=()
            echo "      Downloading individual tools from $ZIMM_BASE_URL ..."
            for tool in "${ZIMM_TOOLS[@]}"; do
                TMP_ZIP="$(mktemp /tmp/zimmerman-XXXXXX.zip)"
                if wget -q "${ZIMM_BASE_URL}/${tool}.zip" -O "$TMP_ZIP"; then
                    unzip -q -o "$TMP_ZIP" -d "$ZIMM_DIR"
                    echo "        $tool: OK"
                else
                    echo "        $tool: FAILED"
                    DOWNLOAD_FAILED+=("$tool")
                fi
                rm -f "$TMP_ZIP"
            done

            # Verify key DLLs
            MISSING=()
            for dll in \
                "RECmd/RECmd.dll" \
                "EvtxeCmd/EvtxECmd.dll" \
                "AppCompatCacheParser.dll" \
                "AmcacheParser.dll"; do
                [[ -f "$ZIMM_DIR/$dll" ]] || MISSING+=("$dll")
            done

            if [[ ${#MISSING[@]} -eq 0 ]]; then
                echo "      Zimmerman tools: OK"
            else
                echo "      WARNING: Some Zimmerman DLLs missing after install:"
                for m in "${MISSING[@]}"; do echo "        $ZIMM_DIR/$m"; done
                echo "      Manual install: https://ericzimmerman.github.io/#!index.md"
                echo "      Python fallbacks will be used for those collectors."
            fi
        fi
    fi
else
    echo "[4/5] Skipping Zimmerman tools (--no-zimmerman)"
fi
echo ""

# ── Step 5: Dependency check ─────────────────────────────────────────────────
echo "[5/5] Running dependency check ..."
echo ""
if [[ -f "$VENV_DIR/bin/python" ]]; then
    "$VENV_DIR/bin/python" "$SCRIPT_DIR/disk-collector/disk_collector.py" \
        --config "$SCRIPT_DIR/disk-collector/config.example.json" \
        --check-deps 2>/dev/null \
    || echo "      (dependency check requires disk-collector/config.example.json)"
else
    echo "      Venv not found — skipping dependency check."
fi

echo ""
echo "========================================================"
echo " Setup complete."
echo ""
echo " To run the disk collector:"
echo "   sudo $VENV_DIR/bin/python disk-collector/disk_collector.py \\"
echo "        --config config.json --fast --out-dir Disk_Artifacts/"
echo ""
echo " To run the full pipeline:"
echo "   cd disk-agentic-architecture"
echo "   ../.venv/bin/python scripts/run_pipeline.py"
echo "========================================================"
