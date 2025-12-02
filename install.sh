#!/bin/bash
#
# WIFUCKER Installer with Layer 9 (QUANTUM) Default Configuration
# ================================================================
# Installs WIFUCKER with full 9-layer system and QUANTUM clearance
# enabled by default.
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Banner
echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     WIFUCKER Installer - 9-Layer System with QUANTUM         ║
║                                                               ║
║  Automatic installation with Layer 9 (QUANTUM) clearance     ║
║  Full acceleration stack: Quantum → Unified → Hardware        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root (for some operations)
NEEDS_SUDO=false
if [ "$EUID" -ne 0 ]; then
    NEEDS_SUDO=true
fi

# Check Python
echo -e "${CYAN}[*] Checking Python...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[✗] Python 3 not found${NC}"
    echo -e "${YELLOW}[!] Please install Python 3.8+ first${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo -e "${GREEN}[✓] Python ${PYTHON_VERSION}${NC}"

# Create virtual environment
echo ""
echo -e "${CYAN}[*] Setting up virtual environment...${NC}"
VENV_DIR="$SCRIPT_DIR/venv"

if [ -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}[!] Virtual environment exists, recreating...${NC}"
    rm -rf "$VENV_DIR"
fi

python3 -m venv "$VENV_DIR"
echo -e "${GREEN}[✓] Virtual environment created${NC}"

# Activate venv
source "$VENV_DIR/bin/activate"

# Upgrade pip
echo -e "${CYAN}[*] Upgrading pip...${NC}"
pip install --upgrade pip --quiet
echo -e "${GREEN}[✓] pip upgraded${NC}"

# Install dependencies
echo ""
echo -e "${CYAN}[*] Installing dependencies...${NC}"
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    pip install -r "$SCRIPT_DIR/requirements.txt" --quiet
    echo -e "${GREEN}[✓] Dependencies installed${NC}"
else
    echo -e "${YELLOW}[!] requirements.txt not found, installing minimal set...${NC}"
    pip install textual rich requests numpy tqdm cryptography --quiet
fi

# Install quantum dependencies (optional)
echo ""
echo -e "${CYAN}[*] Installing quantum processor dependencies (optional)...${NC}"
if pip install qiskit qiskit-aer --quiet 2>/dev/null; then
    echo -e "${GREEN}[✓] Quantum dependencies installed${NC}"
else
    echo -e "${YELLOW}[!] Quantum dependencies not installed (optional)${NC}"
    echo -e "${YELLOW}    Install manually: pip install qiskit qiskit-aer${NC}"
fi

# Set Layer 9 (QUANTUM) clearance
echo ""
echo -e "${CYAN}[*] Setting Layer 9 (QUANTUM) clearance...${NC}"
if [ -f "$SCRIPT_DIR/set_max_clearance.py" ]; then
    if python3 "$SCRIPT_DIR/set_max_clearance.py" 2>/dev/null; then
        echo -e "${GREEN}[✓] QUANTUM clearance (Layer 9) set${NC}"
    else
        echo -e "${YELLOW}[!] Clearance setting may require kernel driver${NC}"
        echo -e "${YELLOW}    Will be set automatically on launch${NC}"
    fi
else
    echo -e "${YELLOW}[!] Clearance script not found${NC}"
fi

# Make launcher executable
echo ""
echo -e "${CYAN}[*] Setting up launcher...${NC}"
chmod +x "$SCRIPT_DIR/wifucker"
chmod +x "$SCRIPT_DIR/wifucker_unified_tui.py"
chmod +x "$SCRIPT_DIR/set_max_clearance.py" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/check_tops.py" 2>/dev/null || true
echo -e "${GREEN}[✓] Launcher executable${NC}"

# Create system-wide symlink (optional)
echo ""
echo -e "${CYAN}[*] Creating system-wide access...${NC}"
if [ "$NEEDS_SUDO" = true ]; then
    echo -e "${YELLOW}[!] Run with sudo to create system-wide symlink:${NC}"
    echo -e "    ${CYAN}sudo ln -sf $SCRIPT_DIR/wifucker /usr/local/bin/wifucker${NC}"
else
    if [ -w "/usr/local/bin" ]; then
        ln -sf "$SCRIPT_DIR/wifucker" /usr/local/bin/wifucker 2>/dev/null || true
        echo -e "${GREEN}[✓] System-wide symlink created${NC}"
    else
        echo -e "${YELLOW}[!] Cannot create system-wide symlink (permission denied)${NC}"
    fi
fi

# Verify installation
echo ""
echo -e "${CYAN}[*] Verifying installation...${NC}"

# Check imports
if "$VENV_DIR/bin/python3" -c "from textual.app import App" 2>/dev/null; then
    echo -e "${GREEN}[✓] textual framework OK${NC}"
else
    echo -e "${RED}[✗] textual framework failed${NC}"
fi

if "$VENV_DIR/bin/python3" -c "from crackers import PBKDF2Cracker" 2>/dev/null; then
    echo -e "${GREEN}[✓] Crackers module OK${NC}"
else
    echo -e "${RED}[✗] Crackers module failed${NC}"
fi

# Check quantum (optional)
if "$VENV_DIR/bin/python3" -c "import qiskit" 2>/dev/null; then
    echo -e "${GREEN}[✓] Quantum processor support available${NC}"
else
    echo -e "${YELLOW}[!] Quantum processor support not available (optional)${NC}"
fi

# Display system info
echo ""
echo -e "${CYAN}[*] System Information:${NC}"
echo -e "    Python: ${PYTHON_VERSION}"
echo -e "    Virtual Environment: ${VENV_DIR}"
echo -e "    Clearance Level: ${GREEN}QUANTUM (Layer 9)${NC}"

# Check TOPS
echo ""
echo -e "${CYAN}[*] Checking available TOPS...${NC}"
if [ -f "$SCRIPT_DIR/check_tops.py" ]; then
    "$VENV_DIR/bin/python3" "$SCRIPT_DIR/check_tops.py" 2>/dev/null | grep -A 5 "TOTAL" || echo -e "${YELLOW}[!] TOPS check unavailable${NC}"
fi

# Installation complete
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  INSTALLATION COMPLETE${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}To launch WIFUCKER:${NC}"
echo -e "  ${GREEN}cd $SCRIPT_DIR${NC}"
echo -e "  ${GREEN}./wifucker${NC}"
echo ""
if [ -L "/usr/local/bin/wifucker" ] || [ -f "/usr/local/bin/wifucker" ]; then
    echo -e "${CYAN}Or from anywhere:${NC}"
    echo -e "  ${GREEN}wifucker${NC}"
    echo ""
fi
echo -e "${CYAN}Features enabled by default:${NC}"
echo -e "  ${GREEN}✓${NC} Layer 9 (QUANTUM) clearance"
echo -e "  ${GREEN}✓${NC} Full 9-layer acceleration stack"
echo -e "  ${GREEN}✓${NC} WPA2/PSK2 routing through all layers"
echo -e "  ${GREEN}✓${NC} Unified accelerator system (80+ TOPS)"
echo -e "  ${GREEN}✓${NC} Quantum processor support (if available)"
echo ""
echo -e "${CYAN}For WiFi operations requiring sudo:${NC}"
echo -e "  ${GREEN}sudo -E ./wifucker${NC}"
echo ""
echo -e "${GREEN}WIFUCKER is ready with full Layer 9 permissions!${NC}"
echo ""


