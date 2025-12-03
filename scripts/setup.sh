#!/bin/bash

# WIFUCKER Auto-Bootstrapping Installer
# Sets up the environment for the WIFUCKER WiFi Security Suite

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}==== WIFUCKER INSTALLER ====${NC}"

# 1. Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed.${NC}"
    exit 1
fi

# 2. Create Virtual Environment
echo -e "${BLUE}[*] Creating virtual environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}[+] Virtual environment created.${NC}"
else
    echo -e "${YELLOW}[!] Virtual environment already exists.${NC}"
fi

# 3. Activate Virtual Environment
echo -e "${BLUE}[*] Activating virtual environment...${NC}"
source venv/bin/activate

# 4. Install Dependencies
echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    echo -e "${GREEN}[+] Dependencies installed.${NC}"
else
    echo -e "${RED}Error: requirements.txt not found.${NC}"
    exit 1
fi

# 5. Check System Dependencies
echo -e "${BLUE}[*] Checking system dependencies...${NC}"
MISSING_DEPS=0
check_dep() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}[-] Missing: $1${NC}"
        MISSING_DEPS=1
    else
        echo -e "${GREEN}[+] Found: $1${NC}"
    fi
}

check_dep "aircrack-ng"
check_dep "iw"
check_dep "ethtool"
check_dep "make"
check_dep "gcc"

if [ $MISSING_DEPS -eq 1 ]; then
    echo -e "${YELLOW}[!] Some system dependencies are missing.${NC}"
    echo -e "    Ubuntu/Debian: sudo apt install aircrack-ng iw ethtool build-essential"

    if command -v sudo &> /dev/null; then
        read -p "$(echo -e "${YELLOW}Do you want to install missing dependencies now? (y/N): ${NC}")" -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}[*] Attempting to install missing dependencies...${NC}"
            sudo apt-get update && sudo apt-get install -y aircrack-ng iw ethtool build-essential
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}[+] Missing dependencies installed successfully.${NC}"
                # Re-check dependencies after installation
                MISSING_DEPS=0
                echo -e "${BLUE}[*] Re-checking system dependencies...${NC}"
                check_dep "aircrack-ng"
                check_dep "iw"
                check_dep "ethtool"
                check_dep "make"
                check_dep "gcc"
            else
                echo -e "${RED}[-] Failed to install missing dependencies.${NC}"
            fi
        else
            echo -e "${YELLOW}[!] Skipping automatic installation of dependencies.${NC}"
        fi
    else
        echo -e "${RED}Error: sudo command not found. Please install dependencies manually.${NC}"
    fi
    if [ $MISSING_DEPS -eq 1 ]; then
        echo -e "${RED}Error: Required system dependencies are still missing. Exiting.${NC}"
        exit 1
    fi
fi

# 6. Compiling helper modules (optional)
echo -e "${BLUE}[*] Checking for C extensions...${NC}"
if [ -f "crackers/Makefile" ]; then
    echo -e "${BLUE}[*] Compiling optimized cracker module (AVX-512/AVX2/AVX/Generic fallback)...${NC}"
    if make -C crackers; then
         echo -e "${GREEN}[+] Compilation successful.${NC}"
    else
         echo -e "${YELLOW}[!] Compilation failed. Hardware acceleration might be limited.${NC}"
    fi
fi

# 7. Setup Complete
echo -e "${GREEN}==== SETUP COMPLETE ====${NC}"
echo -e "To launch the application:"
echo -e "  ${YELLOW}source venv/bin/activate${NC}"
echo -e "  ${YELLOW}sudo -E python3 launcher.py${NC}  (Note: -E preserves env vars for venv)"
echo -e ""
