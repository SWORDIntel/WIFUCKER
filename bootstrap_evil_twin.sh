#!/bin/bash
#
# WIFUCKER Evil Twin Suite Bootstrap Script
# ========================================
#
# Installs all system dependencies required for the Evil Twin Suite
# Supports: hostapd, dnsmasq, captive portals, advanced WPS attacks
#
# This script will install:
# - Wireless tools and drivers
# - hostapd (Access Point daemon)
# - dnsmasq (DHCP/DNS server)
# - Network monitoring tools
# - Python dependencies for evil twin functionality
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║           WIFUCKER Evil Twin Suite Bootstrap                  ║
║                                                               ║
║  Installing dependencies for advanced evil twin attacks       ║
║  • hostapd (Rogue AP creation)                                ║
║  • dnsmasq (DHCP/DNS server)                                  ║
║  • Wireless monitoring tools                                  ║
║  • Captive portal support                                     ║
║  • Advanced WPS attack tools                                  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[✗] Please run as root (sudo $0)${NC}"
    exit 1
fi

# Detect distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/redhat-release ]; then
        echo "rhel"
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

DISTRO=$(detect_distro)
echo -e "${GREEN}[✓] Detected distribution: ${DISTRO}${NC}"

# Function to install packages
install_packages() {
    local packages="$1"
    echo -e "${CYAN}[*] Installing packages: ${packages}${NC}"

    case "$DISTRO" in
        ubuntu|debian|linuxmint)
            apt update
            apt install -y $packages
            ;;
        fedora|rhel|centos)
            if command -v dnf &> /dev/null; then
                dnf install -y $packages
            else
                yum install -y $packages
            fi
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm $packages
            ;;
        opensuse*)
            zypper install -y $packages
            ;;
        *)
            echo -e "${RED}[✗] Unsupported distribution: ${DISTRO}${NC}"
            echo -e "${YELLOW}[!] Please install manually: ${packages}${NC}"
            exit 1
            ;;
    esac
}

# Core wireless tools
echo -e "${CYAN}[*] Installing core wireless tools...${NC}"
CORE_PACKAGES="wireless-tools iw wpa-supplicant"
install_packages "$CORE_PACKAGES"

# hostapd - Access Point daemon
echo -e "${CYAN}[*] Installing hostapd (rogue AP creation)...${NC}"
HOSTAPD_PACKAGES="hostapd"
install_packages "$HOSTAPD_PACKAGES"

# dnsmasq - DHCP/DNS server
echo -e "${CYAN}[*] Installing dnsmasq (DHCP/DNS server)...${NC}"
DNSMASQ_PACKAGES="dnsmasq"
install_packages "$DNSMASQ_PACKAGES"

# Network monitoring and attack tools
echo -e "${CYAN}[*] Installing network monitoring tools...${NC}"
NETWORK_PACKAGES="tcpdump tshark aircrack-ng reaver bully pixiewps arp-scan"
install_packages "$NETWORK_PACKAGES"

# Python development packages
echo -e "${CYAN}[*] Installing Python development packages...${NC}"
case "$DISTRO" in
    ubuntu|debian|linuxmint)
        PYTHON_PACKAGES="python3-dev python3-pip python3-scapy python3-netifaces python3-psutil"
        ;;
    fedora|rhel|centos)
        PYTHON_PACKAGES="python3-devel python3-pip python3-scapy python3-netifaces python3-psutil"
        ;;
    arch|manjaro)
        PYTHON_PACKAGES="python python-pip scapy netifaces psutil"
        ;;
    opensuse*)
        PYTHON_PACKAGES="python3-devel python3-pip python3-scapy python3-netifaces python3-psutil"
        ;;
    *)
        PYTHON_PACKAGES=""
        ;;
esac

if [ -n "$PYTHON_PACKAGES" ]; then
    install_packages "$PYTHON_PACKAGES"
fi

# Additional tools for advanced attacks
echo -e "${CYAN}[*] Installing advanced attack tools...${NC}"
ADVANCED_PACKAGES="macchanger ettercap-common dsniff"
install_packages "$ADVANCED_PACKAGES"

# Configure hostapd for evil twin use
echo -e "${CYAN}[*] Configuring hostapd for evil twin operations...${NC}"
HOSTAPD_CONF="/etc/hostapd/hostapd.conf"
if [ ! -f "$HOSTAPD_CONF" ]; then
    cat > "$HOSTAPD_CONF" << EOF
# Evil Twin hostapd configuration
# This is a template - WIFUCKER will generate specific configs at runtime
interface=wlan0
driver=nl80211
ssid=EvilTwinTemplate
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=eviltwin123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOF
    echo -e "${GREEN}[✓] Created hostapd template configuration${NC}"
fi

# Configure dnsmasq for captive portal use
echo -e "${CYAN}[*] Configuring dnsmasq for captive portals...${NC}"
DNSMASQ_CONF="/etc/dnsmasq-evil-twin.conf"
cat > "$DNSMASQ_CONF" << EOF
# Evil Twin dnsmasq configuration
# WIFUCKER will use this as a template
interface=wlan0
dhcp-range=192.168.0.100,192.168.0.200,12h
dhcp-option=3,192.168.0.1
dhcp-option=6,8.8.8.8,8.8.4.4
server=8.8.8.8
server=8.8.4.4
log-queries
log-dhcp
EOF
echo -e "${GREEN}[✓] Created dnsmasq template configuration${NC}"

# Stop and disable default dnsmasq (to avoid conflicts)
echo -e "${CYAN}[*] Stopping default dnsmasq service...${NC}"
systemctl stop dnsmasq 2>/dev/null || true
systemctl disable dnsmasq 2>/dev/null || true

# Stop and disable default hostapd
echo -e "${CYAN}[*] Stopping default hostapd service...${NC}"
systemctl stop hostapd 2>/dev/null || true
systemctl disable hostapd 2>/dev/null || true

# Install Python dependencies for evil twin suite
echo -e "${CYAN}[*] Installing Python dependencies for evil twin suite...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

if [ -d "$VENV_DIR" ]; then
    echo -e "${CYAN}[*] Installing evil twin Python dependencies...${NC}"
    "$VENV_DIR/bin/pip" install --upgrade pip

    # Install evil twin specific packages
    "$VENV_DIR/bin/pip" install scapy netifaces psutil flask werkzeug

    echo -e "${GREEN}[✓] Python dependencies installed${NC}"
else
    echo -e "${YELLOW}[!] Virtual environment not found${NC}"
    echo -e "${YELLOW}[!] Run ./wifucker_launcher first to create venv, then re-run this script${NC}"
fi

# Create evil twin working directories
echo -e "${CYAN}[*] Creating evil twin working directories...${NC}"
mkdir -p /tmp/evil_twin_logs
mkdir -p /tmp/evil_twin_captures
chmod 755 /tmp/evil_twin_logs
chmod 755 /tmp/evil_twin_captures
echo -e "${GREEN}[✓] Working directories created${NC}"

# Test installations
echo -e "${CYAN}[*] Testing installations...${NC}"

# Test hostapd
if command -v hostapd &> /dev/null; then
    echo -e "${GREEN}[✓] hostapd installed${NC}"
else
    echo -e "${RED}[✗] hostapd not found${NC}"
fi

# Test dnsmasq
if command -v dnsmasq &> /dev/null; then
    echo -e "${GREEN}[✓] dnsmasq installed${NC}"
else
    echo -e "${RED}[✗] dnsmasq not found${NC}"
fi

# Test aircrack-ng
if command -v aircrack-ng &> /dev/null; then
    echo -e "${GREEN}[✓] aircrack-ng installed${NC}"
else
    echo -e "${RED}[✗] aircrack-ng not found${NC}"
fi

# Test reaver
if command -v reaver &> /dev/null; then
    echo -e "${GREEN}[✓] reaver installed${NC}"
else
    echo -e "${RED}[✗] reaver not found${NC}"
fi

# Test Python modules
if [ -d "$VENV_DIR" ]; then
    if "$VENV_DIR/bin/python3" -c "import scapy, netifaces, psutil, flask" 2>/dev/null; then
        echo -e "${GREEN}[✓] Python modules installed${NC}"
    else
        echo -e "${RED}[✗] Python modules missing${NC}"
    fi
fi

# Network interface check
echo -e "${CYAN}[*] Checking wireless interfaces...${NC}"
iwconfig 2>/dev/null | grep -E "^[a-zA-Z0-9]+" | while read -r line; do
    interface=$(echo "$line" | awk '{print $1}')
    echo -e "${GREEN}[✓] Found wireless interface: ${interface}${NC}"
done

# Final instructions
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    BOOTSTRAP COMPLETE                        ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Evil Twin Suite Dependencies Installed!${NC}"
echo ""
echo -e "${GREEN}What's now available:${NC}"
echo -e "  ${GREEN}✓${NC} hostapd - Rogue access point creation"
echo -e "  ${GREEN}✓${NC} dnsmasq - DHCP/DNS server for captive portals"
echo -e "  ${GREEN}✓${NC} aircrack-ng - Wireless monitoring and attack tools"
echo -e "  ${GREEN}✓${NC} reaver/bully - WPS attack tools"
echo -e "  ${GREEN}✓${NC} pixiewps - Offline WPS PIN computation"
echo -e "  ${GREEN}✓${NC} Python evil twin libraries (scapy, flask, etc.)"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo -e "  1. ${CYAN}Run: ./wifucker_launcher${NC}"
echo -e "  2. ${CYAN}Navigate to 'Evil Twin Suite' tab${NC}"
echo -e "  3. ${CYAN}Select interface and target network${NC}"
echo -e "  4. ${CYAN}Launch evil twin attack${NC}"
echo ""
echo -e "${RED}⚠️  LEGAL WARNING:${NC}"
echo -e "     Use only for authorized security testing!"
echo -e "     Evil twin attacks can be illegal without permission."
echo ""

echo -e "${GREEN}Happy hunting! 🦹‍♂️${NC}"
