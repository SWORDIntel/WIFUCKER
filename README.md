# WIFUCKER - Advanced WiFi Security Testing Platform

A comprehensive toolkit for WiFi security assessment featuring WPS attacks, Evil Twin suites, hardware-accelerated cracking, and intelligent automation for UK and international routers.

## Features

### Core WiFi Security Testing
- **Network Scanning**: Discover and analyze WiFi networks with SSID intelligence
- **Handshake Capture**: Automated WPA/WPA2 handshake capture with deauthentication
- **Hardware Acceleration**: Intel NPU, GPU, AVX-512, AMX, and OpenVINO support
- **Intelligent Cracking**: PBKDF2, WPA2, WPA3, and custom algorithm support
- **Smart Wordlists**: AI-powered password generation with location/temporal patterns

### WPS Attack Suite
- **UK Router WPS Database**: Comprehensive database of Virgin Media, BT, EE, Sky, and TalkTalk routers
- **Compute PIN**: MAC address-based PIN generation algorithms
- **Pixie Dust Attacks**: Offline WPS vulnerability exploitation
- **Brute Force PIN**: Full 8-digit WPS PIN enumeration
- **Advanced WPS Methods**:
  - Small DH Key attacks for vulnerable routers
  - WPS Registrar PIN disclosure
  - EAP message injection attacks
- **PIN Validation**: Built-in WPS checksum validation

### IoT Device WPS Attacks
- **HP Printer Support**: Specialized attacks for HP Envy, OfficeJet, LaserJet printers
- **IoT Device Discovery**: Automated scanning for vulnerable IoT devices
- **Default PIN Exploitation**: Factory default WPS PIN attacks
- **MAC-Based PIN Generation**: Hardware address derived PIN calculation
- **Network Pivot**: Use compromised IoT devices as relays to router networks
- **Internet Relay**: Pivot through IoT devices to access internet via compromised networks
- **Device Types Supported**:
  - HP Printers (Envy, OfficeJet, LaserJet series)
  - Smart TVs (Samsung, LG, Android TV)
  - Streaming Devices (Roku, Fire TV, Chromecast)
  - Security Cameras (Nest, generic IP cameras)
  - Smart Speakers (Echo, Google Home, Sonos)

### Evil Twin Attack Suite
- **UK ISP Templates**: Pre-configured captive portals for major UK providers
- **Rogue AP Creation**: Automated setup of malicious access points
- **Captive Portal Server**: Flask-based credential harvesting
- **Network Spoofing**: Seamless SSID cloning and broadcasting
- **Credential Capture**: Secure storage and analysis of harvested credentials

### Router Password Cracking
- **EE WiFi Smart Hub Mode**: Dedicated cracking for EE/BT Smart Hub networks (12-14 digits)
- **Hexadecimal Brute Force**: 10-digit hex patterns for technical devices (a-f, 0-9)
- **Smart Router Detection**: Auto-detect router type from SSID patterns
- **Pattern Storm**: Multi-pattern combination attacks for comprehensive coverage
- **UK Provider Support**: Specialized patterns for Virgin Media, BT, EE, Sky, TalkTalk

### Enhanced User Interface
- **Unified TUI**: Text-based user interface with tabbed navigation
- **Router Cracking Tab**: Guided workflows for router password attacks
- **UK Router WPS Tab**: Specialized WPS attack interface
- **IoT WPS Attacks Tab**: IoT device WPS exploitation and network pivoting
- **Advanced WPS Attacks Tab**: Protocol-level WPS exploitation
- **Evil Twin Suite Tab**: Complete rogue AP management
- **Live Monitoring**: Real-time attack progress and statistics

## Quick Start

```bash
# Make the launcher executable
chmod +x wifucker_launcher

# Run the unified TUI
./wifucker_launcher

# Or run directly with Python
python3 -m wifucker_pkg
```

## Project Structure

```
wifucker/
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── bootstrap_evil_twin.sh       # Evil Twin dependencies bootstrap
├── wifucker_launcher            # Main launcher script
├── wifucker                     # CLI executable
├── captures/                    # Sample handshake capture files
├── tests/                       # Test suites and demonstrations
│   ├── run_all_tests.py         # Test runner script
│   ├── test_uk_wps.py           # UK WPS attack tests
│   ├── test_advanced_wps.py     # Advanced WPS method tests
│   ├── test_evil_twin.py        # Evil Twin suite tests
│   ├── demo_router_cracking.py  # Router cracking demonstration
│   ├── test_import.sh           # Import validation script
│   └── README.md                # Testing documentation
├── venv/                        # Virtual environment (auto-created)
└── wifucker_pkg/                # Main package
    ├── __init__.py             # Package initialization
    ├── __main__.py             # CLI entry point
    ├── wifucker_unified_tui.py # Unified text-based interface
    ├── ai_models/              # AI-powered wordlist generation
    ├── capture/                # Network scanning and capture tools
    ├── crackers/               # Password cracking engines
    │   ├── uk_router_wps.py    # UK router WPS attacks
    │   ├── advanced_wps_attacks.py # Protocol-level WPS exploits
    │   ├── evil_twin_suite.py  # Evil Twin attack suite
    │   ├── router_cracker.py   # Router password cracking
    │   └── ...                 # Other cracking engines
    ├── parsers/                # PCAP and data parsers
    ├── scripts/                # CLI tools and utilities
    └── utils/                  # Helper utilities
```

## Requirements

### System Requirements
- **Python**: 3.8+ with pip
- **Wireless Interface**: Network card supporting monitor mode and packet injection
- **Root/Sudo Privileges**: Required for network operations and system tools
- **RAM**: Minimum 4GB, recommended 8GB+ for WPS attacks
- **Storage**: 2GB+ free space for wordlists and virtual environment

### System Dependencies
- **Core WiFi Tools**: `aircrack-ng`, `iw`, `wireless-tools`
- **Evil Twin Suite**: `hostapd`, `dnsmasq`, `iptables`
- **Build Tools**: `build-essential`, `python3-dev` (for C extensions)

## Installation

### Automated Bootstrap (Recommended)
```bash
# Make launcher executable
chmod +x wifucker_launcher

# Run bootstrap (installs all dependencies automatically)
./wifucker_launcher
```

### Manual Installation

1. **Install system dependencies**:
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install wireless-tools aircrack-ng hostapd dnsmasq iptables python3-dev build-essential

   # Fedora/RHEL
   sudo dnf install wireless-tools aircrack-ng hostapd dnsmasq iptables python3-devel gcc
   ```

2. **Bootstrap Evil Twin dependencies** (if needed):
   ```bash
   sudo ./bootstrap_evil_twin.sh
   ```

3. **The launcher will automatically create a virtual environment and install Python dependencies** when first run.

## Usage

### Launch the Application
```bash
# Make executable (first time only)
chmod +x wifucker_launcher

# Launch the unified TUI
./wifucker_launcher
```

The application provides a tabbed text-based user interface with the following main sections:

### 🏠 **WiFi Operations Tab**
- Network scanning and analysis
- Handshake capture with deauthentication
- Password cracking with hardware acceleration
- Automated scan→capture→crack workflows

### 🔐 **Router Cracking Tab**
Dedicated router password cracking interface with:

#### Quick Access Buttons
- **🔥 EE WiFi Smart Crack**: One-click EE/BT Smart Hub cracking with auto-detection
- **⚡ Router Hex Blitz**: Fast 10-digit hex brute force for technical routers
- **🎯 Pattern Storm**: Multi-pattern attack combining hex, numeric, and brand patterns
- **🔍 Smart Detect & Crack**: Auto-detect router type and select optimal strategy

#### Router Type Selection
- **🔐 Generic Router**: 8-12 character alphanumeric passwords
- **📱 EE/BT Smart Hub**: 12-14 digit numeric patterns (sequential, repeated, etc.)
- **⚙️ Technical Device**: 10-digit hexadecimal patterns (a-f, 0-9)
- **🌐 Auto-Detect**: Intelligent router type detection from SSID

#### Configuration Options
- **Target SSID Input**: Enter router network name for pattern optimization
- **Wordlist Size Control**: Adjustable password generation (1,000-50,000 passwords)
- **Router Analysis**: SSID intelligence and pattern suggestions
- **Live Preview**: Real-time preview of generated passwords
- **Save/Load Wordlists**: Export generated wordlists for external tools

### 🇬🇧 **UK Router WPS Tab**
Comprehensive WPS attack interface for UK routers with both basic and advanced methods:

#### How WPS Works (Background)
**Wi-Fi Protected Setup (WPS)** was designed to simplify WiFi network setup by allowing devices to join networks without entering long WPA2 passphrases. Here's how it works:

1. **PIN-Based Authentication**:
   - 8-digit numeric PIN (last digit is checksum)
   - Split into two 4-digit halves for verification
   - Example PIN: `12345670` (checksum ensures validity)

2. **WPS Protocol Flow**:
   ```
   Enrollee (Device) ↔ Registrar (Router)
   M1: Enrollee Hello → Registrar
   M2: Registrar Hello ← Enrollee
   M3: Enrollee Authentication → Registrar
   M4: Registrar Authentication ← Enrollee
   M5: Enrollee Encryption → Registrar
   M6: Registrar Encryption ← Enrollee
   M7: Enrollee Confirmation → Registrar
   M8: Registrar Confirmation ← Enrollee
   ```

3. **Key Exchange**:
   - Uses Diffie-Hellman key exchange for secure communication
   - Derives WPA2 passphrase using PBKDF2 with PIN as salt
   - Final passphrase: `PBKDF2(PIN, "Wi-Fi Easy and Secure Key Derivation", 4096 iterations)`

4. **Security Flaws**:
   - **Brute Force Vulnerability**: Only 8 digits = 100 million possibilities
   - **Timing Attacks**: Different response times for correct/incorrect PIN halves
   - **Implementation Bugs**: Poor random number generation, weak DH parameters
   - **Protocol Flaws**: Error messages can leak PIN information

#### WPS Versions & Vulnerabilities
- **WPS 1.0**: Original implementation, highly vulnerable to all attacks
- **WPS 2.0**: Added some security but still vulnerable to most attacks
- **WPS 2.0 + PIN**: Enhanced PIN validation but still brute-forceable
- **Modern WPS**: Some implementations have PIN attempt limits and better validation

#### Router-Specific Vulnerabilities
- **Broadcom Chipsets**: Pixie Dust attacks, weak DH parameters
- **Ralink/Mediatek**: PIN computation algorithms, timing attacks
- **Realtek**: EAP message injection vulnerabilities
- **Qualcomm**: Registrar PIN disclosure flaws
- **UK-Specific**: ISP firmware often lags behind security updates

#### WPS Attack Prerequisites
- **WPS Enabled**: Router must have WPS enabled (check with `wash` tool)
- **Signal Strength**: Strong signal required for reliable communication
- **Lockout Avoidance**: Some routers lock WPS after failed attempts
- **PIN Validation**: Built-in checksum validation (last digit must be correct)

#### Basic WPS Attack Methods

##### 🔐 **Compute PIN Attack**
**How it works:**
1. **MAC Address Analysis**: Extracts the router's BSSID (MAC address) from wireless scanning
2. **Algorithm-Based Calculation**: Uses mathematical algorithms to compute the 8-digit WPS PIN from the MAC address
3. **Common Algorithms**:
   - **TrendNet Algorithm**: `PIN = (MAC[5] + MAC[4] + MAC[3]) % 10000000 + (MAC[5] + MAC[4] + MAC[3]) * 10000000`
   - **D-Link Algorithm**: `PIN = (MAC[3] + MAC[4] + MAC[5]) % 10000000`
   - **Belkin Algorithm**: `PIN = (MAC[0] + MAC[1] + MAC[2] + MAC[3] + MAC[4] + MAC[5]) % 10000000`
4. **PIN Testing**: Attempts to authenticate using the computed PIN
5. **Success Rate**: High success rate (80-90%) on vulnerable router models

##### 👾 **Pixie Dust Attack**
**How it works:**
1. **WPS Handshake Capture**: Captures the initial WPS M1/M2 message exchange
2. **Nonce Extraction**: Extracts cryptographic nonces (E-S1, E-S2) from the M1 message
3. **Offline Brute Force**: Uses the router's public key hash to brute force the PIN offline
4. **Key Derivation**: Once PIN is found, derives the WPA2 passphrase using PBKDF2
5. **Vulnerable Components**:
   - Broadcom BCM4327/BCM4328 chipsets
   - Ralink RT5350/RT5572 chipsets
   - Some Realtek RTL8186/RTL8188 chipsets
6. **Attack Speed**: Extremely fast (seconds to minutes) once handshake is captured
7. **Detection Risk**: Low - no interaction with the router beyond initial scan

##### 🔢 **PIN Brute Force Attack**
**How it works:**
1. **Sequential PIN Testing**: Tries all possible 8-digit WPS PINs (00000000 to 99999999)
2. **WPS Protocol Abuse**: Sends WPS authentication attempts for each PIN
3. **Checksum Validation**: Uses WPS checksum algorithm to validate PIN format before testing
4. **Rate Limiting Bypass**: Exploits WPS timing windows to avoid lockouts
5. **PIN Checksum Algorithm**:
   ```
   PIN: ABCDEFGH
   Checksum = ((10 - ((3×(A+B+C) + D+E+F+G+H) % 10)) % 10)
   ```
6. **Attack Duration**: 4-24 hours depending on router response times
7. **Success Rate**: 100% eventual success on WPS-enabled routers (unless locked)

##### 🚫 **Null PIN Attack**
**How it works:**
1. **Default PIN Testing**: Tests for routers with empty or default WPS PINs
2. **Common Default Values**:
   - Empty string ("")
   - All zeros ("00000000")
   - Factory defaults ("12345670", "admin123")
3. **Quick Verification**: Attempts WPS authentication with null/default values
4. **Vulnerable Scenarios**:
   - Routers with factory reset state
   - Misconfigured devices
   - Older firmware with default PINs
5. **Attack Speed**: Instant verification
6. **Success Rate**: Low (1-5%) but very fast to test

#### Advanced WPS Attack Methods

##### 🔑 **Small DH Key Attack**
**How it works:**
1. **DH Parameter Analysis**: Examines the Diffie-Hellman parameters in WPS key exchange
2. **Small Prime Factor Detection**: Identifies when the prime modulus p has small prime factors
3. **Discrete Logarithm Attack**: Uses the small factors to solve the discrete logarithm problem
4. **Private Key Recovery**: Recovers the enrollee's private DH key
5. **Session Key Derivation**: Derives the WPA2 passphrase from recovered keys
6. **Mathematical Basis**:
   ```
   Given p = q1^a * q2^b * ... (small factors)
   For each small factor qi, solve: g^x ≡ y mod qi
   Use Chinese Remainder Theorem to reconstruct x mod p
   ```
7. **Vulnerable Conditions**: Routers using weak DH parameters (rare but exists in some firmware)
8. **Attack Speed**: Fast (minutes to hours) but requires specific vulnerable parameters

##### 📢 **Registrar PIN Disclosure Attack**
**How it works:**
1. **WPS Session Initiation**: Starts a normal WPS registration process
2. **Malformed Message Injection**: Sends specially crafted WPS messages with invalid parameters
3. **Error Response Analysis**: Exploits router error handling to leak PIN information
4. **PIN Digit Extraction**: Forces the router to reveal individual PIN digits through error messages
5. **Common Vectors**:
   - **M4 Message Manipulation**: Modifies the M4 message to trigger PIN disclosure
   - **NACK Message Abuse**: Uses negative acknowledgments to leak PIN data
   - **Timeout Exploitation**: Forces timeouts that reveal PIN information in error responses
6. **Protocol Flaw**: Abuses WPS error reporting mechanisms designed for debugging
7. **Success Rate**: Medium (30-60%) on routers with verbose error reporting

##### 💉 **EAP Message Injection Attack**
**How it works:**
1. **EAP-WPS Session Setup**: Initiates EAP authentication with WPS extensions
2. **Message Sequence Interception**: Captures and analyzes EAP message flow
3. **Malicious Message Injection**: Injects crafted EAP messages into the authentication stream
4. **Credential Extraction**: Exploits EAP processing to extract WPS PINs or WPA2 keys
5. **Attack Vectors**:
   - **EAP-Identity Spoofing**: Spoofs identity messages to gain access to WPS data
   - **EAP-TLS Injection**: Injects false TLS handshakes to extract credentials
   - **EAP-MD5 Challenge**: Manipulates MD5 challenges to leak PIN information
6. **Network Position**: Requires man-in-the-middle position on the network
7. **Success Rate**: High (60-80%) when MITM position can be established
8. **Detection Risk**: Higher due to active network manipulation

#### UK Router Support
- **Virgin Media**: Super Hub 2/3/4 models with specific firmware vulnerabilities
- **BT**: Home Hub 5/6, Smart Hub 2 models with known PIN patterns
- **EE**: Bright Box routers with Bright Box-specific attack vectors
- **Sky**: Broadband routers with QCOM chipset vulnerabilities
- **TalkTalk**: Huawei and Sagemcom models with ISP-specific patterns

#### Features
- **Router Database**: 10+ router models with known WPS vulnerabilities
- **SSID Detection**: Automatic router identification from network names
- **PIN Generation**: Multiple algorithms for comprehensive coverage
- **Attack Pipeline**: Automated PIN testing and validation
- **Protocol Analysis**: Deep WPS protocol inspection and attack coordination
- **PIN Validation**: Built-in WPS checksum validation

#### Attack Success Rates & Characteristics

| Attack Method | Success Rate | Speed | Detection Risk | Router Lockout Risk |
|---------------|-------------|-------|----------------|-------------------|
| **Compute PIN** | 80-90% | < 1 second | Very Low | Low |
| **Pixie Dust** | 60-80% | 1-5 minutes | Very Low | None |
| **PIN Brute Force** | 100%* | 4-24 hours | Medium | High |
| **Null PIN** | 1-5% | < 1 second | Very Low | Low |
| **Small DH Key** | 10-30% | 5-60 minutes | Low | Low |
| **Registrar Disclosure** | 30-60% | 1-10 minutes | Medium | Medium |
| **EAP Injection** | 60-80% | 2-15 minutes | High | Medium |

*100% eventual success on WPS-enabled routers (unless permanently locked)

#### Detection & Mitigation
- **Router Logs**: Most attacks leave traces in router system logs
- **WPS Lockouts**: Failed attempts may temporarily disable WPS (5-60 minutes)
- **Firmware Updates**: Modern firmware often fixes WPS vulnerabilities
- **WPS Disable**: Best defense - disable WPS entirely on routers
- **Strong WPA2**: Use complex WPA2 passwords as fallback security

#### Attack Workflow
1. **Reconnaissance**: Scan for WPS-enabled routers using `wash` or `airodump-ng`
2. **Vulnerability Assessment**: Check router model against known vulnerable databases
3. **Method Selection**: Choose appropriate attack based on router model and WPS version
4. **Handshake Capture**: Capture M1/M2 messages for offline attacks
5. **PIN Testing**: Attempt PIN authentication with router
6. **Passphrase Extraction**: Derive WPA2 passphrase from successful PIN
7. **Network Access**: Use extracted credentials to join the network

#### Practical Attack Sequence Example

**Scenario**: Targeting a BT Home Hub 5 (known vulnerable model)

1. **Reconnaissance**:
   ```bash
   # Scan for WPS-enabled networks
   wash -i wlan0

   # Output shows:
   # BSSID               Channel  RSSI  WPS Version  WPS Locked  ESSID
   # XX:XX:XX:XX:XX:XX  6        -45   1.0          No          BTHub5-XXXX
   ```

2. **Router Detection**:
   - SSID "BTHub5-XXXX" matches BT Home Hub 5 pattern
   - Check router database for known PIN computation algorithms
   - Confirm WPS version 1.0 (highly vulnerable)

3. **Attack Method Selection**:
   - **First Try**: Compute PIN (80-90% success rate, instant)
   - **Fallback**: Pixie Dust (if handshake captured)
   - **Last Resort**: PIN Brute Force (guaranteed success)

4. **PIN Testing**:
   ```
   Computed PIN: 12345670
   Router Response: ✅ PIN accepted
   Derived WPA2 Key: MySecretPassphrase123!
   ```

5. **Success Verification**:
   ```bash
   # Test network access
   iwconfig wlan0 essid "BTHub5-XXXX" key "MySecretPassphrase123!"
   ```

#### Common Attack Patterns by ISP

- **Virgin Media**: Compute PIN attacks highly effective on Super Hub models
- **BT**: Mix of Compute PIN and Pixie Dust attacks successful
- **EE**: Registrar PIN disclosure often works on Bright Box routers
- **Sky**: PIN brute force usually required due to better firmware
- **TalkTalk**: EAP injection attacks effective on Huawei models

#### Technical Reference

##### WPS PIN Checksum Algorithm
```python
def wps_pin_checksum(pin):
    """
    Calculate WPS PIN checksum (last digit)
    PIN format: ABCDEFGH (8 digits, H is checksum)
    """
    pin_str = str(pin).zfill(8)
    digits = [int(d) for d in pin_str]

    # Calculate checksum: (10 - ((3×(A+B+C) + D+E+F+G+H) % 10)) % 10
    checksum = (10 - ((3 * (digits[0] + digits[1] + digits[2]) +
                       digits[3] + digits[4] + digits[5] + digits[6]) % 10)) % 10

    return checksum == digits[7]
```

##### Common PIN Computation Algorithms
```python
def compute_trendnet_pin(mac):
    """TrendNet router PIN computation"""
    mac_int = [int(x, 16) for x in mac.split(':')]
    base = (mac_int[5] + mac_int[4] + mac_int[3]) % 10000000
    pin = base + ((mac_int[5] + mac_int[4] + mac_int[3]) * 10000000)
    return f"{pin:08d}"

def compute_dlink_pin(mac):
    """D-Link router PIN computation"""
    mac_int = [int(x, 16) for x in mac.split(':')]
    pin = (mac_int[3] + mac_int[4] + mac_int[5]) % 10000000
    return f"{pin:08d}"
```

##### WPS Protocol Message Structure
- **M1**: Enrollee Hello (contains PK_E, MAC_E)
- **M2**: Registrar Hello (contains PK_R, MAC_R, E-S1, E-S2)
- **M3**: Enrollee Authentication (contains E-Hash1, E-Hash2)
- **M4**: Registrar Authentication (contains R-Hash1, R-Hash2, E-S1, E-S2)
- **M5**: Enrollee Encryption (contains encrypted data)
- **M6**: Registrar Encryption (contains encrypted data)
- **M7**: Enrollee Confirmation (contains encrypted data)
- **M8**: Registrar Confirmation (contains encrypted data)

##### WPA2 Passphrase Derivation
```python
import hashlib
import hmac

def derive_wpa2_passphrase(pin, ssid):
    """Derive WPA2 passphrase from WPS PIN and SSID"""
    # PBKDF2 with PIN as passphrase and SSID as salt
    passphrase = hashlib.pbkdf2_hmac(
        'sha1',
        pin.encode(),
        ssid.encode(),
        4096,  # iterations
        32     # key length
    ).hex()
    return passphrase
```

#### Troubleshooting Common Issues

- **"No WPS found"**: Router may have WPS disabled or use WPS 2.0+
- **"PIN lockout"**: Router temporarily disabled WPS after failed attempts
- **"Weak signal"**: Move closer to router for reliable communication
- **"Protocol error"**: Router firmware may have patched specific vulnerabilities
- **"DH parameter error"**: Small DH Key attack not applicable to this router model

### 🦹 **Evil Twin Suite Tab**
Complete rogue access point and credential harvesting:

#### Evil Twin Features
- **UK ISP Templates**: Pre-built captive portals for Virgin Media, BT, EE, Sky, TalkTalk
- **Rogue AP Setup**: Automated access point configuration
- **Captive Portal**: Flask-based credential harvesting server
- **Network Spoofing**: SSID cloning and broadcasting

#### Attack Workflow
1. **Target Selection**: Choose target network and ISP template
2. **AP Configuration**: Set up rogue access point with cloned SSID
3. **Portal Deployment**: Launch captive portal for credential capture
4. **Monitoring**: Real-time credential harvesting and logging

#### Templates Included
- **Virgin Media**: Multiple Super Hub variants
- **BT**: Home Hub and Smart Hub designs
- **EE**: Bright Box login pages
- **Sky**: Broadband authentication portals
- **TalkTalk**: Huawei and Sagemcom interfaces

### 🎯 **Attack Pipeline Tab**
Automated multi-stage attack coordination:

#### Pipeline Features
- **Workflow Creation**: Build custom attack sequences
- **Stage Management**: Parallel and sequential attack execution
- **Progress Monitoring**: Real-time attack status and results
- **Result Aggregation**: Comprehensive attack reporting

### ⚙️ **Settings Tab**
Configuration and preferences:

#### Settings Categories
- **Hardware Acceleration**: Enable/disable CPU/GPU/NPU acceleration
- **Network Interfaces**: Wireless adapter configuration
- **Attack Parameters**: Timeout, retry, and performance settings
- **Logging**: Debug level and output configuration
- **Security**: Safe mode and validation settings

## Hardware Acceleration

WIFUCKER automatically detects and utilizes available hardware acceleration:

### CPU Acceleration
- **AVX-512**: Advanced SIMD instructions for bulk cryptographic operations
- **AVX2/AVX**: Vector processing for password cracking
- **AMX (Advanced Matrix Extensions)**: Matrix operations for AI workloads
- **AES-NI**: Hardware-accelerated AES encryption/decryption

### GPU Acceleration
- **Intel GPU**: OpenCL acceleration for cracking operations
- **NVIDIA CUDA**: GPU-accelerated password cracking (via external tools)
- **AMD GPU**: ROCm/OpenCL support for heterogeneous computing

### AI/NPU Acceleration
- **Intel NPU**: Neural processing for pattern recognition and AI wordlist generation
- **OpenVINO**: Optimized neural network inference for ML-based attacks
- **ONNX Runtime**: Cross-platform ML model execution

### Performance Features
- **Multi-threading**: Automatic thread pool optimization based on CPU cores
- **Memory Optimization**: Efficient memory usage for large wordlists
- **Hardware Detection**: Automatic capability detection and optimal algorithm selection
- **Fallback Modes**: Graceful degradation when hardware acceleration unavailable

## Router Password Cracking & WPS Attacks

Comprehensive router security assessment toolkit:

### Traditional Router Password Cracking

#### EE WiFi Smart Hub Mode
- **Target**: EE/BT Smart Hub routers
- **Pattern**: 12-14 digit numeric passwords
- **Examples**: Sequential numbers (123456789012), repeated digits (111111111111), pattern repeats
- **Detection**: Auto-detects EE/BT networks from SSID patterns

#### Hexadecimal Brute Force Mode
- **Target**: Technical devices and enterprise routers
- **Pattern**: 10-digit hexadecimal (a-f, 0-9)
- **Use Case**: Network equipment, IoT devices, industrial routers
- **Performance**: Optimized for hexadecimal character sets

#### Smart Router Detection
- **Auto-Analysis**: Analyzes SSID for router type detection
- **Pattern Matching**: Matches against 50+ known router brands and patterns
- **Adaptive Generation**: Generates appropriate wordlists based on detection
- **UK Provider Support**: Specialized patterns for all major UK ISPs

#### Available Router Patterns
- **Hexadecimal (10 digits)**: a-f, 0-9 combinations for technical devices
- **EE WiFi Numbers (12-14 chars)**: EE/BT Smart Hub numeric patterns
- **UK Provider Patterns**: Virgin Media, BT, EE, Sky, TalkTalk specific formats
- **Mixed Hex (8-12 chars)**: Extended hexadecimal patterns
- **Numeric Serial (10-16 chars)**: Serial number and manufacturing patterns
- **Alphanumeric Router (8-12 chars)**: Generic router default passwords

### WPS Attack Suite

#### UK Router WPS Database
- **Router Coverage**: 10+ models across 5 major UK providers
- **Vulnerability Database**: Known WPS PIN generation algorithms per model
- **SSID Matching**: Automatic router identification from network names
- **Firmware Tracking**: Vulnerability updates for different firmware versions

#### WPS Attack Methods
- **Compute PIN**: MAC address-based PIN calculation algorithms
- **Pixie Dust**: Offline WPS vulnerability exploitation (Pixie-Dust attack)
- **Brute Force PIN**: Complete 8-digit WPS PIN enumeration (00000000-99999999)
- **Null PIN**: Testing for default or empty PIN configurations

#### Advanced WPS Attacks
- **Small DH Key Attack**: Exploits weak Diffie-Hellman parameters in WPS key exchange
- **Registrar PIN Disclosure**: Forces Access Point to reveal PIN through malformed messages
- **EAP Message Injection**: Injects malicious EAP messages to extract WPS credentials

### IoT Device WPS Attacks

#### HP Printer Vulnerabilities
Specialized WPS attacks for HP printer ecosystems:

- **HP Envy Series**: 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000 models
- **HP OfficeJet Series**: 100, 200, 400, 500, 600, 700 models
- **HP LaserJet Series**: Pro and MFP models with wireless capabilities
- **Default PINs**: Common factory defaults (12345670, 00000000, 88888888, 99999999)
- **MAC-Based PINs**: Hardware address derived PIN calculations
- **Model-Specific Algorithms**: Different PIN generation for different HP series

#### IoT Device Types Supported
- **Printers**: HP Envy, OfficeJet, LaserJet with wireless connectivity
- **Smart TVs**: Samsung Smart TV, LG webOS, Android TV devices
- **Streaming Devices**: Roku, Amazon Fire TV, Google Chromecast, Apple TV
- **Security Cameras**: Nest Cam, Ring devices, generic IP cameras
- **Smart Speakers**: Amazon Echo, Google Home, Sonos speakers
- **Generic IoT**: Any device with WPS-enabled wireless connectivity

#### Network Pivot & Relay Functionality
Advanced post-exploitation capabilities:

- **Device Compromise**: WPS PIN extraction and network key recovery
- **Network Pivot**: Use compromised IoT device as relay to router network
- **Internet Access**: Pivot through IoT devices to reach internet connectivity
- **Router Access**: Bridge through IoT devices to access router interfaces
- **Traffic Routing**: Automatic routing configuration for pivoted connections

#### Attack Workflow
1. **IoT Device Discovery**: Scan for vulnerable IoT devices on target network
2. **Device Type Identification**: Auto-detect HP printers and other IoT devices
3. **WPS Attack Selection**: Choose optimal attack method based on device type
4. **PIN Extraction**: Crack WPS PIN using device-specific algorithms
5. **Network Key Recovery**: Extract WPA/WPA2 credentials from compromised device
6. **Pivot Establishment**: Set up network relay through compromised device
7. **Internet Access**: Use pivot to access router network and internet
8. **Cleanup & Persistence**: Maintain access while avoiding detection

#### Technical Implementation
- **Device Fingerprinting**: SSID pattern matching and device type identification
- **Multi-Method Attacks**: Default PIN, MAC-based, computed PIN, and brute force attacks
- **Protocol-Level Attacks**: Pixie Dust, Small DH Key, and EAP injection for IoT devices
- **Network Manipulation**: ARP scanning, IP detection, and routing table modification
- **Connection Management**: Automatic interface configuration and cleanup

### Evil Twin Attack Suite

#### UK ISP Templates
Pre-configured captive portals for major UK providers:
- **Virgin Media**: Super Hub 2/3/4 login pages
- **BT**: Home Hub 5/6 and Smart Hub 2 interfaces
- **EE**: Bright Box authentication portals
- **Sky**: Broadband login pages with regional variants
- **TalkTalk**: Huawei and Sagemcom router interfaces

#### Attack Components
- **Rogue AP Creation**: Automated hostapd configuration for fake access points
- **Captive Portal Server**: Flask-based credential harvesting with session management
- **DNS Spoofing**: dnsmasq configuration for captive portal redirection
- **Traffic Interception**: iptables rules for MITM positioning

#### Workflow Automation
1. **Target Reconnaissance**: Scan for legitimate networks and clone SSID
2. **AP Deployment**: Launch rogue access point with cloned credentials
3. **Portal Activation**: Deploy ISP-specific captive portal
4. **Credential Harvesting**: Capture and securely store user credentials
5. **Attack Cleanup**: Automated teardown and log analysis

## Testing & Validation

WIFUCKER includes comprehensive test suites covering all major functionality:

### Test Suite Overview

#### Core Test Categories
- **UK Router WPS Tests**: UK router database, PIN generation, WPS cracking pipeline
- **IoT WPS Tests**: HP printer vulnerabilities, IoT device detection, network pivoting
- **Advanced WPS Tests**: Protocol-level attacks, vulnerability detection, attack coordination
- **Evil Twin Tests**: UK ISP templates, AP configuration, captive portal functionality
- **Router Cracking Demo**: Live demonstration of router password cracking capabilities

### Running Tests

#### Run All Tests
```bash
# From WIFUCKER root directory
python3 tests/run_all_tests.py
```

#### Run Individual Test Suites
```bash
# UK Router WPS functionality
python3 tests/test_uk_wps.py

# Advanced WPS attack methods
python3 tests/test_advanced_wps.py

# Evil Twin suite components
python3 tests/test_evil_twin.py

# Router cracking demonstration
python3 tests/demo_router_cracking.py

# Import validation
bash tests/test_import.sh
```

### Test Results & Coverage

Current test coverage includes:
- ✅ **UK Router Database**: Router model detection and pattern matching
- ✅ **WPS PIN Generation**: Compute PIN, Pixie Dust, brute force algorithms
- ✅ **WPS Attack Pipeline**: End-to-end attack coordination and reporting
- ✅ **Advanced WPS Methods**: Small DH Key, Registrar PIN, EAP injection
- ✅ **Evil Twin Templates**: UK ISP captive portal configurations
- ✅ **Router Password Patterns**: EE WiFi, hex, and provider-specific generation

### Test Dependencies

Tests gracefully handle missing dependencies:
- **Optional Dependencies**: `netifaces`, `psutil`, `scapy`, `flask` for Evil Twin tests
- **System Tools**: `hostapd`, `dnsmasq`, `iptables` for Evil Twin functionality
- **Graceful Degradation**: Tests skip functionality when dependencies unavailable

### Continuous Testing

Tests are designed for:
- **CI/CD Integration**: Automated testing in continuous integration pipelines
- **Dependency Validation**: Ensuring all required components are available
- **Regression Prevention**: Catching functionality regressions during development

See `tests/README.md` for detailed testing documentation and troubleshooting.

## Bootstrap Scripts

### Automated Setup
WIFUCKER includes bootstrap scripts for automatic dependency installation:

#### Core Bootstrap (`wifucker_launcher`)
- Creates isolated Python virtual environment
- Installs all Python dependencies from `requirements.txt`
- Sets up development environment automatically

#### Evil Twin Bootstrap (`bootstrap_evil_twin.sh`)
- Installs system-level WiFi tools (`aircrack-ng`, `iw`)
- Configures Evil Twin dependencies (`hostapd`, `dnsmasq`, `iptables`)
- Requires sudo privileges for system package installation

### Bootstrap Usage
```bash
# Basic setup (Python environment)
./wifucker_launcher

# Evil Twin dependencies (requires sudo)
sudo ./bootstrap_evil_twin.sh
```

## Security & Legal Notice

### ⚠️ **IMPORTANT SECURITY WARNING**

This tool is designed **EXCLUSIVELY** for authorized security testing and research purposes only.

#### Legal Requirements
- **Obtain explicit written permission** from network/system owners before testing
- **Comply with all applicable laws** in your jurisdiction
- **Do not test on networks you do not own or control**
- **Document all testing activities** for legal compliance

#### Ethical Guidelines
- **Authorized Testing Only**: Never test without explicit permission
- **No Production Networks**: Do not test on live production systems
- **Responsible Disclosure**: Report vulnerabilities through proper channels
- **No Malicious Use**: This tool is for defensive security research only

#### WPS Attack Considerations
- **WPS attacks may violate terms of service** for some ISPs
- **Some WPS attacks can cause device instability** or require factory resets
- **Always have recovery plans** for tested devices

#### Evil Twin Attack Warnings
- **Evil Twin attacks intercept user credentials** - handle with extreme care
- **May violate wiretapping laws** in some jurisdictions
- **Never harvest credentials without explicit consent**
- **Use only in controlled, authorized testing environments**

### Liability Disclaimer
The authors and contributors are not responsible for misuse of this tool. Users assume all responsibility for compliance with applicable laws and regulations.

## License

MIT License - See LICENSE file for details.

## Contributing

We welcome contributions from the security research community:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/your-feature-name`
3. **Follow Cursor Rules**: All code must comply with the Cursor Rules requirements
4. **Add tests**: Include comprehensive tests for new functionality
5. **Update documentation**: Keep README and docs current
6. **Submit a pull request**

### Contribution Guidelines
- **Cursor Rules Compliance**: All code must follow Cursor Rules (no minimal implementations, full functionality)
- **Test Coverage**: Include tests for all new features
- **Documentation**: Update README and inline documentation
- **Code Quality**: Follow existing code patterns and conventions
- **Security**: No backdoors, hardcoded credentials, or malicious code

## Support & Community

### Issue Reporting
- **Bug Reports**: Use GitHub Issues with detailed reproduction steps
- **Security Issues**: Contact maintainers directly (do not post publicly)
- **Feature Requests**: Open GitHub Issues with detailed specifications

### Documentation
- **User Guide**: This README provides comprehensive usage instructions
- **API Documentation**: Inline code documentation for developers
- **Test Documentation**: `tests/README.md` for testing procedures

### Development Resources
- **Test Suite**: Comprehensive automated testing framework
- **Bootstrap Scripts**: Automated development environment setup
- **Hardware Acceleration**: Built-in support for modern CPU/GPU acceleration

## Changelog

### Version 2.0 - Major Feature Release
- ✅ **WPS Attack Suite**: Complete UK router WPS database with Virgin Media, BT, EE, Sky, TalkTalk support
- ✅ **Advanced WPS Attacks**: Small DH Key, Registrar PIN Disclosure, EAP Message Injection
- ✅ **Evil Twin Suite**: Full rogue AP creation with UK ISP captive portal templates
- ✅ **Unified TUI**: Tabbed interface with dedicated sections for all attack types
- ✅ **Hardware Acceleration**: Enhanced AVX-512, AMX, and OpenVINO integration
- ✅ **Test Infrastructure**: Comprehensive test suite with automated runners
- ✅ **Bootstrap Automation**: Self-bootstrapping with all dependencies
- ✅ **UK Router Focus**: Specialized support for all major UK broadband providers

### Version 1.x - Core WiFi Security
- ✅ Network scanning and handshake capture
- ✅ Hardware-accelerated password cracking
- ✅ Router password cracking for EE/BT networks
- ✅ AI-powered wordlist generation
- ✅ Automated attack workflows

## Roadmap

### Planned Features
- **WPA3 Support**: Enhanced cracking for WPA3-Personal and WPA3-Enterprise
- **Cloud Integration**: Distributed cracking across multiple systems
- **Machine Learning**: Advanced pattern recognition for password prediction
- **IoT Device Support**: Specialized attacks for smart home devices
- **Wireless Protocol Analysis**: Deep packet inspection and protocol fuzzing

### Community Contributions Welcome
We actively seek contributions for:
- Additional router model support
- New WPS attack vectors
- Evil Twin template expansions
- Performance optimizations
- Documentation improvements

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Support

For issues and questions, please open an issue on the GitHub repository.
