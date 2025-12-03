# WIFUCKER - 9-Layer System with QUANTUM

## Quick Install & Launch

```bash
cd tools/WIFUCKER
./wifucker
```

The launcher bootstraps the virtual environment, installs dependencies, sets QUANTUM (Layer 9) clearance, and starts the unified TUI. For manual setup utilities, see `scripts/` and [docs/INSTALL.md](docs/INSTALL.md).

---

# WIFUCKER

WIFUCKER is a comprehensive suite of tools for Wi-Fi security testing and network analysis. It provides a wide range of capabilities, from network scanning and packet capture to advanced password cracking accelerated by specialized hardware.

## Key Features

*   **Network Operations**:
    *   **Wi-Fi Scanning**: Discover nearby wireless networks.
    *   **Monitor Mode**: Put wireless interfaces into monitor mode for packet sniffing.
    *   **Handshake Capture**: Capture WPA/WPA2 handshakes for offline analysis.
    *   **Deauthentication Attacks**: Disrupt network connections to aid in handshake capture.

*   **Password Cracking**:
    *   **Multi-Hardware Acceleration**: Utilizes CPU (AVX512), Intel NPU, and Movidius NCS2 for high-speed password cracking.
    *   **OpenVINO Integration**: Leverages OpenVINO for optimized inference on Intel hardware.
    *   **AI-Powered Wordlists**: Includes tools for generating intelligent wordlists.

*   **Surveillance and Reporting**:
    *   **Kismet & Wigle Integration**: Monitor network activity and integrate with external mapping services.
    *   **Location Tracking**: Track the location of network devices.
    *   **Automated Reporting**: Generate reports on network findings.

*   **User Interfaces**:
    *   **Command-Line Interface (CLI)**: For scripting and automation.
    *   **Text-based User Interface (TUI)**: An enhanced, user-friendly console interface.

## Hardware Acceleration

This project is designed to take advantage of modern hardware for accelerating computationally intensive tasks:

*   **Intel NPU (Neural Processing Unit)**: For AI-based tasks and optimized cracking.
*   **Intel Movidius NCS2**: For running inference models at the edge.
*   **AVX512**: For high-performance CPU-based cracking.

## Getting Started

Use `./wifucker` for the full guided flow (install + TUI). Supporting utilities and hardware helpers live in `scripts/`.

***

*Disclaimer: This tool is intended for educational purposes and authorized security testing only. Unauthorized use of this tool on networks you do not own or have permission to test is illegal.*
