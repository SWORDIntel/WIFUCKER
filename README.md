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

To get started, explore the various modules and scripts in this repository. The `launcher.py` script may be a good starting point for accessing the different functionalities.

***

*Disclaimer: This tool is intended for educational purposes and authorized security testing only. Unauthorized use of this tool on networks you do not own or have permission to test is illegal.*
