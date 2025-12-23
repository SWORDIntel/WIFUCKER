"""
WiFuFucker - Advanced WiFi Security Testing Platform
====================================================

A comprehensive toolkit for WiFi security assessment featuring:
- Network scanning and analysis
- Handshake capture with deauthentication attacks
- Hardware-accelerated password cracking
- Intelligent wordlist generation
- DSMIL intelligence integration
- Router password cracking (EE WiFi, hex patterns)

Author: DSMIL Security Research
License: MIT
"""

__version__ = "2.0.0"
__author__ = "DSMIL Security Research"

# Conditional imports for TUI (only available with venv/textual)
try:
    from .wifucker_unified_tui import WiFuFuckerApp

    def main():
        """Main entry point for the WiFuFucker TUI"""
        app = WiFuFuckerApp()
        app.run()

except ImportError:
    # TUI not available (missing textual or venv)
    WiFuFuckerApp = None

    def main():
        """TUI not available - use launcher script"""
        print("ERROR: textual module not found and venv not detected")
        print("Please run the launcher: ./wifucker")
        print("Or activate the virtual environment first")
        return 1

if __name__ == "__main__":
    exit(main() or 0)
