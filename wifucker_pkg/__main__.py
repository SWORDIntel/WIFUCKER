#!/usr/bin/env python3
"""
WIFUCKER Package Main Entry Point
"""

from .wifucker_unified_tui import WiFuFuckerApp

def main():
    """Main entry point for the WIFUCKER TUI"""
    app = WiFuFuckerApp()
    app.run()

if __name__ == "__main__":
    main()
