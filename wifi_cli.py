#!/usr/bin/env python3
"""
WiFi Security Suite - Command Line Interface
=============================================

Hardware-accelerated WiFi security assessment with OpenVINO.

Supports:
- PCAP parsing and handshake extraction
- Hardware-accelerated cracking (NPU, NCS2, ARC GPU)
- AI-powered wordlist generation
- Automatic wordlist download
- Multi-device parallel processing

Usage:
    wifucker parse <pcap_file> [--export-hashcat output.hc] [--export-john output.john]
    wifucker crack <pcap_file> <wordlist> [--device NPU|NCS2|GPU|CPU] [--rules]
    wifucker generate <ssid> [--output wordlist.txt] [--max 100000]
    wifucker download [--all] [--source seclists_wifi]
    wifucker benchmark [--device NPU|NCS2|GPU|CPU]
    wifucker benchmark [--device NPU|NCS2|GPU|CPU]
    wifucker audit [--auto] [--ai-model PATH] [--devices LIST]
    wifucker devices
"""

import argparse
import sys
import os
import time
from pathlib import Path
from typing import List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme

# TEMPEST Theme
tempest_theme = Theme(
    {
        "info": "cyan",
        "warning": "bold yellow",
        "error": "bold red",
        "success": "bold green",
        "header": "bold #ff9500",  # Amber
        "border": "#2d3640",
        "classification": "bold white on #ff0844",
    }
)

console = Console(theme=tempest_theme)
from parsers.pcap_parser import PCAPParser
from crackers.openvino_cracker import OpenVINOWiFiCracker
from crackers.hardware_detector import HardwareDetector

# AI wordlist generation removed per user request; using simple rule‑based generator
# from ai_models.wordlist_generator import AIWordlistGenerator, WordlistConfig
from utils.wordlist_downloader import WordlistDownloader
from capture.monitor_mode import MonitorMode
from capture.handshake_capture import HandshakeCapture
from capture.adapter_optimizer import AdapterOptimizer
from surveillance.kismet_monitor import KismetMonitor, SecureKismetDB
from surveillance.probe_tracker import ProbeTracker, ProbeRequest
from surveillance.persistence_detector import PersistenceDetector
from surveillance.location_tracker import LocationTracker, GPSLocation
from surveillance.wigle_api import WiGLEAPI
from surveillance.report_generator import ReportGenerator, ReportFormat


def print_banner():
    """Print CLI banner"""
    banner_text = """
    WIFUCKER - TEMPEST CLASS C
    TACTICAL OPERATIONS CONSOLE
    """

    console.print(
        Panel(
            Text(banner_text, justify="center", style="header"),
            border_style="header",
            subtitle="[bold #00ff41]NPU[/] │ [bold #00ffff]NCS2[/] │ [bold #ff9500]GPU[/] │ [bold #ff0844]CPU[/]",
            subtitle_align="center",
        )
    )
    console.print(
        "[classification]  CLASSIFICATION: AUTHORIZED SECURITY PERSONNEL ONLY  [/]",
        justify="center",
    )
    console.print()
    console.print("⚠️  FOR AUTHORIZED SECURITY TESTING ONLY ⚠️", justify="center")
    console.print("Unauthorized access to computer networks is illegal.", justify="center")
    console.print()


def cmd_parse(args):
    """Parse PCAP file and extract handshakes"""
    print(f"\n[*] Parsing PCAP file: {args.pcap}")

    parser = PCAPParser(args.pcap)
    handshakes, pmkids = parser.parse()

    # Print summary
    summary = parser.get_summary()

    print("\n" + "=" * 70)
    print("EXTRACTION SUMMARY")
    print("=" * 70)
    print(f"  Total handshakes: {summary['total_handshakes']}")
    print(f"  Complete: {summary['complete_handshakes']}")
    print(f"  PMKIDs: {summary['pmkids']}")
    print(f"  Unique networks: {summary['unique_networks']}")
    print(f"  Unique clients: {summary['unique_clients']}")
    print("=" * 70)

    # List all handshakes
    if handshakes:
        print("\n[*] Extracted handshakes:")
        for i, hs in enumerate(handshakes, 1):
            complete = "✓" if hs.is_complete else "✗"
            print(f"  {i}. {hs.ssid:20s} | {hs.bssid} | {complete} Complete")

    # Export if requested
    if args.export_hashcat:
        parser.export_hashcat(args.export_hashcat)
        print(f"\n[+] Exported to hashcat format: {args.export_hashcat}")

    if args.export_john:
        parser.export_john(args.export_john)
        print(f"[+] Exported to john format: {args.export_john}")

    return 0


def cmd_crack(args):
    """Crack WiFi password from PCAP"""
    print(f"\n[*] Starting WiFi cracking session")
    print(f"[*] PCAP: {args.pcap}")
    print(f"[*] Wordlist: {args.wordlist}")

    # Parse PCAP first
    parser = PCAPParser(args.pcap)
    handshakes, pmkids = parser.parse()

    if not handshakes:
        print("[-] No complete handshakes found in PCAP")
        return 1

    # Select handshake to crack
    if len(handshakes) > 1:
        print("\n[*] Multiple handshakes found:")
        for i, hs in enumerate(handshakes, 1):
            print(f"  {i}. {hs.ssid} ({hs.bssid})")

        while True:
            try:
                choice = input("\nSelect handshake to crack (1-{}): ".format(len(handshakes)))
                idx = int(choice) - 1
                if 0 <= idx < len(handshakes):
                    break
            except (ValueError, KeyboardInterrupt):
                print("\n[!] Cancelled")
                return 1

        target_hs = handshakes[idx]
    else:
        target_hs = handshakes[0]

    print(f"\n[+] Selected target: {target_hs.ssid} ({target_hs.bssid})")

    # Initialize cracker
    device_pref = args.device if args.device else None
    cracker = OpenVINOWiFiCracker(use_hardware=not args.cpu_only, device_preference=device_pref)

    # Crack
    result = cracker.crack_handshake(
        ssid=target_hs.ssid,
        anonce=target_hs.anonce,
        snonce=target_hs.snonce,
        mic=target_hs.mic,
        bssid=target_hs.bssid,
        client=target_hs.client,
        wordlist_file=args.wordlist,
        progress_callback=progress_callback,
        use_rules=args.rules,
    )

    # Show result
    print("\n")
    if result.success:
        print("=" * 70)
        print("                      🎉 SUCCESS! 🎉")
        print("=" * 70)
        print(f"  SSID:     {target_hs.ssid}")
        print(f"  Password: {result.password}")
        print(f"  Device:   {result.device_used}")
        print(f"  Attempts: {result.attempts:,}")
        print(f"  Time:     {result.elapsed_time:.2f} seconds")
        print(f"  Speed:    {result.hashes_per_second:,.0f} H/s")
        print("=" * 70)

        # Save result
        if args.output:
            with open(args.output, "w") as f:
                f.write(f"SSID: {target_hs.ssid}\n")
                f.write(f"BSSID: {target_hs.bssid}\n")
                f.write(f"Password: {result.password}\n")
            print(f"\n[+] Result saved to: {args.output}")

        return 0
    else:
        print("=" * 70)
        print("                   ❌ PASSWORD NOT FOUND")
        print("=" * 70)
        print(f"  SSID:     {target_hs.ssid}")
        print(f"  Attempts: {result.attempts:,}")
        print(f"  Time:     {result.elapsed_time:.2f} seconds")
        print("=" * 70)
        print("\n💡 Try:")
        print("  - Use a larger wordlist")
        print("  - Enable rules with --rules")
        print("  - Generate SSID-based wordlist: davbest-wifi generate {}".format(target_hs.ssid))
        print("  - Download popular wordlists: davbest-wifi download --all")

        return 1


def cmd_generate(args):
    """Generate simple rule‑based wordlist (no AI)"""
    print(f"\n[*] Generating simple wordlist for SSID: {args.ssid}")

    # Simple pattern: ssid + numbers
    passwords = []
    for i in range(1, args.max_passwords + 1):
        passwords.append(f"{args.ssid}{i:04d}")

    output = args.output if args.output else f"wordlist_{args.ssid}.txt"
    with open(output, "w") as f:
        f.write("\n".join(passwords))

    print(f"\n[+] Wordlist generated: {output}")
    print(f"[+] Total passwords: {len(passwords):,}")
    if args.show_sample:
        print("\n[*] Sample passwords (first 20):")
        for i, pwd in enumerate(passwords[:20], 1):
            print(f"  {i:2d}. {pwd}")

    return 0


def cmd_download(args):
    """Download wordlists"""
    downloader = WordlistDownloader(download_dir=args.dir)

    if args.all:
        downloader.download_all(force=args.force)
    elif args.source:
        downloader.download_wordlist(args.source, force=args.force)
    else:
        downloader.list_available()
        print("\nUse --all to download all, or --source <key> for specific list")

    return 0


def cmd_devices(args):
    """List available hardware devices"""
    print("\n[*] Detecting available hardware accelerators...")

    detector = HardwareDetector()
    devices = detector.detect_devices()

    # Show multi-device config if available
    multi_config = detector.get_multi_device_config()
    if multi_config:
        print(f"\n[+] Multi-device execution available: {multi_config}")

    return 0


def cmd_benchmark(args):
    """Benchmark hardware devices"""
    print("\n[*] Running benchmark...")

    detector = HardwareDetector()
    devices = detector.detect_devices()

    if args.device:
        # Benchmark specific device
        target_device = None
        for device in devices:
            if device.device_type.value.upper() == args.device.upper():
                target_device = device
                break

        if not target_device:
            print(f"[-] Device not found: {args.device}")
            return 1

        print(f"\n[*] Benchmarking: {target_device.device_name}")
        # Would need actual model to benchmark
        print("[!] Note: Actual benchmark requires a model file")
    else:
        # Benchmark all devices
        print("[*] Benchmarking all available devices...")
        # Would benchmark each

    return 0


def cmd_interfaces(args):
    """List wireless interfaces"""
    print("\n[*] Detecting wireless interfaces...")

    monitor = MonitorMode()

    # Check requirements
    all_present, missing, optional_missing = monitor.check_requirements()

    if not all_present:
        print("\n[-] Missing required tools:")
        for tool in missing:
            print(f"    - {tool}")
        print("\n[!] Install with: sudo apt install wireless-tools iw net-tools")
        return 1

    if optional_missing:
        print("\n[!] Optional tools not found (recommended for full functionality):")
        for tool in optional_missing:
            print(f"    - {tool}")
        print("[!] Install with: sudo apt install aircrack-ng")
        print()

    # Detect interfaces
    interfaces = monitor.detect_interfaces()

    if not interfaces:
        print("[-] No wireless interfaces found")
        return 1

    # Display interfaces
    print("\n" + "=" * 80)
    print("WIRELESS INTERFACES")
    print("=" * 80)

    for iface in interfaces:
        print(f"  {iface}")

    print("=" * 80)
    print(f"\nFound {len(interfaces)} wireless interface(s)")
    print(f"\n[*] Tip: Use 'davbest-wifi optimize <interface>' to maximize performance")

    return 0


def cmd_optimize(args):
    """Optimize WiFi adapter for maximum performance"""
    import os

    # Check if running as root
    if os.geteuid() != 0:
        print("[-] This command requires root privileges")
        print("[*] Run with: sudo davbest-wifi optimize ...")
        return 1

    optimizer = AdapterOptimizer(args.interface)

    if args.info:
        optimizer.show_info()
        return 0

    # Perform optimization
    print(f"\n[*] Optimizing {args.interface}...")

    if args.aggressive:
        print("[!] Aggressive mode enabled - use with caution!")

    results = optimizer.optimize(aggressive=args.aggressive)

    if all(results.values()):
        print("\n[+] Optimization complete!")
        return 0
    else:
        print("\n[!] Some optimizations failed (may be driver-specific)")
        return 0  # Don't fail, some optimizations are optional


def cmd_monitor(args):
    """Enable/disable monitor mode"""
    monitor = MonitorMode()

    if args.action == "enable":
        print(f"\n[*] Enabling monitor mode on {args.interface}...")

        success, message, mon_iface = monitor.enable_monitor_mode(args.interface)

        if success:
            print(f"[+] {message}")
            print(f"\n[*] Monitor interface: {mon_iface}")
            print(f"[*] Use this interface for capture: davbest-wifi capture {mon_iface}")
            return 0
        else:
            print(f"[-] {message}")
            return 1

    elif args.action == "disable":
        print(f"\n[*] Disabling monitor mode on {args.interface}...")

        success, message = monitor.disable_monitor_mode(args.interface)

        if success:
            print(f"[+] {message}")
            return 0
        else:
            print(f"[-] {message}")
            return 1

    return 0


def progress_callback(current, total, percent, speed):
    sys.stdout.write(f"\r  Progress: {percent:5.1f}% | {current:,}/{total:,} | {speed:,.0f} H/s")
    sys.stdout.flush()


def cmd_audit(args):
    """Run full WiFi security audit"""
    print(f"\n[*] Starting Full WiFi Security Audit")
    print(f"[*] Mode: {'Automatic' if args.auto else 'Interactive'}")

    # Check for Kitty terminal
    term = os.environ.get("TERM", "")
    if "kitty" in term:
        print("[+] Kitty terminal detected - Enabling accelerated TUI features")

    # Step 1: Hardware Detection
    print("\n[Phase 1] Hardware Detection")
    detector = HardwareDetector()
    devices = detector.detect_devices()
    if not devices:
        print("[-] No hardware accelerators found. Using CPU.")
    else:
        print(f"[+] Found {len(devices)} accelerator(s):")
        for dev in devices:
            print(f"  - {dev.device_name} ({dev.device_type.name})")

    # Step 2: Interface Selection
    print("\n[Phase 2] Interface Selection")
    monitor = MonitorMode()
    interfaces = monitor.detect_interfaces()
    if not interfaces:
        print("[-] No wireless interfaces found")
        return 1

    selected_interface = None
    if args.auto:
        # Pick first capable interface
        selected_interface = interfaces[0]
        print(f"[*] Auto-selected interface: {selected_interface}")
    else:
        print("[*] Available interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")

        while not selected_interface:
            try:
                choice = int(input("Select interface (number): "))
                if 1 <= choice <= len(interfaces):
                    selected_interface = interfaces[choice - 1]
            except ValueError:
                pass

    # Ensure monitor mode
    print(f"[*] Enabling monitor mode on {selected_interface}...")
    success, msg, mon_iface = monitor.enable_monitor_mode(selected_interface)
    if not success:
        print(f"[-] Failed to enable monitor mode: {msg}")
        return 1
    print(f"[+] Monitor mode enabled: {mon_iface}")

    # Step 3: Target Selection & Capture
    print("\n[Phase 3] Target Selection & Capture")

    capture = HandshakeCapture(interface=mon_iface, output_dir="./captures")

    target_network = None
    if args.auto:
        # Auto-scan and pick strongest signal
        print("[*] Scanning for targets (10s)...")
        from .capture.network_scanner import NetworkScanner

        scanner = NetworkScanner(mon_iface)
        networks = scanner.scan(duration=10)
        if not networks:
            print("[-] No networks found")
            return 1
        target_network = max(networks, key=lambda n: n.signal_strength)
        print(f"[+] Auto-selected target: {target_network.ssid} ({target_network.bssid})")
    else:
        # Interactive scan
        print("[*] Scanning for targets...")
        from .capture.network_scanner import NetworkScanner

        scanner = NetworkScanner(mon_iface)
        networks = scanner.scan(duration=10)
        if not networks:
            print("[-] No networks found")
            return 1

        print(f"\nFound {len(networks)} networks:")
        sorted_networks = sorted(networks, key=lambda n: n.signal_strength, reverse=True)
        for i, net in enumerate(sorted_networks[:10], 1):
            print(
                f"  {i}. {net.ssid:<20} | {net.bssid} | CH {net.channel:>2} | {net.signal_strength} dBm"
            )

        while not target_network:
            try:
                choice = int(input("Select target (number): "))
                if 1 <= choice <= len(sorted_networks):
                    target_network = sorted_networks[choice - 1]
            except ValueError:
                pass

    print(f"[*] Capturing handshake for {target_network.ssid}...")
    result = capture.capture_handshake(target_network, timeout=60, deauth_packets=5)

    if not result.success:
        print(f"[-] Capture failed: {result.message}")
        return 1

    print(f"[+] Handshake captured: {result.pcap_file}")

    # Step 4: Parsing
    print("\n[Phase 4] Verifying Handshake")
    parser = PCAPParser(result.pcap_file)
    handshakes, pmkids = parser.parse()
    if not handshakes:
        print("[-] Verification failed: No valid handshakes found in capture")
        return 1
    print(f"[+] Verified {len(handshakes)} handshake(s)")

    # Step 5: Wordlist Generation (Rule-based, NO AI)
    print("\n[Phase 5] Wordlist Generation")
    wordlist_file = f"wordlists/{target_network.ssid}_gen.txt"
    os.makedirs("wordlists", exist_ok=True)

    print(f"[*] Generating rule-based wordlist for {target_network.ssid}...")
    passwords = []
    base_ssid = target_network.ssid.strip()
    for i in range(0, 10000):
        passwords.append(f"{base_ssid}{i}")
        passwords.append(f"{base_ssid}{i:04d}")

    with open(wordlist_file, "w") as f:
        f.write("\n".join(passwords))
    print(f"[+] Generated {len(passwords)} candidates in {wordlist_file}")

    # Step 6: Cracking
    print("\n[Phase 6] Hardware-Accelerated Cracking")

    selected_device = "CPU"
    if devices:
        dev_types = [d.device_type.name for d in devices]
        if "NPU" in dev_types:
            selected_device = "NPU"
        elif "MYRIAD" in dev_types:
            selected_device = "NCS2"
        elif "GPU" in dev_types:
            selected_device = "GPU"

    print(f"[*] Using device: {selected_device}")

    cracker = OpenVINOWiFiCracker(device=selected_device)
    target_hs = next((hs for hs in handshakes if hs.bssid == target_network.bssid), handshakes[0])

    print(f"[*] Cracking {target_hs.ssid} ({target_hs.bssid})...")
    crack_result = cracker.crack(target_hs, wordlist_file, rules=True, callback=progress_callback)

    if crack_result.found:
        print(f"\n\n[+] PASSWORD FOUND: {crack_result.password}")
    else:
        print(f"\n[-] Password not found in generated wordlist.")

    # Step 7: Reporting
    print("\n[Phase 7] Generating Report")

    report_path = os.path.abspath(f"reports/audit_{target_network.ssid}_{int(time.time())}.md")
    os.makedirs("reports", exist_ok=True)
    with open(report_path, "w") as f:
        f.write(f"# WiFi Audit Report: {target_network.ssid}\n")
        f.write(f"**Date:** {time.ctime()}\n")
        f.write(f"**Target:** {target_network.ssid} ({target_network.bssid})\n")
        f.write(f"**Interface:** {mon_iface}\n")
        f.write(f"**Device Used:** {selected_device}\n")
        f.write(f"**Result:** {'SUCCESS' if crack_result.found else 'FAILURE'}\n")
        if crack_result.found:
            f.write(f"**Password:** `{crack_result.password}`\n")
        f.write(f"**Time Elapsed:** {crack_result.elapsed_time:.2f}s\n")
        f.write(f"**Attempts:** {crack_result.attempts}\n")

    print(f"[+] Report saved to: {report_path}")

    print("\n[+] Audit Complete!")
    return 0


def cmd_capture(args):
    """Capture WiFi handshakes"""
    import os

    # Check if running as root
    if os.geteuid() != 0:
        print("[-] This command requires root privileges")
        print("[*] Run with: sudo davbest-wifi capture ...")
        return 1

    print(f"\n[*] Starting handshake capture on {args.interface}")

    # Initialize capture
    capture = HandshakeCapture(interface=args.interface, output_dir=args.output_dir)

    # If target specified directly
    if args.bssid and args.channel:
        # Manual target
        from .capture.network_scanner import WiFiNetwork

        target = WiFiNetwork(
            bssid=args.bssid,
            channel=args.channel,
            essid=args.essid or f"Target-{args.bssid}",
            power=-50,
            encryption="WPA2",
            cipher="",
            authentication="",
        )

        print(f"[*] Manual target: {target.essid} ({target.bssid}) on channel {target.channel}")

    else:
        # Scan and select
        print("[*] Scanning for networks...")
        target = capture.scan_and_select_network(
            scan_duration=args.scan_time, show_hidden=args.show_hidden, min_power=args.min_power
        )

        if not target:
            print("[-] No target selected")
            return 1

    # Capture handshake
    result = capture.capture_handshake(
        target=target,
        output_file=args.output,
        deauth_count=args.deauth_count,
        capture_duration=args.timeout,
        verify=not args.no_verify,
    )

    # Print result
    print(f"\n{'='*70}")
    if result.success:
        print("                      ✓ HANDSHAKE CAPTURED!")
    else:
        print("                      ✗ CAPTURE FAILED")
    print(f"{'='*70}")
    print(f"  Target:     {result.target_network.essid}")
    print(f"  BSSID:      {result.target_network.bssid}")
    print(f"  Channel:    {result.target_network.channel}")
    if result.success:
        print(f"  Handshakes: {result.handshakes_captured}")
    print(f"  Duration:   {result.duration:.1f}s")
    print(f"  PCAP File:  {result.pcap_file}")
    print(f"{'='*70}")

    if result.success:
        print(f"\n[*] Next steps:")
        print(f"    1. Crack: davbest-wifi crack {result.pcap_file} wordlist.txt")
        print(f"    2. Parse: davbest-wifi parse {result.pcap_file}")
        return 0
    else:
        print(f"\n[!] {result.message}")
        return 1


def cmd_surveillance_monitor(args):
    """Monitor Kismet databases for surveillance detection"""
    import os

    # Check if running as root
    if os.geteuid() != 0:
        print("[-] This command requires root privileges")
        print("[*] Run with: sudo davbest-wifi surveillance monitor")
        return 1

    print("\n[*] Starting Kismet surveillance monitoring")
    print("[!] This requires Kismet to be running with GPS support")

    # Load ignore list if specified
    ignore_list = []
    if args.ignore_file and Path(args.ignore_file).exists():
        with open(args.ignore_file) as f:
            ignore_list = [line.strip() for line in f if line.strip()]
        print(f"[+] Loaded {len(ignore_list)} ignored devices/SSIDs")

    # Initialize tracker and detector
    tracker = ProbeTracker()
    detector = PersistenceDetector(
        min_appearances=args.min_appearances, min_persistence_score=args.min_score
    )

    # Initialize monitor
    monitor = KismetMonitor(
        kismet_db_dir=args.kismet_dir, check_interval=args.interval, ignore_list=ignore_list
    )

    # Callback for new probes
    def on_new_probes(probes, ssid_probes):
        """Handle new probe requests"""
        # Add to tracker
        for probe_data in probes:
            probe = ProbeRequest(
                mac_address=probe_data["mac_address"],
                signal_strength=probe_data["signal_strength"],
                latitude=probe_data["latitude"],
                longitude=probe_data["longitude"],
                timestamp=probe_data["last_seen"],
            )
            tracker.add_probe(probe)

        for probe_data in ssid_probes:
            probe = ProbeRequest(
                mac_address=probe_data["mac_address"],
                ssid=probe_data["ssid_name"],
                signal_strength=probe_data["signal_strength"],
                latitude=probe_data["latitude"],
                longitude=probe_data["longitude"],
                timestamp=probe_data["last_seen"],
            )
            tracker.add_probe(probe)

        # Rotate if needed
        if tracker.should_rotate():
            tracker.rotate_tracking_lists()

        # Analyze for threats
        devices = list(tracker.devices.values())
        scores = detector.analyze_devices(devices)

        # Show threats
        for score in scores:
            if score.is_threat():
                print(f"\n{score.risk_level.icon} THREAT DETECTED: {score}")
                for reason in score.detection_reasons:
                    print(f"    - {reason}")

    # Start monitoring
    print(f"[*] Monitoring: {args.kismet_dir}")
    print(f"[*] Check interval: {args.interval}s")
    print(f"[*] Press Ctrl+C to stop\n")

    try:
        monitor.start_monitoring(callback=on_new_probes)
    except KeyboardInterrupt:
        print("\n[*] Stopped by user")

        # Generate final report if requested
        if args.report:
            devices = list(tracker.devices.values())
            scores = detector.analyze_devices(devices)
            location_tracker = LocationTracker()
            clusters = location_tracker.create_clusters(devices)

            generator = ReportGenerator(output_dir=args.report_dir)
            report_file = generator.generate_report(
                scores,
                clusters,
                devices,
                format=ReportFormat.MARKDOWN,
                title="Surveillance Monitoring Session",
            )
            print(f"\n[+] Report saved: {report_file}")

    return 0


def cmd_surveillance_analyze(args):
    """Analyze Kismet database for surveillance patterns"""
    print("\n[*] Analyzing Kismet database for surveillance patterns")
    print(f"[*] Database: {args.database}")

    # Parse database
    print("[*] Extracting probe requests...")

    tracker = ProbeTracker()

    with SecureKismetDB(args.database) as db:
        probes = db.get_probe_requests()
        ssid_probes = db.get_ssid_probes()

        print(f"[+] Found {len(probes)} probe requests")
        print(f"[+] Found {len(ssid_probes)} SSID probes")

        # Add to tracker
        for probe_data in probes:
            probe = ProbeRequest(
                mac_address=probe_data["mac_address"],
                signal_strength=probe_data["signal_strength"],
                latitude=probe_data["latitude"],
                longitude=probe_data["longitude"],
                timestamp=probe_data["last_seen"],
            )
            tracker.add_probe(probe)

        for probe_data in ssid_probes:
            probe = ProbeRequest(
                mac_address=probe_data["mac_address"],
                ssid=probe_data["ssid_name"],
                signal_strength=probe_data["signal_strength"],
                latitude=probe_data["latitude"],
                longitude=probe_data["longitude"],
                timestamp=probe_data["last_seen"],
            )
            tracker.add_probe(probe)

    # Analyze
    print("\n[*] Running persistence detection...")
    detector = PersistenceDetector(
        min_appearances=args.min_appearances, min_persistence_score=args.min_score
    )

    devices = list(tracker.devices.values())
    scores = detector.analyze_devices(devices)

    # Location analysis
    print("[*] Analyzing location clusters...")
    location_tracker = LocationTracker()
    clusters = location_tracker.create_clusters(devices)

    # Print results
    print(f"\n{'='*70}")
    print("SURVEILLANCE ANALYSIS RESULTS")
    print(f"{'='*70}")
    print(f"  Total Devices:    {len(devices)}")
    print(f"  Suspicious:       {len([s for s in scores if s.risk_level.value == 'suspicious'])}")
    print(f"  High Risk:        {len([s for s in scores if s.risk_level.value == 'high'])}")
    print(f"  Critical Threats: {len([s for s in scores if s.risk_level.value == 'critical'])}")
    print(f"  Location Clusters: {len(clusters)}")
    print(f"{'='*70}\n")

    # Show threats
    threats = [s for s in scores if s.is_threat()]
    if threats:
        print("DETECTED THREATS:\n")
        for score in threats:
            print(f"{score}")
            for reason in score.detection_reasons:
                print(f"  - {reason}")
            print()

    # Generate reports
    print("[*] Generating reports...")
    generator = ReportGenerator(output_dir=args.output_dir)

    if args.markdown or args.all_formats:
        md_file = generator.generate_report(scores, clusters, devices, ReportFormat.MARKDOWN)
        print(f"[+] Markdown: {md_file}")

    if args.html or args.all_formats:
        html_file = generator.generate_report(scores, clusters, devices, ReportFormat.HTML)
        print(f"[+] HTML: {html_file}")

    if args.kml or args.all_formats:
        kml_file = generator.generate_report(scores, clusters, devices, ReportFormat.KML)
        print(f"[+] KML: {kml_file}")

    return 0


def cmd_surveillance_wigle(args):
    """WiGLE API operations"""
    # Load credentials
    if args.setup:
        print("\n[*] WiGLE API Setup")
        print("[*] Get your API credentials from: https://wigle.net")

        api_name = input("API Name: ").strip()
        api_token = input("API Token: ").strip()

        wigle = WiGLEAPI()
        wigle.save_encrypted_credentials(args.creds_file, api_name, api_token)
        print(f"[+] Credentials saved to: {args.creds_file}")
        return 0

    # Initialize API
    wigle = WiGLEAPI(credentials_file=args.creds_file)

    if args.status:
        # Show account status
        status = wigle.get_api_status()
        if "error" in status:
            print(f"[-] {status['error']}")
            return 1

        print(f"\n[+] WiGLE Account Status:")
        print(f"  Username:       {status['username']}")
        print(f"  Rank:           {status['rank']}")
        print(f"  Daily Queries:  {status['daily_queries']}/{status['daily_limit']}")
        print(f"  Monthly Queries: {status['monthly_queries']}/{status['monthly_limit']}")

    elif args.search_ssid:
        # Search by SSID
        print(f"\n[*] Searching WiGLE for SSID: {args.search_ssid}")
        results = wigle.search_ssid(args.search_ssid, max_results=args.max_results)

        if not results:
            print("[-] No results found")
            return 0

        print(f"\n[+] Found {len(results)} results:\n")
        for i, loc in enumerate(results, 1):
            print(f"{i}. {loc}")

    elif args.search_bssid:
        # Search by BSSID
        print(f"\n[*] Searching WiGLE for BSSID: {args.search_bssid}")
        result = wigle.search_bssid(args.search_bssid)

        if not result:
            print("[-] No results found")
            return 0

        print(f"\n[+] Result:")
        print(f"  {result}")

    return 0


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="WIFUCKER - WiFi Security Suite with OpenVINO",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--no-banner", action="store_true", help="Disable banner")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Parse command
    parse_parser = subparsers.add_parser("parse", help="Parse PCAP file")
    parse_parser.add_argument("pcap", help="PCAP file to parse")
    parse_parser.add_argument("--export-hashcat", help="Export to hashcat format")
    parse_parser.add_argument("--export-john", help="Export to john format")

    # Crack command
    crack_parser = subparsers.add_parser("crack", help="Crack WiFi password")
    crack_parser.add_argument("pcap", help="PCAP file with handshakes")
    crack_parser.add_argument("wordlist", help="Password wordlist")
    crack_parser.add_argument(
        "--device", choices=["NPU", "NCS2", "GPU", "CPU"], help="Force specific device"
    )
    crack_parser.add_argument(
        "--cpu-only", action="store_true", help="Use CPU only (no acceleration)"
    )
    crack_parser.add_argument("--rules", action="store_true", help="Apply password mutation rules")
    crack_parser.add_argument("--output", "-o", help="Save result to file")

    # Generate command
    gen_parser = subparsers.add_parser("generate", help="Generate AI-powered wordlist")
    gen_parser.add_argument("ssid", help="Target SSID")
    gen_parser.add_argument("--output", "-o", help="Output file")
    gen_parser.add_argument(
        "--max-passwords", type=int, default=10000, help="Maximum passwords to generate"
    )
    gen_parser.add_argument("--min-length", type=int, default=8, help="Minimum password length")
    gen_parser.add_argument("--max-length", type=int, default=63, help="Maximum password length")
    gen_parser.add_argument("--show-sample", action="store_true", help="Show sample passwords")

    # Download command
    dl_parser = subparsers.add_parser("download", help="Download wordlists")
    dl_parser.add_argument("--all", action="store_true", help="Download all wordlists")
    dl_parser.add_argument("--source", help="Download specific wordlist")
    dl_parser.add_argument("--dir", default="./wordlists", help="Download directory")
    dl_parser.add_argument("--force", action="store_true", help="Force re-download")

    # Devices command
    dev_parser = subparsers.add_parser("devices", help="List available devices")

    # Benchmark command
    bench_parser = subparsers.add_parser("benchmark", help="Benchmark devices")
    bench_parser.add_argument(
        "--device", choices=["NPU", "NCS2", "GPU", "CPU"], help="Benchmark specific device"
    )

    # Audit command
    audit_parser = subparsers.add_parser("audit", help="Run full WiFi security audit")
    audit_parser.add_argument(
        "--auto", action="store_true", help="Run in automatic mode (runs all steps without prompts)"
    )
    audit_parser.add_argument(
        "--devices", help="Comma-separated list of devices to use (e.g., NPU,GPU)"
    )

    # Interfaces command
    iface_parser = subparsers.add_parser("interfaces", help="List wireless interfaces")

    # Optimize command
    opt_parser = subparsers.add_parser("optimize", help="Optimize adapter for maximum performance")
    opt_parser.add_argument("interface", help="Wireless interface name")
    opt_parser.add_argument("--info", action="store_true", help="Show adapter information only")
    opt_parser.add_argument(
        "--aggressive", action="store_true", help="Enable aggressive optimizations"
    )

    # Monitor mode command
    mon_parser = subparsers.add_parser("monitor", help="Enable/disable monitor mode")
    mon_parser.add_argument("action", choices=["enable", "disable"], help="Action to perform")
    mon_parser.add_argument("interface", help="Wireless interface name")

    # Capture command
    cap_parser = subparsers.add_parser("capture", help="Capture handshakes with deauth")
    cap_parser.add_argument("interface", help="Monitor mode interface (e.g., wlan0mon)")
    cap_parser.add_argument("--bssid", help="Target AP BSSID (skip scan if provided)")
    cap_parser.add_argument("--essid", help="Target ESSID name (optional, for labeling)")
    cap_parser.add_argument("--channel", type=int, help="Target channel (required with --bssid)")
    cap_parser.add_argument(
        "--scan-time", type=int, default=10, help="Network scan duration (default: 10s)"
    )
    cap_parser.add_argument(
        "--timeout", type=int, default=30, help="Capture timeout (default: 30s)"
    )
    cap_parser.add_argument(
        "--deauth-count", type=int, default=10, help="Deauth packets per burst (default: 10)"
    )
    cap_parser.add_argument(
        "--output", "-o", help="Output PCAP file (auto-generated if not specified)"
    )
    cap_parser.add_argument(
        "--output-dir", default="./captures", help="Output directory (default: ./captures)"
    )
    cap_parser.add_argument(
        "--min-power", type=int, default=-80, help="Minimum signal strength to show (default: -80)"
    )
    cap_parser.add_argument("--show-hidden", action="store_true", help="Show hidden networks")
    cap_parser.add_argument("--no-verify", action="store_true", help="Skip handshake verification")

    # Surveillance command (main parser)
    surv_parser = subparsers.add_parser("surveillance", help="Surveillance detection (defensive)")
    surv_subparsers = surv_parser.add_subparsers(
        dest="surveillance_command", help="Surveillance subcommand"
    )

    # Surveillance monitor subcommand
    surv_mon_parser = surv_subparsers.add_parser("monitor", help="Monitor Kismet for surveillance")
    surv_mon_parser.add_argument(
        "--kismet-dir", default="/var/log/kismet", help="Kismet database directory"
    )
    surv_mon_parser.add_argument(
        "--interval", type=int, default=60, help="Check interval in seconds (default: 60)"
    )
    surv_mon_parser.add_argument("--ignore-file", help="File with MAC/SSID ignore list")
    surv_mon_parser.add_argument(
        "--min-appearances", type=int, default=3, help="Minimum appearances for detection"
    )
    surv_mon_parser.add_argument(
        "--min-score", type=float, default=0.5, help="Minimum persistence score"
    )
    surv_mon_parser.add_argument("--report", action="store_true", help="Generate report on exit")
    surv_mon_parser.add_argument(
        "--report-dir", default="./surveillance_reports", help="Report output directory"
    )

    # Surveillance analyze subcommand
    surv_analyze_parser = surv_subparsers.add_parser("analyze", help="Analyze Kismet database")
    surv_analyze_parser.add_argument("database", help="Path to Kismet database file")
    surv_analyze_parser.add_argument(
        "--min-appearances", type=int, default=3, help="Minimum appearances"
    )
    surv_analyze_parser.add_argument(
        "--min-score", type=float, default=0.5, help="Minimum persistence score"
    )
    surv_analyze_parser.add_argument(
        "--output-dir", default="./surveillance_reports", help="Report output directory"
    )
    surv_analyze_parser.add_argument(
        "--markdown", action="store_true", help="Generate Markdown report"
    )
    surv_analyze_parser.add_argument("--html", action="store_true", help="Generate HTML report")
    surv_analyze_parser.add_argument(
        "--kml", action="store_true", help="Generate KML report (Google Earth)"
    )
    surv_analyze_parser.add_argument(
        "--all-formats", action="store_true", help="Generate all report formats"
    )

    # Surveillance WiGLE subcommand
    surv_wigle_parser = surv_subparsers.add_parser("wigle", help="WiGLE API operations")
    surv_wigle_parser.add_argument(
        "--setup", action="store_true", help="Configure WiGLE credentials"
    )
    surv_wigle_parser.add_argument("--status", action="store_true", help="Show API status")
    surv_wigle_parser.add_argument("--search-ssid", help="Search for SSID")
    surv_wigle_parser.add_argument("--search-bssid", help="Search for BSSID")
    surv_wigle_parser.add_argument("--max-results", type=int, default=10, help="Maximum results")
    surv_wigle_parser.add_argument(
        "--creds-file", default="~/.wigle_creds.json", help="Credentials file path"
    )

    args = parser.parse_args()

    # Show banner
    if not args.no_banner:
        print_banner()

    # Execute command
    if not args.command:
        parser.print_help()
        return 0

    try:
        if args.command == "parse":
            return cmd_parse(args)
        elif args.command == "crack":
            return cmd_crack(args)
        elif args.command == "generate":
            return cmd_generate(args)
        elif args.command == "download":
            return cmd_download(args)
        elif args.command == "devices":
            return cmd_devices(args)
        elif args.command == "benchmark":
            return cmd_benchmark(args)
        elif args.command == "audit":
            return cmd_audit(args)
        elif args.command == "interfaces":
            return cmd_interfaces(args)
        elif args.command == "optimize":
            return cmd_optimize(args)
        elif args.command == "monitor":
            return cmd_monitor(args)
        elif args.command == "capture":
            return cmd_capture(args)
        elif args.command == "surveillance":
            if args.surveillance_command == "monitor":
                return cmd_surveillance_monitor(args)
            elif args.surveillance_command == "analyze":
                return cmd_surveillance_analyze(args)
            elif args.surveillance_command == "wigle":
                return cmd_surveillance_wigle(args)
            else:
                surv_parser.print_help()
                return 0
        else:
            parser.print_help()
            return 0

    except KeyboardInterrupt:
        console.print("\n\n[warning]⚠ INTERRUPTED BY USER[/]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[error]❌ ERROR: {e}[/]")
        if "--debug" in sys.argv:
            raise
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main())
