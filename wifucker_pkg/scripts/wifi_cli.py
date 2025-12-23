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
import json
import uuid
from pathlib import Path
from typing import List, Optional, Dict, Any
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
from utils.json_formatter import JSONOutputFormatter, ExitCode, ErrorCode
from utils.progress_reporter import ProgressReporter
from utils.operation_manager import OperationManager, OperationStatus
from utils.profile_manager import ProfileManager, Profile


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
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    
    if not use_json:
        print(f"\n[*] Parsing PCAP file: {args.pcap}")

    # Check if file exists
    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        if use_json:
            print(formatter.format_error(
                command="parse",
                error_code=ErrorCode.FILE_NOT_FOUND,
                message=f"PCAP file not found: {args.pcap}",
                exit_code=ExitCode.NOT_FOUND
            ))
        else:
            print(f"[-] PCAP file not found: {args.pcap}")
        return int(ExitCode.NOT_FOUND)

    try:
        parser = PCAPParser(str(pcap_path))
        handshakes, pmkids = parser.parse()
        summary = parser.get_summary()

        # Prepare data
        handshake_data = []
        for hs in handshakes:
            handshake_data.append({
                "ssid": hs.ssid,
                "bssid": hs.bssid,
                "channel": getattr(hs, 'channel', 0),
                "handshake_type": getattr(hs, 'handshake_type', 'WPA2'),
                "valid": hs.is_complete,
                "complete": hs.is_complete
            })

        data = {
            "pcap_file": str(pcap_path),
            "handshakes": handshake_data,
            "pmkids": pmkids,
            "handshake_count": len(handshakes),
            "summary": summary
        }

        # Export if requested
        if args.export_hashcat:
            parser.export_hashcat(args.export_hashcat)
            data["export_hashcat"] = args.export_hashcat

        if args.export_john:
            parser.export_john(args.export_john)
            data["export_john"] = args.export_john

        if use_json:
            print(formatter.format_result("parse", True, data))
            return int(ExitCode.SUCCESS)

        # Text output
        print("\n" + "=" * 70)
        print("EXTRACTION SUMMARY")
        print("=" * 70)
        print(f"  Total handshakes: {summary['total_handshakes']}")
        print(f"  Complete: {summary['complete_handshakes']}")
        print(f"  PMKIDs: {summary['pmkids']}")
        print(f"  Unique networks: {summary['unique_networks']}")
        print(f"  Unique clients: {summary['unique_clients']}")
        print("=" * 70)

        if handshakes:
            print("\n[*] Extracted handshakes:")
            for i, hs in enumerate(handshakes, 1):
                complete = "✓" if hs.is_complete else "✗"
                print(f"  {i}. {hs.ssid:20s} | {hs.bssid} | {complete} Complete")

        if args.export_hashcat:
            print(f"\n[+] Exported to hashcat format: {args.export_hashcat}")
        if args.export_john:
            print(f"[+] Exported to john format: {args.export_john}")

        return int(ExitCode.SUCCESS)

    except Exception as e:
        if use_json:
            print(formatter.format_error(
                command="parse",
                error_code=ErrorCode.INVALID_PCAP,
                message=f"Failed to parse PCAP file: {str(e)}",
                details=str(e),
                exit_code=ExitCode.GENERAL_ERROR
            ))
        else:
            print(f"[-] Error parsing PCAP: {e}")
        return int(ExitCode.GENERAL_ERROR)


def cmd_crack(args):
    """Crack WiFi password from PCAP"""
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    non_interactive = getattr(args, 'non_interactive', False) or use_json
    
    if not use_json:
        print(f"\n[*] Starting WiFi cracking session")
        print(f"[*] PCAP: {args.pcap}")
        print(f"[*] Wordlist: {args.wordlist}")

    # Check files exist
    pcap_path = Path(args.pcap)
    
    if not pcap_path.exists():
        if use_json:
            print(formatter.format_error(
                command="crack",
                error_code=ErrorCode.FILE_NOT_FOUND,
                message=f"PCAP file not found: {args.pcap}",
                exit_code=ExitCode.NOT_FOUND
            ))
        else:
            print(f"[-] PCAP file not found: {args.pcap}")
        return int(ExitCode.NOT_FOUND)
    
    # Wordlist is optional if brute force is enabled
    wordlist_path = None
    if args.brute_force:
        if not use_json:
            print(f"[*] Brute force mode enabled")
    else:
        if not args.wordlist:
            if use_json:
                print(formatter.format_error(
                    command="crack",
                    error_code=ErrorCode.INVALID_ARGS,
                    message="Wordlist required unless --brute-force is specified",
                    exit_code=ExitCode.INVALID_ARGS
                ))
            else:
                print(f"[-] Wordlist required (or use --brute-force)")
            return int(ExitCode.INVALID_ARGS)
        
        wordlist_path = Path(args.wordlist)
        if not wordlist_path.exists():
            if use_json:
                print(formatter.format_error(
                    command="crack",
                    error_code=ErrorCode.FILE_NOT_FOUND,
                    message=f"Wordlist file not found: {args.wordlist}",
                    exit_code=ExitCode.NOT_FOUND
                ))
            else:
                print(f"[-] Wordlist file not found: {args.wordlist}")
            return int(ExitCode.NOT_FOUND)

    try:
        # Parse PCAP first
        parser = PCAPParser(str(pcap_path))
        handshakes, pmkids = parser.parse()

        if not handshakes:
            if use_json:
                print(formatter.format_error(
                    command="crack",
                    error_code=ErrorCode.NO_HANDSHAKES,
                    message="No complete handshakes found in PCAP",
                    suggestions=[
                        "Verify PCAP file was captured correctly",
                        "Try capturing again with --deauth-count 10"
                    ],
                    exit_code=ExitCode.NOT_FOUND
                ))
            else:
                print("[-] No complete handshakes found in PCAP")
            return int(ExitCode.NOT_FOUND)

        # Select handshake to crack
        target_hs = None
        if len(handshakes) > 1:
            # Use --handshake-index if provided, otherwise use first
            handshake_index = getattr(args, 'handshake_index', None)
            if handshake_index is not None:
                if 0 <= handshake_index < len(handshakes):
                    target_hs = handshakes[handshake_index]
                else:
                    if use_json:
                        print(formatter.format_error(
                            command="crack",
                            error_code=ErrorCode.INVALID_ARGS,
                            message=f"Invalid handshake index: {handshake_index} (valid: 0-{len(handshakes)-1})",
                            exit_code=ExitCode.INVALID_ARGS
                        ))
                    else:
                        print(f"[-] Invalid handshake index: {handshake_index}")
                    return int(ExitCode.INVALID_ARGS)
            elif non_interactive:
                # Auto-select first handshake
                target_hs = handshakes[0]
            else:
                # Interactive selection
                print("\n[*] Multiple handshakes found:")
                for i, hs in enumerate(handshakes, 1):
                    print(f"  {i}. {hs.ssid} ({hs.bssid})")

                while True:
                    try:
                        choice = input("\nSelect handshake to crack (1-{}): ".format(len(handshakes)))
                        idx = int(choice) - 1
                        if 0 <= idx < len(handshakes):
                            target_hs = handshakes[idx]
                            break
                    except (ValueError, KeyboardInterrupt):
                        print("\n[!] Cancelled")
                        return int(ExitCode.GENERAL_ERROR)
        else:
            target_hs = handshakes[0]

        if not use_json:
            print(f"\n[+] Selected target: {target_hs.ssid} ({target_hs.bssid})")

        # Initialize progress reporter
        progress_file = None
        if getattr(args, 'progress_file', None):
            progress_file = Path(args.progress_file)
            progress_file.parent.mkdir(parents=True, exist_ok=True)
        
        progress_reporter = ProgressReporter(progress_file, operation="crack")
        
        # Progress callback wrapper
        def progress_wrapper(current, total, percent, rate):
            progress_callback(current, total, percent, rate)
            progress_reporter.update(current, total, rate)

        # Initialize cracker
        device_pref = args.device if args.device else None
        cracker = OpenVINOWiFiCracker(use_hardware=not args.cpu_only, device_preference=device_pref)

        # Get EAPOL frame for proper MIC verification (message 2 or 4 with MIC)
        import struct
        eapol_frame = None
        if hasattr(target_hs, 'eapol_frames') and target_hs.eapol_frames:
            # Find EAPOL frame with MIC that matches the captured MIC
            for frame in target_hs.eapol_frames:
                if len(frame) >= 97:
                    # Check if this frame has MIC (key_info bit 7 set)
                    try:
                        key_info = struct.unpack('>H', frame[5:7])[0]
                        if key_info & 0x0100:  # MIC bit set
                            # Check if MIC in frame matches captured MIC
                            frame_mic = frame[81:97]
                            if frame_mic == target_hs.mic:
                                eapol_frame = frame
                                break
                    except:
                        pass
            # If no matching frame found, use first frame with MIC
            if not eapol_frame:
                for frame in target_hs.eapol_frames:
                    if len(frame) >= 97:
                        try:
                            key_info = struct.unpack('>H', frame[5:7])[0]
                            if key_info & 0x0100:  # MIC bit set
                                eapol_frame = frame
                                break
                        except:
                            pass
            # If still no frame with MIC found, use the last one
            if not eapol_frame and target_hs.eapol_frames:
                eapol_frame = target_hs.eapol_frames[-1]

        # Crack
        result = cracker.crack_handshake(
            ssid=target_hs.ssid,
            anonce=target_hs.anonce,
            snonce=target_hs.snonce,
            mic=target_hs.mic,
            bssid=target_hs.bssid,
            client=target_hs.client,
            wordlist_file=str(wordlist_path) if wordlist_path else None,
            progress_callback=progress_wrapper if progress_file else progress_callback,
            use_rules=args.rules,
            eapol_frame=eapol_frame,
            brute_force=args.brute_force,
            min_length=getattr(args, 'min_length', 8),
            max_length=getattr(args, 'max_length', 12),
            charset=getattr(args, 'charset', None),
            use_hashcat=getattr(args, 'use_hashcat', False),
            hashcat_only=getattr(args, 'hashcat_only', False),
        )
        
        progress_reporter.complete(result.success)

        # Prepare result data
        result_data = {
            "ssid": target_hs.ssid,
            "bssid": target_hs.bssid,
            "found": result.success,
            "attempts": result.attempts,
            "elapsed_time": result.elapsed_time,
            "rate": result.hashes_per_second,
            "device_used": result.device_used
        }
        
        if result.success:
            result_data["password"] = result.password

        if use_json:
            if result.success:
                print(formatter.format_result("crack", True, result_data))
            else:
                print(formatter.format_result(
                    "crack",
                    False,
                    result_data,
                    errors=[{
                        "code": ErrorCode.CRACK_FAILED,
                        "message": "Password not found in wordlist",
                        "suggestions": [
                            "Use a larger wordlist",
                            "Enable rules with --rules",
                            f"Generate SSID-based wordlist: wifucker generate {target_hs.ssid}",
                            "Download popular wordlists: wifucker download --all"
                        ]
                    }]
                ))
            return int(ExitCode.SUCCESS) if result.success else int(ExitCode.GENERAL_ERROR)

        # Text output
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

            return int(ExitCode.SUCCESS)
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
            print(f"  - Generate SSID-based wordlist: wifucker generate {target_hs.ssid}")
            print("  - Download popular wordlists: wifucker download --all")

            return int(ExitCode.GENERAL_ERROR)
    
    except Exception as e:
        if use_json:
            print(formatter.format_error(
                command="crack",
                error_code=ErrorCode.CRACK_FAILED,
                message=f"Cracking failed: {str(e)}",
                details=str(e),
                exit_code=ExitCode.GENERAL_ERROR
            ))
        else:
            print(f"[-] Error: {e}")
        return int(ExitCode.GENERAL_ERROR)


def cmd_generate(args):
    """Generate simple rule‑based wordlist (no AI)"""
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    
    if not use_json:
        print(f"\n[*] Generating simple wordlist for SSID: {args.ssid}")

    # Simple pattern: ssid + numbers
    passwords = []
    for i in range(1, args.max_passwords + 1):
        passwords.append(f"{args.ssid}{i:04d}")

    output = args.output if args.output else f"wordlist_{args.ssid}.txt"
    with open(output, "w") as f:
        f.write("\n".join(passwords))

    data = {
        "ssid": args.ssid,
        "output_file": output,
        "total_passwords": len(passwords),
        "max_passwords": args.max_passwords,
        "min_length": args.min_length,
        "max_length": args.max_length
    }
    
    if args.show_sample:
        data["sample_passwords"] = passwords[:20]

    if use_json:
        print(formatter.format_result("generate", True, data))
        return int(ExitCode.SUCCESS)

    print(f"\n[+] Wordlist generated: {output}")
    print(f"[+] Total passwords: {len(passwords):,}")
    if args.show_sample:
        print("\n[*] Sample passwords (first 20):")
        for i, pwd in enumerate(passwords[:20], 1):
            print(f"  {i:2d}. {pwd}")

    return int(ExitCode.SUCCESS)


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
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    
    if not use_json:
        print("\n[*] Detecting available hardware accelerators...")

    detector = HardwareDetector()
    devices = detector.detect_devices()

    device_data = []
    for device in devices:
        device_data.append({
            "device_type": device.device_type.name,
            "device_name": device.device_name,
            "available": device.available,
            "capabilities": getattr(device, 'capabilities', {})
        })

    multi_config = detector.get_multi_device_config()
    
    data = {
        "devices": device_data,
        "device_count": len(devices),
        "multi_device_config": multi_config
    }

    if use_json:
        print(formatter.format_result("devices", True, data))
        return int(ExitCode.SUCCESS)

    # Show multi-device config if available
    if multi_config:
        print(f"\n[+] Multi-device execution available: {multi_config}")

    return int(ExitCode.SUCCESS)


def cmd_benchmark(args):
    """Benchmark hardware devices"""
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    
    if not use_json:
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
            if use_json:
                print(formatter.format_error(
                    command="benchmark",
                    error_code=ErrorCode.DEVICE_NOT_FOUND,
                    message=f"Device not found: {args.device}",
                    exit_code=ExitCode.NOT_FOUND
                ))
            else:
                print(f"[-] Device not found: {args.device}")
            return int(ExitCode.NOT_FOUND)

        if not use_json:
            print(f"\n[*] Benchmarking: {target_device.device_name}")
            print("[!] Note: Actual benchmark requires a model file")
        
        data = {
            "device": {
                "type": target_device.device_type.name,
                "name": target_device.device_name
            },
            "note": "Actual benchmark requires a model file"
        }
    else:
        # Benchmark all devices
        if not use_json:
            print("[*] Benchmarking all available devices...")
        
        data = {
            "devices": [{"type": d.device_type.name, "name": d.device_name} for d in devices],
            "note": "Actual benchmark requires a model file"
        }

    if use_json:
        print(formatter.format_result("benchmark", True, data))
        return int(ExitCode.SUCCESS)

    return int(ExitCode.SUCCESS)


def cmd_interfaces(args):
    """List wireless interfaces"""
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    
    if not use_json:
        print("\n[*] Detecting wireless interfaces...")

    monitor = MonitorMode()

    # Check requirements
    all_present, missing, optional_missing = monitor.check_requirements()

    if not all_present:
        if use_json:
            print(formatter.format_error(
                command="interfaces",
                error_code=ErrorCode.MISSING_TOOLS,
                message="Missing required tools",
                details={"missing": missing},
                suggestions=["Install with: sudo apt install wireless-tools iw net-tools"],
                exit_code=ExitCode.GENERAL_ERROR
            ))
        else:
            print("\n[-] Missing required tools:")
            for tool in missing:
                print(f"    - {tool}")
            print("\n[!] Install with: sudo apt install wireless-tools iw net-tools")
        return int(ExitCode.GENERAL_ERROR)

    if optional_missing and not use_json:
        print("\n[!] Optional tools not found (recommended for full functionality):")
        for tool in optional_missing:
            print(f"    - {tool}")
        print("[!] Install with: sudo apt install aircrack-ng")
        print()

    # Detect interfaces
    interfaces = monitor.detect_interfaces()

    if not interfaces:
        if use_json:
            print(formatter.format_error(
                command="interfaces",
                error_code=ErrorCode.NO_INTERFACES,
                message="No wireless interfaces found",
                exit_code=ExitCode.NOT_FOUND
            ))
        else:
            print("[-] No wireless interfaces found")
        return int(ExitCode.NOT_FOUND)

    data = {
        "interfaces": interfaces,
        "count": len(interfaces),
        "requirements": {
            "all_present": all_present,
            "missing": missing,
            "optional_missing": optional_missing
        }
    }

    if use_json:
        print(formatter.format_result("interfaces", True, data))
        return int(ExitCode.SUCCESS)

    # Display interfaces
    print("\n" + "=" * 80)
    print("WIRELESS INTERFACES")
    print("=" * 80)

    for iface in interfaces:
        print(f"  {iface}")

    print("=" * 80)
    print(f"\nFound {len(interfaces)} wireless interface(s)")
    print(f"\n[*] Tip: Use 'wifucker optimize <interface>' to maximize performance")

    return int(ExitCode.SUCCESS)


# Operation Management Commands
def cmd_operation_status(args):
    """Get operation status"""
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    
    manager = OperationManager()
    operation = manager.get_operation(args.operation_id)
    
    if not operation:
        if use_json:
            print(formatter.format_error(
                command="operation status",
                error_code=ErrorCode.NOT_FOUND,
                message=f"Operation not found: {args.operation_id}",
                exit_code=ExitCode.NOT_FOUND
            ))
        else:
            print(f"[-] Operation not found: {args.operation_id}")
        return int(ExitCode.NOT_FOUND)
    
    data = {
        "id": operation.id,
        "command": operation.command,
        "status": operation.status.value,
        "created": operation.created,
        "started": operation.started,
        "completed": operation.completed,
        "result": operation.result,
        "error": operation.error,
        "pid": operation.pid
    }
    
    if use_json:
        print(formatter.format_result("operation status", True, data))
        return int(ExitCode.SUCCESS)
    
    print(f"\nOperation: {operation.id}")
    print(f"Command: {operation.command}")
    print(f"Status: {operation.status.value}")
    print(f"Created: {operation.created}")
    if operation.started:
        print(f"Started: {operation.started}")
    if operation.completed:
        print(f"Completed: {operation.completed}")
    if operation.error:
        print(f"Error: {operation.error}")
    if operation.result:
        print(f"Result: {json.dumps(operation.result, indent=2)}")
    
    return int(ExitCode.SUCCESS)


def cmd_operation_list(args):
    """List operations"""
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    
    manager = OperationManager()
    status_filter = None
    if getattr(args, 'status', None):
        status_filter = OperationStatus(args.status)
    
    operations = manager.list_operations(status_filter)
    
    data = {
        "operations": [{
            "id": op.id,
            "command": op.command,
            "status": op.status.value,
            "created": op.created,
            "started": op.started,
            "completed": op.completed
        } for op in operations],
        "count": len(operations)
    }
    
    if use_json:
        print(formatter.format_result("operation list", True, data))
        return int(ExitCode.SUCCESS)
    
    if operations:
        print("\nOperations:")
        print("=" * 80)
        for op in operations:
            print(f"  {op.id[:8]}... | {op.command:15s} | {op.status.value:10s} | {op.created}")
        print("=" * 80)
    else:
        print("No operations found")
    
    return int(ExitCode.SUCCESS)


def cmd_operation_cancel(args):
    """Cancel operation"""
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    
    manager = OperationManager()
    success = manager.cancel_operation(args.operation_id)
    
    if not success:
        if use_json:
            print(formatter.format_error(
                command="operation cancel",
                error_code=ErrorCode.OPERATION_CANCEL_FAILED,
                message=f"Failed to cancel operation: {args.operation_id}",
                exit_code=ExitCode.GENERAL_ERROR
            ))
        else:
            print(f"[-] Failed to cancel operation: {args.operation_id}")
        return int(ExitCode.GENERAL_ERROR)
    
    if use_json:
        print(formatter.format_result("operation cancel", True, {"operation_id": args.operation_id}))
        return int(ExitCode.SUCCESS)
    
    print(f"[+] Operation cancelled: {args.operation_id}")
    return int(ExitCode.SUCCESS)


def cmd_operation_cleanup(args):
    """Cleanup old operations"""
    manager = OperationManager()
    days = getattr(args, 'days', 7)
    manager.cleanup_old_operations(days)
    print(f"[+] Cleaned up operations older than {days} days")
    return int(ExitCode.SUCCESS)


# Profile Management Commands
def cmd_profile_save(args):
    """Save profile"""
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    
    manager = ProfileManager()
    
    # Parse args if provided as JSON string
    profile_args = {}
    if getattr(args, 'args', None):
        try:
            profile_args = json.loads(args.args)
        except json.JSONDecodeError:
            if use_json:
                print(formatter.format_error(
                    command="profile save",
                    error_code=ErrorCode.INVALID_ARGS,
                    message="Invalid JSON in --args",
                    exit_code=ExitCode.INVALID_ARGS
                ))
            else:
                print("[-] Invalid JSON in --args")
            return int(ExitCode.INVALID_ARGS)
    
    profile = manager.create_from_args(
        name=args.name,
        command=args.command,
        args=profile_args,
        description=getattr(args, 'description', None)
    )
    
    if use_json:
        print(formatter.format_result("profile save", True, {
            "name": profile.name,
            "command": profile.command,
            "description": profile.description
        }))
        return int(ExitCode.SUCCESS)
    
    print(f"[+] Profile saved: {profile.name}")
    return int(ExitCode.SUCCESS)


def cmd_profile_load(args):
    """Load and execute profile"""
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    
    manager = ProfileManager()
    profile = manager.get_profile(args.name)
    
    if not profile:
        if use_json:
            print(formatter.format_error(
                command="profile load",
                error_code=ErrorCode.NOT_FOUND,
                message=f"Profile not found: {args.name}",
                exit_code=ExitCode.NOT_FOUND
            ))
        else:
            print(f"[-] Profile not found: {args.name}")
        return int(ExitCode.NOT_FOUND)
    
    # Create args object from profile
    class ProfileArgs:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    
    profile_args = ProfileArgs(**profile.args)
    profile_args.json = use_json
    
    # Route to appropriate command handler
    command_handlers = {
        "scan": cmd_scan,
        "capture": cmd_capture,
        "crack": cmd_crack,
        "parse": cmd_parse,
        "audit": cmd_audit,
        "generate": cmd_generate
    }
    
    if profile.command not in command_handlers:
        if use_json:
            print(formatter.format_error(
                command="profile load",
                error_code=ErrorCode.INVALID_ARGS,
                message=f"Unsupported command in profile: {profile.command}",
                exit_code=ExitCode.INVALID_ARGS
            ))
        else:
            print(f"[-] Unsupported command: {profile.command}")
        return int(ExitCode.INVALID_ARGS)
    
    return command_handlers[profile.command](profile_args)


def cmd_profile_list(args):
    """List profiles"""
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    
    manager = ProfileManager()
    profiles = manager.list_profiles()
    
    data = {
        "profiles": [{
            "name": p.name,
            "command": p.command,
            "description": p.description
        } for p in profiles],
        "count": len(profiles)
    }
    
    if use_json:
        print(formatter.format_result("profile list", True, data))
        return int(ExitCode.SUCCESS)
    
    if profiles:
        print("\nProfiles:")
        print("=" * 80)
        for p in profiles:
            desc = f" - {p.description}" if p.description else ""
            print(f"  {p.name:20s} | {p.command:15s}{desc}")
        print("=" * 80)
    else:
        print("No profiles found")
    
    return int(ExitCode.SUCCESS)


def cmd_profile_delete(args):
    """Delete profile"""
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    
    manager = ProfileManager()
    success = manager.delete_profile(args.name)
    
    if not success:
        if use_json:
            print(formatter.format_error(
                command="profile delete",
                error_code=ErrorCode.NOT_FOUND,
                message=f"Profile not found: {args.name}",
                exit_code=ExitCode.NOT_FOUND
            ))
        else:
            print(f"[-] Profile not found: {args.name}")
        return int(ExitCode.NOT_FOUND)
    
    if use_json:
        print(formatter.format_result("profile delete", True, {"name": args.name}))
        return int(ExitCode.SUCCESS)
    
    print(f"[+] Profile deleted: {args.name}")
    return int(ExitCode.SUCCESS)


# Batch Operations Command
def cmd_batch(args):
    """Run batch operations"""
    import subprocess
    import threading
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    
    # Load batch file
    batch_file = Path(args.file)
    if not batch_file.exists():
        if use_json:
            print(formatter.format_error(
                command="batch",
                error_code=ErrorCode.FILE_NOT_FOUND,
                message=f"Batch file not found: {args.file}",
                exit_code=ExitCode.NOT_FOUND
            ))
        else:
            print(f"[-] Batch file not found: {args.file}")
        return int(ExitCode.NOT_FOUND)
    
    try:
        batch_data = json.loads(batch_file.read_text())
        operations = batch_data.get("operations", [])
    except Exception as e:
        if use_json:
            print(formatter.format_error(
                command="batch",
                error_code=ErrorCode.INVALID_ARGS,
                message=f"Invalid batch file: {str(e)}",
                exit_code=ExitCode.INVALID_ARGS
            ))
        else:
            print(f"[-] Invalid batch file: {str(e)}")
        return int(ExitCode.INVALID_ARGS)
    
    if not operations:
        if use_json:
            print(formatter.format_error(
                command="batch",
                error_code=ErrorCode.INVALID_ARGS,
                message="No operations in batch file",
                exit_code=ExitCode.INVALID_ARGS
            ))
        else:
            print("[-] No operations in batch file")
        return int(ExitCode.INVALID_ARGS)
    
    # Progress reporter
    progress_file = None
    if getattr(args, 'progress_file', None):
        progress_file = Path(args.progress_file)
        progress_file.parent.mkdir(parents=True, exist_ok=True)
    
    progress_reporter = ProgressReporter(progress_file, operation="batch")
    
    results = []
    errors = []
    
    def run_operation(op_data):
        """Run single operation"""
        op_id = op_data.get("id", str(uuid.uuid4()))
        command = op_data.get("command")
        op_args = op_data.get("args", {})
        
        # Build command line
        cmd = ["python3", sys.argv[0], command]
        for key, value in op_args.items():
            if isinstance(value, bool) and value:
                cmd.append(f"--{key}")
            elif not isinstance(value, bool):
                cmd.extend([f"--{key}", str(value)])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            return {
                "id": op_id,
                "command": command,
                "success": result.returncode == 0,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        except subprocess.TimeoutExpired:
            return {
                "id": op_id,
                "command": command,
                "success": False,
                "error": "Operation timed out"
            }
        except Exception as e:
            return {
                "id": op_id,
                "command": command,
                "success": False,
                "error": str(e)
            }
    
    # Execute operations
    if args.parallel:
        # Parallel execution
        max_workers = args.max_parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(run_operation, op): op for op in operations}
            
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                if not result["success"]:
                    errors.append(result)
                    if args.stop_on_error:
                        # Cancel remaining operations
                        for f in futures:
                            f.cancel()
                        break
                
                progress_reporter.update(len(results), len(operations))
    else:
        # Sequential execution
        for i, op in enumerate(operations):
            result = run_operation(op)
            results.append(result)
            if not result["success"]:
                errors.append(result)
                if args.stop_on_error:
                    break
            
            progress_reporter.update(i + 1, len(operations))
    
    progress_reporter.complete(len(errors) == 0)
    
    data = {
        "total": len(operations),
        "completed": len(results),
        "successful": len([r for r in results if r["success"]]),
        "failed": len(errors),
        "results": results
    }
    
    if use_json:
        print(formatter.format_result("batch", len(errors) == 0, data))
        return int(ExitCode.SUCCESS) if len(errors) == 0 else int(ExitCode.GENERAL_ERROR)
    
    print(f"\nBatch execution complete:")
    print(f"  Total: {len(operations)}")
    print(f"  Successful: {len([r for r in results if r['success']])}")
    print(f"  Failed: {len(errors)}")
    
    if errors:
        print("\nErrors:")
        for err in errors:
            print(f"  {err['id']}: {err.get('error', 'Unknown error')}")
    
    return int(ExitCode.SUCCESS) if len(errors) == 0 else int(ExitCode.GENERAL_ERROR)


# Workflow Commands
def cmd_workflow_run(args):
    """Run workflow"""
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    
    # Load workflow
    workflows_dir = Path.home() / ".wifucker" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    workflow_file = workflows_dir / f"{args.name}.json"
    
    if not workflow_file.exists():
        # Check predefined workflows
        predefined = get_predefined_workflows()
        if args.name not in predefined:
            if use_json:
                print(formatter.format_error(
                    command="workflow run",
                    error_code=ErrorCode.NOT_FOUND,
                    message=f"Workflow not found: {args.name}",
                    exit_code=ExitCode.NOT_FOUND
                ))
            else:
                print(f"[-] Workflow not found: {args.name}")
            return int(ExitCode.NOT_FOUND)
        workflow_data = predefined[args.name]
    else:
        try:
            workflow_data = json.loads(workflow_file.read_text())
        except Exception as e:
            if use_json:
                print(formatter.format_error(
                    command="workflow run",
                    error_code=ErrorCode.INVALID_ARGS,
                    message=f"Invalid workflow file: {str(e)}",
                    exit_code=ExitCode.INVALID_ARGS
                ))
            else:
                print(f"[-] Invalid workflow file: {str(e)}")
            return int(ExitCode.INVALID_ARGS)
    
    # Parse workflow arguments
    workflow_args = {}
    if getattr(args, 'args', None):
        try:
            workflow_args = json.loads(args.args)
        except json.JSONDecodeError:
            if use_json:
                print(formatter.format_error(
                    command="workflow run",
                    error_code=ErrorCode.INVALID_ARGS,
                    message="Invalid JSON in --args",
                    exit_code=ExitCode.INVALID_ARGS
                ))
            else:
                print("[-] Invalid JSON in --args")
            return int(ExitCode.INVALID_ARGS)
    
    # Merge workflow args with provided args
    workflow_args = {**workflow_data.get("default_args", {}), **workflow_args}
    
    # Execute workflow steps
    steps = workflow_data.get("steps", [])
    if not steps:
        if use_json:
            print(formatter.format_error(
                command="workflow run",
                error_code=ErrorCode.INVALID_ARGS,
                message="Workflow has no steps",
                exit_code=ExitCode.INVALID_ARGS
            ))
        else:
            print("[-] Workflow has no steps")
        return int(ExitCode.INVALID_ARGS)
    
    # Progress reporter
    progress_file = None
    if getattr(args, 'progress_file', None):
        progress_file = Path(args.progress_file)
        progress_file.parent.mkdir(parents=True, exist_ok=True)
    
    progress_reporter = ProgressReporter(progress_file, operation=f"workflow_{args.name}")
    
    results = []
    for i, step in enumerate(steps):
        step_type = step.get("type")
        step_command = step.get("command")
        step_args = step.get("args", {})
        
        # Substitute workflow args
        for key, value in step_args.items():
            if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
                arg_name = value[2:-1]
                step_args[key] = workflow_args.get(arg_name, value)
        
        if step_type == "command":
            # Execute command
            class StepArgs:
                def __init__(self, **kwargs):
                    for k, v in kwargs.items():
                        setattr(self, k, v)
            
            step_args_obj = StepArgs(**step_args)
            step_args_obj.json = use_json
            
            command_handlers = {
                "scan": cmd_scan,
                "capture": cmd_capture,
                "crack": cmd_crack,
                "parse": cmd_parse,
                "audit": cmd_audit,
                "generate": cmd_generate
            }
            
            if step_command in command_handlers:
                result_code = command_handlers[step_command](step_args_obj)
                results.append({
                    "step": i + 1,
                    "command": step_command,
                    "success": result_code == 0
                })
                if result_code != 0 and step.get("stop_on_error", True):
                    break
            else:
                results.append({
                    "step": i + 1,
                    "command": step_command,
                    "success": False,
                    "error": "Unknown command"
                })
                break
        
        progress_reporter.update(i + 1, len(steps))
    
    progress_reporter.complete(all(r.get("success", False) for r in results))
    
    data = {
        "workflow": args.name,
        "steps": len(steps),
        "completed": len(results),
        "successful": len([r for r in results if r.get("success", False)]),
        "results": results
    }
    
    if use_json:
        print(formatter.format_result("workflow run", all(r.get("success", False) for r in results), data))
        return int(ExitCode.SUCCESS) if all(r.get("success", False) for r in results) else int(ExitCode.GENERAL_ERROR)
    
    print(f"\nWorkflow '{args.name}' complete:")
    print(f"  Steps: {len(steps)}")
    print(f"  Successful: {len([r for r in results if r.get('success', False)])}")
    
    return int(ExitCode.SUCCESS) if all(r.get("success", False) for r in results) else int(ExitCode.GENERAL_ERROR)


def cmd_workflow_list(args):
    """List workflows"""
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    
    workflows_dir = Path.home() / ".wifucker" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    
    # Get predefined workflows
    predefined = get_predefined_workflows()
    
    # Get custom workflows
    custom = {}
    for workflow_file in workflows_dir.glob("*.json"):
        try:
            workflow_data = json.loads(workflow_file.read_text())
            custom[workflow_file.stem] = {
                "name": workflow_file.stem,
                "description": workflow_data.get("description", ""),
                "type": "custom"
            }
        except Exception:
            continue
    
    workflows = {**predefined, **custom}
    
    data = {
        "workflows": [{
            "name": name,
            "description": wf.get("description", ""),
            "type": wf.get("type", "custom")
        } for name, wf in workflows.items()],
        "count": len(workflows)
    }
    
    if use_json:
        print(formatter.format_result("workflow list", True, data))
        return int(ExitCode.SUCCESS)
    
    if workflows:
        print("\nWorkflows:")
        print("=" * 80)
        for name, wf in workflows.items():
            wf_type = wf.get("type", "custom")
            desc = f" - {wf.get('description', '')}" if wf.get('description') else ""
            print(f"  {name:20s} | {wf_type:10s}{desc}")
        print("=" * 80)
    else:
        print("No workflows found")
    
    return int(ExitCode.SUCCESS)


def cmd_workflow_create(args):
    """Create workflow"""
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    
    workflows_dir = Path.home() / ".wifucker" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    
    workflow_file = Path(args.file)
    if not workflow_file.exists():
        if use_json:
            print(formatter.format_error(
                command="workflow create",
                error_code=ErrorCode.FILE_NOT_FOUND,
                message=f"Workflow file not found: {args.file}",
                exit_code=ExitCode.NOT_FOUND
            ))
        else:
            print(f"[-] Workflow file not found: {args.file}")
        return int(ExitCode.NOT_FOUND)
    
    try:
        workflow_data = json.loads(workflow_file.read_text())
        if getattr(args, 'description', None):
            workflow_data["description"] = args.description
        
        output_file = workflows_dir / f"{args.name}.json"
        output_file.write_text(json.dumps(workflow_data, indent=2))
    except Exception as e:
        if use_json:
            print(formatter.format_error(
                command="workflow create",
                error_code=ErrorCode.INVALID_ARGS,
                message=f"Invalid workflow file: {str(e)}",
                exit_code=ExitCode.INVALID_ARGS
            ))
        else:
            print(f"[-] Invalid workflow file: {str(e)}")
        return int(ExitCode.INVALID_ARGS)
    
    if use_json:
        print(formatter.format_result("workflow create", True, {"name": args.name}))
        return int(ExitCode.SUCCESS)
    
    print(f"[+] Workflow created: {args.name}")
    return int(ExitCode.SUCCESS)


def get_predefined_workflows():
    """Get predefined workflows"""
    return {
        "full_audit": {
            "description": "Complete WiFi security audit",
            "type": "predefined",
            "default_args": {},
            "steps": [
                {"type": "command", "command": "scan", "args": {"interface": "${interface}", "duration": 10}},
                {"type": "command", "command": "capture", "args": {"interface": "${interface}", "target_ssid": "${target_ssid}"}},
                {"type": "command", "command": "parse", "args": {"pcap": "${pcap_file}"}},
                {"type": "command", "command": "generate", "args": {"ssid": "${target_ssid}"}},
                {"type": "command", "command": "crack", "args": {"pcap": "${pcap_file}", "wordlist": "${wordlist_file}"}}
            ]
        },
        "quick_scan": {
            "description": "Quick network scan",
            "type": "predefined",
            "default_args": {},
            "steps": [
                {"type": "command", "command": "scan", "args": {"interface": "${interface}", "duration": 5}}
            ]
        }
    }


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
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    non_interactive = getattr(args, 'auto', False) or use_json or getattr(args, 'non_interactive', False)
    
    if not use_json:
        print(f"\n[*] Starting Full WiFi Security Audit")
        print(f"[*] Mode: {'Automatic' if args.auto else 'Interactive'}")

    # Step 1: Hardware Detection
    if not use_json:
        print("\n[Phase 1] Hardware Detection")
    detector = HardwareDetector()
    devices = detector.detect_devices()
    
    device_data = []
    if devices:
        for dev in devices:
            device_data.append({
                "name": dev.device_name,
                "type": dev.device_type.name
            })
        if not use_json:
            print(f"[+] Found {len(devices)} accelerator(s):")
            for dev in devices:
                print(f"  - {dev.device_name} ({dev.device_type.name})")
    else:
        if not use_json:
            print("[-] No hardware accelerators found. Using CPU.")

    # Step 2: Interface Selection
    if not use_json:
        print("\n[Phase 2] Interface Selection")
    monitor = MonitorMode()
    interfaces = monitor.detect_interfaces()
    if not interfaces:
        if use_json:
            print(formatter.format_error(
                command="audit",
                error_code=ErrorCode.INTERFACE_NOT_FOUND,
                message="No wireless interfaces found",
                exit_code=ExitCode.NOT_FOUND
            ))
        else:
            print("[-] No wireless interfaces found")
        return int(ExitCode.NOT_FOUND)

    selected_interface = None
    interface_name = getattr(args, 'interface', None)
    
    if interface_name:
        # Use provided interface
        iface_names = [iface.name if hasattr(iface, 'name') else str(iface) for iface in interfaces]
        if interface_name in iface_names:
            selected_interface = interface_name
        else:
            if use_json:
                print(formatter.format_error(
                    command="audit",
                    error_code=ErrorCode.INTERFACE_NOT_FOUND,
                    message=f"Interface not found: {interface_name}",
                    exit_code=ExitCode.NOT_FOUND
                ))
            else:
                print(f"[-] Interface not found: {interface_name}")
            return int(ExitCode.NOT_FOUND)
    elif args.auto or non_interactive:
        # Pick first capable interface
        selected_interface = interfaces[0].name if hasattr(interfaces[0], 'name') else str(interfaces[0])
        if not use_json:
            print(f"[*] Auto-selected interface: {selected_interface}")
    else:
        # Interactive selection
        print("[*] Available interfaces:")
        for i, iface in enumerate(interfaces, 1):
            iface_str = iface.name if hasattr(iface, 'name') else str(iface)
            print(f"  {i}. {iface_str}")

        while not selected_interface:
            try:
                choice = int(input("Select interface (number): "))
                if 1 <= choice <= len(interfaces):
                    iface = interfaces[choice - 1]
                    selected_interface = iface.name if hasattr(iface, 'name') else str(iface)
            except ValueError:
                pass

    # Ensure monitor mode
    if not use_json:
        print(f"[*] Enabling monitor mode on {selected_interface}...")
    success, msg, mon_iface = monitor.enable_monitor_mode(selected_interface)
    if not success:
        if use_json:
            print(formatter.format_error(
                command="audit",
                error_code=ErrorCode.MONITOR_MODE_FAILED,
                message=f"Failed to enable monitor mode: {msg}",
                suggestions=[
                    "Ensure you have root privileges",
                    "Check interface is not in use",
                    "Try: sudo wifucker monitor enable " + selected_interface
                ],
                exit_code=ExitCode.GENERAL_ERROR
            ))
        else:
            print(f"[-] Failed to enable monitor mode: {msg}")
        return int(ExitCode.GENERAL_ERROR)
    if not use_json:
        print(f"[+] Monitor mode enabled: {mon_iface}")

    # Step 3: Target Selection & Capture
    if not use_json:
        print("\n[Phase 3] Target Selection & Capture")

    capture = HandshakeCapture(interface=mon_iface, output_dir="./captures")

    target_network = None
    target_ssid = getattr(args, 'target_ssid', None)
    target_bssid = getattr(args, 'target_bssid', None)
    scan_duration = getattr(args, 'scan_duration', 10)
    
    from capture.network_scanner import NetworkScanner
    scanner = NetworkScanner(mon_iface)
    
    if not use_json:
        print(f"[*] Scanning for targets ({scan_duration}s)...")
    networks = scanner.scan(duration=scan_duration)
    
    if not networks:
        if use_json:
            print(formatter.format_error(
                command="audit",
                error_code=ErrorCode.NETWORK_ERROR,
                message="No networks found during scan",
                suggestions=[
                    "Check interface is in monitor mode",
                    "Try increasing scan duration",
                    "Verify networks are in range"
                ],
                exit_code=ExitCode.NETWORK_ERROR
            ))
        else:
            print("[-] No networks found")
        return int(ExitCode.NETWORK_ERROR)
    
    # Select target network
    if target_bssid:
        target_network = next((n for n in networks if n.bssid == target_bssid), None)
        if not target_network:
            if use_json:
                print(formatter.format_error(
                    command="audit",
                    error_code=ErrorCode.NETWORK_ERROR,
                    message=f"Target network with BSSID {target_bssid} not found",
                    exit_code=ExitCode.NOT_FOUND
                ))
            else:
                print(f"[-] Target network {target_bssid} not found")
            return int(ExitCode.NOT_FOUND)
    elif target_ssid:
        target_network = next((n for n in networks if n.essid == target_ssid), None)
        if not target_network:
            if use_json:
                print(formatter.format_error(
                    command="audit",
                    error_code=ErrorCode.NETWORK_ERROR,
                    message=f"Target network with SSID {target_ssid} not found",
                    exit_code=ExitCode.NOT_FOUND
                ))
            else:
                print(f"[-] Target network {target_ssid} not found")
            return int(ExitCode.NOT_FOUND)
    elif args.auto or non_interactive:
        # Auto-select strongest signal
        target_network = max(networks, key=lambda n: n.power)
        if not use_json:
            print(f"[+] Auto-selected target: {target_network.essid} ({target_network.bssid})")
    else:
        # Interactive selection
        print(f"\nFound {len(networks)} networks:")
        sorted_networks = sorted(networks, key=lambda n: n.power, reverse=True)
        for i, net in enumerate(sorted_networks[:10], 1):
            print(
                f"  {i}. {net.essid:<20} | {net.bssid} | CH {net.channel:>2} | {net.power} dBm"
            )

        # Auto-select if in non-interactive mode or --auto flag
        if use_json or getattr(args, 'auto', False):
            if sorted_networks:
                target_network = sorted_networks[0]  # Select strongest signal
                if not use_json:
                    print(f"[+] Auto-selected: {target_network.essid} ({target_network.bssid})")
            else:
                if use_json:
                    print(formatter.format_error(
                        command="audit",
                        error_code=ErrorCode.NETWORK_ERROR,
                        message="No networks found",
                        exit_code=ExitCode.NETWORK_ERROR
                    ))
                else:
                    print("[-] No networks found")
                return int(ExitCode.NETWORK_ERROR)
        else:
            # Interactive selection (only if not in JSON mode)
            while not target_network:
                try:
                    choice = int(input("Select target (number): "))
                    if 1 <= choice <= len(sorted_networks):
                        target_network = sorted_networks[choice - 1]
                except ValueError:
                    pass
                except (EOFError, KeyboardInterrupt):
                    if use_json:
                        print(formatter.format_error(
                            command="audit",
                            error_code=ErrorCode.CANCELLED,
                            message="Operation cancelled by user",
                            exit_code=ExitCode.CANCELLED
                        ))
                    return int(ExitCode.CANCELLED)

    capture_duration = getattr(args, 'capture_duration', 60)
    deauth_count = getattr(args, 'deauth_count', 5)
    
    if not use_json:
        print(f"[*] Capturing handshake for {target_network.essid}...")
    result = capture.capture_handshake(
        target=target_network,
        capture_duration=capture_duration,
        deauth_count=deauth_count
    )

    if not result.success:
        if use_json:
            print(formatter.format_error(
                command="audit",
                error_code=ErrorCode.CAPTURE_FAILED,
                message=f"Capture failed: {result.message}",
                suggestions=[
                    "Ensure target network has active clients",
                    f"Try increasing capture duration (current: {capture_duration}s)",
                    f"Try increasing deauth count (current: {deauth_count})"
                ],
                exit_code=ExitCode.GENERAL_ERROR
            ))
        else:
            print(f"[-] Capture failed: {result.message}")
        return int(ExitCode.GENERAL_ERROR)

    if not use_json:
        print(f"[+] Handshake captured: {result.pcap_file}")

    # Step 4: Parsing
    if not use_json:
        print("\n[Phase 4] Verifying Handshake")
    parser = PCAPParser(result.pcap_file)
    handshakes, pmkids = parser.parse()
    if not handshakes:
        if use_json:
            print(formatter.format_error(
                command="audit",
                error_code=ErrorCode.NO_HANDSHAKES,
                message="Verification failed: No valid handshakes found in capture",
                exit_code=ExitCode.NOT_FOUND
            ))
        else:
            print("[-] Verification failed: No valid handshakes found in capture")
        return int(ExitCode.NOT_FOUND)
    if not use_json:
        print(f"[+] Verified {len(handshakes)} handshake(s)")

    # Step 5: Wordlist Generation (Rule-based, NO AI)
    if not use_json:
        print("\n[Phase 5] Wordlist Generation")
    wordlist_file = f"wordlists/{target_network.essid}_gen.txt"
    os.makedirs("wordlists", exist_ok=True)

    if not use_json:
        print(f"[*] Generating rule-based wordlist for {target_network.essid}...")
    passwords = []
    base_ssid = target_network.essid.strip()
    for i in range(0, 10000):
        passwords.append(f"{base_ssid}{i}")
        passwords.append(f"{base_ssid}{i:04d}")

    with open(wordlist_file, "w") as f:
        f.write("\n".join(passwords))
    if not use_json:
        print(f"[+] Generated {len(passwords)} candidates in {wordlist_file}")

    # Step 6: Cracking
    if not use_json:
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

    if not use_json:
        print(f"[*] Using device: {selected_device}")

    cracker = OpenVINOWiFiCracker(device=selected_device)
    target_hs = next((hs for hs in handshakes if hs.bssid == target_network.bssid), handshakes[0])

    if not use_json:
        print(f"[*] Cracking {target_hs.ssid} ({target_hs.bssid})...")
    
    # Progress reporter for cracking
    progress_file = None
    if getattr(args, 'progress_file', None):
        progress_file = Path(args.progress_file)
        progress_file.parent.mkdir(parents=True, exist_ok=True)
    
    progress_reporter = ProgressReporter(progress_file, operation="audit_crack")
    
    def crack_progress_wrapper(current, total, percent, rate):
        progress_callback(current, total, percent, rate)
        progress_reporter.update(current, total, rate)
    
    crack_result = cracker.crack(target_hs, wordlist_file, rules=True, callback=crack_progress_wrapper if progress_file else progress_callback)
    progress_reporter.complete(crack_result.found)

    # Step 7: Reporting
    if not use_json:
        print("\n[Phase 7] Generating Report")

    report_path = os.path.abspath(f"reports/audit_{target_network.essid}_{int(time.time())}.md")
    os.makedirs("reports", exist_ok=True)
    with open(report_path, "w") as f:
        f.write(f"# WiFi Audit Report: {target_network.essid}\n")
        f.write(f"**Date:** {time.ctime()}\n")
        f.write(f"**Target:** {target_network.essid} ({target_network.bssid})\n")
        f.write(f"**Interface:** {mon_iface}\n")
        f.write(f"**Device Used:** {selected_device}\n")
        f.write(f"**Result:** {'SUCCESS' if crack_result.found else 'FAILURE'}\n")
        if crack_result.found:
            f.write(f"**Password:** `{crack_result.password}`\n")
        f.write(f"**Time Elapsed:** {crack_result.elapsed_time:.2f}s\n")
        f.write(f"**Attempts:** {crack_result.attempts}\n")

    if not use_json:
        print(f"[+] Report saved to: {report_path}")
        print("\n[+] Audit Complete!")

    # JSON output
    if use_json:
        audit_data = {
            "interface": mon_iface,
            "target_network": {
                "essid": target_network.essid,
                "bssid": target_network.bssid,
                "channel": target_network.channel,
                "power": target_network.power
            },
            "devices": device_data,
            "device_used": selected_device,
            "pcap_file": result.pcap_file,
            "handshakes_captured": len(handshakes),
            "wordlist_file": wordlist_file,
            "wordlist_size": len(passwords),
            "crack_result": {
                "found": crack_result.found,
                "attempts": crack_result.attempts,
                "elapsed_time": crack_result.elapsed_time,
                "rate": getattr(crack_result, 'hashes_per_second', 0)
            },
            "report_file": report_path
        }
        
        if crack_result.found:
            audit_data["crack_result"]["password"] = crack_result.password
        
        print(formatter.format_result("audit", crack_result.found, audit_data))
        return int(ExitCode.SUCCESS) if crack_result.found else int(ExitCode.GENERAL_ERROR)
    
    if crack_result.found:
        print(f"\n\n[+] PASSWORD FOUND: {crack_result.password}")
    else:
        print(f"\n[-] Password not found in generated wordlist.")
    
    return int(ExitCode.SUCCESS) if crack_result.found else int(ExitCode.GENERAL_ERROR)


def cmd_scan(args):
    """Scan for WiFi networks"""
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    
    if not use_json:
        print(f"\n[*] Scanning for networks on {args.interface}")
    
    # Check root if needed
    if os.geteuid() != 0 and not use_json:
        print("[yellow]Warning: Root privileges recommended for network scanning[/]")
    
    # Ensure monitor mode
    monitor = MonitorMode()
    interface = args.interface
    
    if not monitor.is_in_monitor_mode(interface):
        if not use_json:
            print(f"[*] Enabling monitor mode on {interface}...")
        success, msg, mon_iface = monitor.enable_monitor_mode(interface)
        if success:
            interface = mon_iface
            if not use_json:
                print(f"[+] {msg}")
        else:
            if use_json:
                print(formatter.format_error(
                    command="scan",
                    error_code=ErrorCode.MONITOR_MODE_FAILED,
                    message=f"Failed to enable monitor mode: {msg}",
                    exit_code=ExitCode.GENERAL_ERROR
                ))
            else:
                print(f"[-] {msg}")
            return int(ExitCode.GENERAL_ERROR)
    
    # Scan for networks
    from capture.network_scanner import NetworkScanner
    scanner = NetworkScanner(interface)
    duration = getattr(args, 'duration', 10)
    
    if not use_json:
        print(f"[*] Scanning for {duration} seconds...")
    
    networks = scanner.scan(duration=duration)
    
    # Apply filters
    min_power = getattr(args, 'min_power', -100)
    encryption_filter = getattr(args, 'encryption', None)
    has_clients_flag = getattr(args, 'has_clients', False)
    no_clients_flag = getattr(args, 'no_clients', False)
    
    filtered_networks = []
    for net in networks:
        if net.power < min_power:
            continue
        if encryption_filter and encryption_filter.upper() not in net.encryption.upper():
            continue
        client_count = len(net.clients) if hasattr(net, 'clients') and net.clients else 0
        if has_clients_flag and client_count == 0:
            continue
        if no_clients_flag and client_count > 0:
            continue
        filtered_networks.append(net)
    
    # Sort
    sort_by = getattr(args, 'sort', 'signal')
    if sort_by == 'signal':
        filtered_networks.sort(key=lambda n: n.power, reverse=True)
    elif sort_by == 'channel':
        filtered_networks.sort(key=lambda n: n.channel)
    elif sort_by == 'name':
        filtered_networks.sort(key=lambda n: n.essid)
    
    # Prepare data
    network_data = []
    for net in filtered_networks:
        clients = net.clients if hasattr(net, 'clients') and net.clients else []
        client_count = len(clients)
        network_data.append({
            "essid": net.essid,
            "bssid": net.bssid,
            "channel": net.channel,
            "power": net.power,
            "encryption": net.encryption,
            "clients": [{"mac": c.mac, "power": getattr(c, 'power', None)} if hasattr(c, 'mac') else str(c) for c in clients],
            "client_count": client_count
        })
    
    if use_json:
        data = {
            "interface": interface,
            "networks": network_data,
            "count": len(network_data),
            "duration": duration
        }
        print(formatter.format_result("scan", True, data))
        return int(ExitCode.SUCCESS)
    
    # Text output
    if filtered_networks:
        print(f"\n[+] Found {len(filtered_networks)} network(s):")
        print("=" * 90)
        print("  #  | ESSID                     | BSSID             | CH | PWR   | ENC      | CLNT")
        print("=" * 90)
        for i, net in enumerate(filtered_networks[:20], 1):
            clients = net.clients if hasattr(net, 'clients') and net.clients else []
            client_count = len(clients)
            client_marker = "✓" if client_count > 0 else " "
            print(f" {i:2d}  | {net.essid:25s} | {net.bssid} | {net.channel:2d} | "
                  f"{net.power:3d} dBm | {net.encryption:8s} | {client_count:2d} {client_marker}")
        print("=" * 90)
    else:
        print("[-] No networks found matching criteria")
    
    return int(ExitCode.SUCCESS)


def cmd_capture(args):
    """Capture WiFi handshakes"""
    formatter = JSONOutputFormatter()
    use_json = getattr(args, 'json', False)
    
    # Check if running as root
    if os.geteuid() != 0:
        if use_json:
            print(formatter.format_error(
                command="capture",
                error_code=ErrorCode.PERMISSION_DENIED,
                message="This command requires root privileges",
                suggestions=["Run with: sudo wifucker capture ..."],
                exit_code=ExitCode.PERMISSION_DENIED
            ))
        else:
            print("[-] This command requires root privileges")
            print("[*] Run with: sudo wifucker capture ...")
        return int(ExitCode.PERMISSION_DENIED)

    if not use_json:
        print(f"\n[*] Starting handshake capture on {args.interface}")

    # Initialize capture
    capture = HandshakeCapture(interface=args.interface, output_dir=args.output_dir)
    
    target_ssid = getattr(args, 'target_ssid', None)
    auto_select = getattr(args, 'auto_select', False)
    non_interactive = use_json or auto_select

    # Determine target
    target = None
    
    if args.bssid and args.channel:
        # Manual target via BSSID
        from capture.network_scanner import WiFiNetwork
        target = WiFiNetwork(
            bssid=args.bssid,
            channel=args.channel,
            essid=args.essid or target_ssid or f"Target-{args.bssid}",
            power=-50,
            encryption="WPA2",
            cipher="",
            authentication="",
        )
        if not use_json:
            print(f"[*] Manual target: {target.essid} ({target.bssid}) on channel {target.channel}")
    elif target_ssid or auto_select:
        # Scan and find target
        if not use_json:
            print("[*] Scanning for networks...")
        from capture.network_scanner import NetworkScanner
        scanner = NetworkScanner(args.interface)
        networks = scanner.scan(duration=args.scan_time)
        
        if not networks:
            if use_json:
                print(formatter.format_error(
                    command="capture",
                    error_code=ErrorCode.NETWORK_ERROR,
                    message="No networks found during scan",
                    exit_code=ExitCode.NETWORK_ERROR
                ))
            else:
                print("[-] No networks found")
            return int(ExitCode.NETWORK_ERROR)
        
        if target_ssid:
            target = next((n for n in networks if n.essid == target_ssid), None)
            if not target:
                if use_json:
                    print(formatter.format_error(
                        command="capture",
                        error_code=ErrorCode.NETWORK_ERROR,
                        message=f"Target network '{target_ssid}' not found",
                        exit_code=ExitCode.NOT_FOUND
                    ))
                else:
                    print(f"[-] Target network '{target_ssid}' not found")
                return int(ExitCode.NOT_FOUND)
        elif auto_select:
            # Auto-select strongest signal
            target = max(networks, key=lambda n: n.power)
            if not use_json:
                print(f"[+] Auto-selected: {target.essid} ({target.bssid})")
    else:
        # Interactive scan and select
        if non_interactive:
            if use_json:
                print(formatter.format_error(
                    command="capture",
                    error_code=ErrorCode.INVALID_ARGS,
                    message="Target selection required. Use --target-ssid, --auto-select, or --bssid/--channel",
                    exit_code=ExitCode.INVALID_ARGS
                ))
            else:
                print("[-] No target specified. Use --target-ssid, --auto-select, or --bssid/--channel")
            return int(ExitCode.INVALID_ARGS)
        
        # Interactive selection
        print("[*] Scanning for networks...")
        target = capture.scan_and_select_network(
            scan_duration=args.scan_time, show_hidden=args.show_hidden, min_power=args.min_power
        )

        if not target:
            if use_json:
                print(formatter.format_error(
                    command="capture",
                    error_code=ErrorCode.NETWORK_ERROR,
                    message="No target selected",
                    exit_code=ExitCode.GENERAL_ERROR
                ))
            else:
                print("[-] No target selected")
            return int(ExitCode.GENERAL_ERROR)

    # Progress reporter
    progress_file = None
    if getattr(args, 'progress_file', None):
        progress_file = Path(args.progress_file)
        progress_file.parent.mkdir(parents=True, exist_ok=True)
    
    progress_reporter = ProgressReporter(progress_file, operation="capture")
    
    # Capture handshake
    capture_duration = getattr(args, 'timeout', 60)
    deauth_count = getattr(args, 'deauth_count', 5)
    
    if not use_json:
        print(f"[*] Capturing handshake for {target.essid}...")
    
    def progress_callback(remaining, total):
        if progress_file:
            progress_reporter.update(total - remaining, total, 0)
        if not use_json:
            print(f"\r[*] Capturing... {remaining}s remaining", end='', flush=True)
    
    result = capture.capture_handshake(
        target=target,
        output_file=getattr(args, 'output', None),
        deauth_count=deauth_count,
        capture_duration=capture_duration,
        verify=not getattr(args, 'no_verify', False),
    )
    
    progress_reporter.complete(result.success)
    
    if not use_json:
        print()  # New line after progress

    # JSON output
    if use_json:
        if result.success:
            data = {
                "target": {
                    "essid": result.target_network.essid,
                    "bssid": result.target_network.bssid,
                    "channel": result.target_network.channel,
                    "power": result.target_network.power
                },
                "handshakes_captured": result.handshakes_captured,
                "duration": result.duration,
                "pcap_file": result.pcap_file,
                "deauth_count": deauth_count,
                "capture_duration": capture_duration
            }
            print(formatter.format_result("capture", True, data))
            return int(ExitCode.SUCCESS)
        else:
            print(formatter.format_error(
                command="capture",
                error_code=ErrorCode.CAPTURE_FAILED,
                message=result.message or "Handshake capture failed",
                exit_code=ExitCode.GENERAL_ERROR
            ))
            return int(ExitCode.GENERAL_ERROR)

    # Text output
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
        print(f"    1. Crack: wifucker crack {result.pcap_file} wordlist.txt")
        print(f"    2. Parse: wifucker parse {result.pcap_file}")
        return int(ExitCode.SUCCESS)
    else:
        print(f"\n[!] {result.message}")
        return int(ExitCode.GENERAL_ERROR)


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
    parse_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # Crack command
    crack_parser = subparsers.add_parser("crack", help="Crack WiFi password")
    crack_parser.add_argument("pcap", help="PCAP file with handshakes")
    crack_parser.add_argument("wordlist", nargs="?", help="Password wordlist (optional if --brute-force)")
    crack_parser.add_argument(
        "--device", choices=["NPU", "NCS2", "GPU", "CPU"], help="Force specific device"
    )
    crack_parser.add_argument(
        "--cpu-only", action="store_true", help="Use CPU only (no acceleration)"
    )
    crack_parser.add_argument("--rules", action="store_true", help="Apply password mutation rules")
    crack_parser.add_argument("--brute-force", action="store_true", help="Use brute force instead of wordlist")
    crack_parser.add_argument("--min-length", type=int, default=8, help="Minimum password length for brute force")
    crack_parser.add_argument("--max-length", type=int, default=12, help="Maximum password length for brute force")
    crack_parser.add_argument("--charset", help="Custom character set for brute force (default: alphanumeric + special)")
    crack_parser.add_argument("--use-hashcat", action="store_true", help="Use hashcat as fallback or alternative method")
    crack_parser.add_argument("--hashcat-only", action="store_true", help="Force hashcat usage (skip OpenVINO/hardware acceleration)")
    crack_parser.add_argument("--output", "-o", help="Save result to file")
    crack_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    crack_parser.add_argument("--progress-file", help="File to write progress updates (JSON)")

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
    gen_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # Download command
    dl_parser = subparsers.add_parser("download", help="Download wordlists")
    dl_parser.add_argument("--all", action="store_true", help="Download all wordlists")
    dl_parser.add_argument("--source", help="Download specific wordlist")
    dl_parser.add_argument("--dir", default="./wordlists", help="Download directory")
    dl_parser.add_argument("--force", action="store_true", help="Force re-download")

    # Devices command
    dev_parser = subparsers.add_parser("devices", help="List available devices")
    dev_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # Benchmark command
    bench_parser = subparsers.add_parser("benchmark", help="Benchmark devices")
    bench_parser.add_argument(
        "--device", choices=["NPU", "NCS2", "GPU", "CPU"], help="Benchmark specific device"
    )
    bench_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # Audit command
    audit_parser = subparsers.add_parser("audit", help="Run full WiFi security audit")
    audit_parser.add_argument(
        "--auto", action="store_true", help="Run in automatic mode (runs all steps without prompts)"
    )
    audit_parser.add_argument(
        "--devices", help="Comma-separated list of devices to use (e.g., NPU,GPU)"
    )
    audit_parser.add_argument("--interface", help="Wireless interface (auto-detect if not specified)")
    audit_parser.add_argument("--target-ssid", help="Target network SSID (skip selection if provided)")
    audit_parser.add_argument("--capture-duration", type=int, default=60, help="Handshake capture duration (default: 60s)")
    audit_parser.add_argument("--deauth-count", type=int, default=5, help="Deauth packets per burst (default: 5)")
    audit_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    audit_parser.add_argument("--progress-file", help="File to write progress updates (JSON)")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan for WiFi networks")
    scan_parser.add_argument("interface", help="Wireless interface name")
    scan_parser.add_argument("--duration", type=int, default=10, help="Scan duration in seconds (default: 10)")
    scan_parser.add_argument("--min-power", type=int, default=-100, help="Minimum signal strength (default: -100)")
    scan_parser.add_argument("--encryption", help="Filter by encryption type (e.g., WPA2, WPA)")
    scan_parser.add_argument("--has-clients", action="store_true", help="Only show networks with active clients")
    scan_parser.add_argument("--no-clients", action="store_true", help="Only show networks without clients")
    scan_parser.add_argument("--sort", choices=["signal", "channel", "name"], default="signal", help="Sort order (default: signal)")
    scan_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    
    # Interfaces command
    iface_parser = subparsers.add_parser("interfaces", help="List wireless interfaces")
    iface_parser.add_argument("--json", action="store_true", help="Output in JSON format")

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
    cap_parser.add_argument("--target-ssid", help="Target network SSID (auto-select from scan)")
    cap_parser.add_argument("--auto-select", action="store_true", help="Auto-select strongest network")
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
    cap_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    cap_parser.add_argument("--progress-file", help="File to write progress updates (JSON)")

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

    # Operation management commands
    op_parser = subparsers.add_parser("operation", help="Operation management")
    op_subparsers = op_parser.add_subparsers(dest="operation_command", help="Operation subcommand")
    
    op_status_parser = op_subparsers.add_parser("status", help="Get operation status")
    op_status_parser.add_argument("operation_id", help="Operation ID")
    op_status_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    
    op_list_parser = op_subparsers.add_parser("list", help="List operations")
    op_list_parser.add_argument("--status", choices=["pending", "running", "completed", "failed", "cancelled"], help="Filter by status")
    op_list_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    
    op_cancel_parser = op_subparsers.add_parser("cancel", help="Cancel operation")
    op_cancel_parser.add_argument("operation_id", help="Operation ID")
    op_cancel_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    
    op_cleanup_parser = op_subparsers.add_parser("cleanup", help="Cleanup old operations")
    op_cleanup_parser.add_argument("--days", type=int, default=7, help="Remove operations older than N days")

    # Profile management commands
    profile_parser = subparsers.add_parser("profile", help="Configuration profile management")
    profile_subparsers = profile_parser.add_subparsers(dest="profile_command", help="Profile subcommand")
    
    profile_save_parser = profile_subparsers.add_parser("save", help="Save current command as profile")
    profile_save_parser.add_argument("name", help="Profile name")
    profile_save_parser.add_argument("--description", help="Profile description")
    profile_save_parser.add_argument("--command", required=True, help="Command name")
    profile_save_parser.add_argument("--args", help="JSON string of arguments")
    
    profile_load_parser = profile_subparsers.add_parser("load", help="Load and execute profile")
    profile_load_parser.add_argument("name", help="Profile name")
    profile_load_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    
    profile_list_parser = profile_subparsers.add_parser("list", help="List all profiles")
    profile_list_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    
    profile_delete_parser = profile_subparsers.add_parser("delete", help="Delete profile")
    profile_delete_parser.add_argument("name", help="Profile name")
    profile_delete_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # Batch operations command
    batch_parser = subparsers.add_parser("batch", help="Run multiple operations")
    batch_parser.add_argument("--file", help="JSON file with batch operations")
    batch_parser.add_argument("--parallel", action="store_true", help="Run operations in parallel")
    batch_parser.add_argument("--max-parallel", type=int, default=4, help="Maximum parallel operations")
    batch_parser.add_argument("--stop-on-error", action="store_true", help="Stop on first error")
    batch_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    batch_parser.add_argument("--progress-file", help="File to write progress updates (JSON)")

    # Workflow command
    workflow_parser = subparsers.add_parser("workflow", help="Execute predefined or custom workflows")
    workflow_subparsers = workflow_parser.add_subparsers(dest="workflow_command", help="Workflow subcommand")
    
    workflow_run_parser = workflow_subparsers.add_parser("run", help="Run workflow")
    workflow_run_parser.add_argument("name", help="Workflow name")
    workflow_run_parser.add_argument("--args", help="JSON string of workflow arguments")
    workflow_run_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    workflow_run_parser.add_argument("--progress-file", help="File to write progress updates (JSON)")
    
    workflow_list_parser = workflow_subparsers.add_parser("list", help="List available workflows")
    workflow_list_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    
    workflow_create_parser = workflow_subparsers.add_parser("create", help="Create custom workflow")
    workflow_create_parser.add_argument("name", help="Workflow name")
    workflow_create_parser.add_argument("--file", required=True, help="JSON file with workflow definition")
    workflow_create_parser.add_argument("--description", help="Workflow description")

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
        elif args.command == "scan":
            return cmd_scan(args)
        elif args.command == "capture":
            return cmd_capture(args)
        elif args.command == "interfaces":
            return cmd_interfaces(args)
        elif args.command == "optimize":
            return cmd_optimize(args)
        elif args.command == "monitor":
            return cmd_monitor(args)
        elif args.command == "operation":
            if args.operation_command == "status":
                return cmd_operation_status(args)
            elif args.operation_command == "list":
                return cmd_operation_list(args)
            elif args.operation_command == "cancel":
                return cmd_operation_cancel(args)
            elif args.operation_command == "cleanup":
                return cmd_operation_cleanup(args)
            else:
                op_parser.print_help()
                return 0
        elif args.command == "profile":
            if args.profile_command == "save":
                return cmd_profile_save(args)
            elif args.profile_command == "load":
                return cmd_profile_load(args)
            elif args.profile_command == "list":
                return cmd_profile_list(args)
            elif args.profile_command == "delete":
                return cmd_profile_delete(args)
            else:
                profile_parser.print_help()
                return 0
        elif args.command == "batch":
            return cmd_batch(args)
        elif args.command == "workflow":
            if args.workflow_command == "run":
                return cmd_workflow_run(args)
            elif args.workflow_command == "list":
                return cmd_workflow_list(args)
            elif args.workflow_command == "create":
                return cmd_workflow_create(args)
            else:
                workflow_parser.print_help()
                return 0
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
