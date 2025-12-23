#!/usr/bin/env python3
"""
Hashcat Wrapper for WIFUCKER
============================

Python wrapper for hashcat binary integration.
Provides subprocess-based interface to hashcat for WPA/WPA2 cracking.
"""

import os
import sys
import subprocess
import tempfile
import time
import re
from pathlib import Path
from typing import Optional, Callable, List
from dataclasses import dataclass

# Import CrackingResult to avoid circular import
# Use TYPE_CHECKING to defer import
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .openvino_cracker import CrackingResult
else:
    # Import at runtime to avoid circular dependency
    # We'll import it when needed in methods
    CrackingResult = None


@dataclass
class HashcatConfig:
    """Hashcat configuration"""
    binary_path: str
    hash_mode: int = 22000  # WPA2
    attack_mode: int = 0  # Dictionary attack
    status_interval: int = 1  # Status update interval in seconds
    potfile: Optional[str] = None
    rules_file: Optional[str] = None
    mask: Optional[str] = None  # For brute force (attack mode 3)


class HashcatCracker:
    """
    Wrapper for hashcat binary subprocess calls.
    
    Provides interface to hashcat for WPA/WPA2 password cracking
    using hashcat format (mode 22000).
    """
    
    def __init__(self, binary_path: Optional[str] = None):
        """
        Initialize hashcat cracker.
        
        Args:
            binary_path: Path to hashcat binary. If None, uses bundled hashcat.
        """
        if binary_path:
            self.binary_path = binary_path
        else:
            # Use bundled hashcat in crackers/hashcat/
            script_dir = Path(__file__).parent
            self.binary_path = str(script_dir / "hashcat" / "hashcat")
        
        # Verify binary exists
        if not os.path.isfile(self.binary_path):
            raise FileNotFoundError(
                f"Hashcat binary not found: {self.binary_path}\n"
                f"Please build hashcat or provide correct path."
            )
        
        # Verify binary is executable
        if not os.access(self.binary_path, os.X_OK):
            raise PermissionError(
                f"Hashcat binary is not executable: {self.binary_path}"
            )
        
        # Test hashcat version
        try:
            result = subprocess.run(
                [self.binary_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                raise RuntimeError(f"Hashcat version check failed: {result.stderr}")
            self.version = result.stdout.strip()
        except subprocess.TimeoutExpired:
            raise RuntimeError("Hashcat binary appears to be unresponsive")
        except Exception as e:
            raise RuntimeError(f"Failed to verify hashcat binary: {e}")
    
    def crack_wpa2(
        self,
        hashcat_hash: str,
        wordlist_file: Optional[str] = None,
        brute_force: bool = False,
        min_length: int = 8,
        max_length: int = 12,
        charset: Optional[str] = None,
        rules_file: Optional[str] = None,
        progress_callback: Optional[Callable[[float, int, float], None]] = None,
        timeout: Optional[int] = None
    ):
        # Import here to avoid circular dependency
        from .openvino_cracker import CrackingResult
        """
        Crack WPA2 password using hashcat.
        
        Args:
            hashcat_hash: Hashcat format hash (22000) - single line
            wordlist_file: Path to wordlist file (for dictionary attack)
            brute_force: Use brute force attack instead of wordlist
            min_length: Minimum password length (brute force)
            max_length: Maximum password length (brute force)
            charset: Custom charset for brute force (e.g., "?l?u?d?s")
            rules_file: Path to hashcat rules file
            progress_callback: Callback function(progress_pct, attempts, h/s)
            timeout: Maximum time in seconds (None = no timeout)
        
        Returns:
            CrackingResult with success status and password if found
        """
        start_time = time.time()
        attempts = 0
        hashes_per_second = 0.0
        
        # Create temporary hash file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.hc22000', delete=False) as hash_file:
            hash_file.write(hashcat_hash + '\n')
            hash_file_path = hash_file.name
        
        try:
            # Build hashcat command
            cmd = [self.binary_path]
            
            # Hash mode (22000 = WPA2)
            cmd.extend(['-m', '22000'])
            
            # Attack mode
            if brute_force:
                cmd.extend(['-a', '3'])  # Brute force
                if charset:
                    # Use custom charset
                    cmd.append(charset)
                else:
                    # Build mask for length range
                    # Default charset: ?l?u?d?s (lower, upper, digit, special)
                    mask = f"?{'?'.join(['l' if i % 2 == 0 else 'u' for i in range(min_length)])}"
                    cmd.append(mask)
            else:
                # Dictionary attack
                cmd.extend(['-a', '0'])
                if not wordlist_file:
                    raise ValueError("wordlist_file required for dictionary attack")
                cmd.append(hash_file_path)
                cmd.append(wordlist_file)
            
            # Rules file
            if rules_file and os.path.isfile(rules_file):
                cmd.extend(['-r', rules_file])
            
            # Status reporting
            cmd.extend(['--status', '--status-timer', str(1)])
            
            # Potfile (store cracked passwords)
            potfile_path = tempfile.mktemp(suffix='.potfile')
            cmd.extend(['--potfile-path', potfile_path])
            
            # Remove session files
            cmd.append('--remove')
            
            # Quiet mode (less output)
            cmd.append('--quiet')
            
            print(f"[*] Hashcat command: {' '.join(cmd[:10])}...")
            print(f"[*] Hash file: {hash_file_path}")
            
            # Run hashcat
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Monitor progress
            last_status_time = time.time()
            status_file = None
            
            # Hashcat creates status file: hashcat.hashcat.potfile
            # Look for status files in current directory
            status_pattern = re.compile(r'hashcat\.\d+\.status')
            
            try:
                # Wait for process with timeout
                if timeout:
                    try:
                        stdout, stderr = process.communicate(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        stdout, stderr = process.communicate()
                        # Import here to avoid circular dependency
                        from .openvino_cracker import CrackingResult
                        return CrackingResult(
                            success=False,
                            attempts=attempts,
                            elapsed_time=time.time() - start_time,
                            device_used="hashcat",
                            hashes_per_second=hashes_per_second
                        )
                else:
                    stdout, stderr = process.communicate()
                
                return_code = process.returncode
                
                # Parse output for password
                password = None
                
                # Check potfile for cracked password
                if os.path.isfile(potfile_path):
                    try:
                        with open(potfile_path, 'r') as pf:
                            for line in pf:
                                line = line.strip()
                                if line and ':' in line:
                                    # Potfile format: hash:password
                                    parts = line.split(':', 1)
                                    if len(parts) == 2:
                                        password = parts[1]
                                        break
                    except Exception as e:
                        print(f"[!] Error reading potfile: {e}")
                
                # Also check stdout for password
                if not password:
                    # Hashcat output format: hashcat_hash:password
                    for line in stdout.split('\n'):
                        if ':' in line and not line.startswith('#'):
                            parts = line.split(':', 1)
                            if len(parts) == 2:
                                password = parts[1].strip()
                                break
                
                # Parse status for attempts and speed
                if stderr:
                    # Look for status information in stderr
                    # Format: "Status.........: Exhausted" or "Status.........: Cracked"
                    status_match = re.search(r'Status\.+:\s+(\w+)', stderr)
                    if status_match:
                        status = status_match.group(1)
                        if status == "Cracked":
                            # Password found
                            pass
                    
                    # Parse hashes per second
                    hps_match = re.search(r'Speed\.+#1\.+:\s+([\d.]+)\s+H/s', stderr)
                    if hps_match:
                        hashes_per_second = float(hps_match.group(1))
                    
                    # Parse attempts
                    attempts_match = re.search(r'Progress\.+:\s+(\d+)/(\d+)', stderr)
                    if attempts_match:
                        attempts = int(attempts_match.group(1))
                
                success = password is not None
                
                if success:
                    print(f"[+] Hashcat found password: {password}")
                else:
                    print(f"[-] Hashcat did not find password (return code: {return_code})")
                    if stderr:
                        print(f"[!] Hashcat stderr: {stderr[:200]}")
                
                # Import here to avoid circular dependency
                from .openvino_cracker import CrackingResult
                return CrackingResult(
                    success=success,
                    password=password,
                    attempts=attempts,
                    elapsed_time=time.time() - start_time,
                    device_used="hashcat",
                    hashes_per_second=hashes_per_second
                )
                
            finally:
                # Cleanup
                if process.poll() is None:
                    process.kill()
                    process.wait()
        
        finally:
            # Cleanup temporary files
            try:
                os.unlink(hash_file_path)
            except Exception:
                pass
            try:
                if os.path.isfile(potfile_path):
                    os.unlink(potfile_path)
            except Exception:
                pass
    
    def crack_from_handshake_data(
        self,
        ssid: str,
        bssid: str,
        client: str,
        anonce: bytes,
        snonce: bytes,
        mic: bytes,
        eapol_frames: Optional[List[bytes]] = None,
        wordlist_file: Optional[str] = None,
        brute_force: bool = False,
        min_length: int = 8,
        max_length: int = 12,
        charset: Optional[str] = None,
        rules_file: Optional[str] = None,
        progress_callback: Optional[Callable[[float, int, float], None]] = None,
        timeout: Optional[int] = None
    ):
        # Import here to avoid circular dependency
        from .openvino_cracker import CrackingResult
        """
        Crack WPA2 password from handshake data.
        
        This method builds the hashcat format hash from handshake data
        and then calls crack_wpa2().
        
        Args:
            ssid: Network SSID
            bssid: Access Point MAC address
            client: Client MAC address
            anonce: Authenticator nonce
            snonce: Supplicant nonce
            mic: Message Integrity Code
            eapol_frames: List of EAPOL frames (for building hashcat format)
            wordlist_file: Path to wordlist file
            brute_force: Use brute force attack
            min_length: Minimum password length (brute force)
            max_length: Maximum password length (brute force)
            charset: Custom charset for brute force
            rules_file: Path to hashcat rules file
            progress_callback: Callback for progress updates
            timeout: Maximum time in seconds
        
        Returns:
            CrackingResult with success status and password if found
        """
        import binascii
        import struct
        
        # Build hashcat format hash
        # Format: WPA*02*MIC*MAC_AP*MAC_CLIENT*ESSID*ANONCE*EAPOL*MESSAGEPAIR
        try:
            essid_hex = binascii.hexlify(ssid.encode()).decode()
            bssid_clean = bssid.replace(':', '').lower()
            client_clean = client.replace(':', '').lower()
            anonce_hex = binascii.hexlify(anonce).decode()
            mic_hex = binascii.hexlify(mic).decode()
            
            # Build EAPOL message pair
            eapol_hex = ""
            if eapol_frames:
                msg1 = None
                msg2 = None
                for frame in eapol_frames:
                    if len(frame) >= 7:
                        key_info = struct.unpack('>H', frame[5:7])[0]
                        # Message 1: has ANonce, no MIC
                        if (key_info & 0x0008) and not (key_info & 0x0100):
                            msg1 = frame
                        # Message 2: has SNonce and MIC
                        elif (key_info & 0x0100) and (key_info & 0x0008):
                            msg2 = frame
                
                if msg1 and msg2:
                    eapol_hex = binascii.hexlify(msg1).decode() + binascii.hexlify(msg2).decode()
                elif msg2:
                    eapol_hex = binascii.hexlify(msg2).decode()
            
            # Build hashcat hash line
            if eapol_hex:
                hashcat_hash = f"WPA*02*{mic_hex}*{bssid_clean}*{client_clean}*{essid_hex}*{anonce_hex}*{eapol_hex}*0103007502010a00000000000000000000{anonce_hex}00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            else:
                hashcat_hash = f"WPA*02*{mic_hex}*{bssid_clean}*{client_clean}*{essid_hex}*{anonce_hex}"
            
            # Call crack_wpa2 with built hash
            return self.crack_wpa2(
                hashcat_hash,
                wordlist_file=wordlist_file,
                brute_force=brute_force,
                min_length=min_length,
                max_length=max_length,
                charset=charset,
                rules_file=rules_file,
                progress_callback=progress_callback,
                timeout=timeout
            )
        
        except Exception as e:
            print(f"[-] Error building hashcat hash: {e}")
            # Import here to avoid circular dependency
            from .openvino_cracker import CrackingResult
            return CrackingResult(
                success=False,
                elapsed_time=0.0,
                device_used="hashcat"
            )
