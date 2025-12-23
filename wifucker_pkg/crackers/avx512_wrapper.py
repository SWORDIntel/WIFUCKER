#!/usr/bin/env python3
"""
AVX-512 Cracker Python Wrapper
================================

Python interface to the AVX-512 accelerated WiFi password cracker.
Provides 5-10x performance boost over OpenVINO NPU on modern Intel CPUs.
"""

import ctypes
import os
from pathlib import Path
from typing import Optional, List, Tuple
import subprocess


class AVX512Cracker:
    """
    High-performance WiFi password cracker using AVX-512 SIMD instructions

    Automatically pins to P-cores for maximum performance.
    Expected: 200,000-500,000 H/s on modern Intel Core i9
    """

    def __init__(self):
        self.lib = None
        self.lib_path = None
        self.cracker_type = None # Stores 'avx512', 'avx2', 'avx', or 'generic'
        self._load_library()

    def _find_library(self) -> Optional[Tuple[Path, str]]:
        """Find the compiled cracker library (AVX-512, AVX2, AVX, or Generic)"""
        current_dir = Path(__file__).parent
        
        # Ordered by preference: AVX-512, AVX2, AVX, Generic
        lib_variants = [
            ("cracker_avx512.so", "avx512"),
            ("cracker_avx2.so", "avx2"),
            ("cracker_avx.so", "avx"),
            ("cracker_generic.so", "generic")
        ]

        for lib_name, cracker_type in lib_variants:
            # Check current directory
            lib_path = current_dir / lib_name
            if lib_path.exists():
                return lib_path, cracker_type
            
            # Check one level up (if wrapper is in a subdirectory)
            lib_path = current_dir.parent / lib_name
            if lib_path.exists():
                return lib_path, cracker_type

        return None, None

    def _compile_library(self) -> bool:
        """Attempt to compile the library if not found"""
        print("[*] Cracker library not found, attempting to compile...")

        makefile_dir = Path(__file__).parent
        makefile = makefile_dir / 'Makefile'

        if not makefile.exists():
            print("[-] Makefile not found in crackers/ directory.")
            return False

        # Check dependencies (already handled by setup.sh now, but good to have a check)
        try:
            subprocess.run(['gcc', '--version'], capture_output=True, check=True)
        except:
            print("[-] GCC not found. Please ensure build-essential is installed.")
            return False

        # Try to compile
        try:
            result = subprocess.run(
                ['make', '-C', str(makefile_dir)],
                capture_output=True,
                text=True,
                timeout=120 # Increased timeout for potential longer compilation
            )

            if result.returncode == 0:
                print("[+] Successfully compiled cracker library.")
                return True
            else:
                print(f"[-] Compilation failed. Output:\n{result.stderr}")
                return False

        except Exception as e:
            print(f"[-] Compilation error: {e}")
            return False

    def _load_library(self):
        """Load the shared cracker library"""
        lib_info = self._find_library()
        lib_path, cracker_type = lib_info

        if not lib_path:
            # Try to compile
            if self._compile_library():
                lib_path, cracker_type = self._find_library()

        if not lib_path:
            print("[-] No cracker library available after compilation attempt.")
            print("[!] Falling back to OpenVINO/CPU cracker.")
            self.lib = None
            self.cracker_type = None
            return

        try:
            self.lib = ctypes.CDLL(str(lib_path))
            self.lib_path = lib_path
            self.cracker_type = cracker_type
            self._setup_functions()
            print(f"[+] Loaded cracker library ({self.cracker_type}): {lib_path}")
        except Exception as e:
            print(f"[-] Failed to load cracker library: {e}")
            self.lib = None
            self.cracker_type = None

    def _setup_functions(self):
        """Setup C function prototypes based on loaded cracker type"""
        if not self.lib:
            return

        # Dynamically construct function names based on cracker_type
        # Functions are named like cracker_init_generic, cracker_crack_avx2, etc.
        # Except for avx512, which uses just cracker_init, cracker_crack
        prefix = ""
        if self.cracker_type == "avx512":
            # The original avx512_cracker.c uses non-suffixed function names
            pass
        elif self.cracker_type:
            prefix = f"_{self.cracker_type}"

        # cracker_init()
        self.lib.__getattr__(f"cracker_init{prefix}").argtypes = [
            ctypes.c_char_p,  # ssid
            ctypes.POINTER(ctypes.c_uint8),  # target_pmk
            ctypes.POINTER(ctypes.c_char_p),  # wordlist
            ctypes.c_size_t,  # wordlist_size
            ctypes.c_int  # num_threads
        ]
        self.lib.__getattr__(f"cracker_init{prefix}").restype = ctypes.c_void_p
        # Assign to a more convenient name for the class
        self.cracker_init_func = self.lib.__getattr__(f"cracker_init{prefix}")


        # cracker_crack()
        self.lib.__getattr__(f"cracker_crack{prefix}").argtypes = [ctypes.c_void_p]
        self.lib.__getattr__(f"cracker_crack{prefix}").restype = ctypes.c_int
        self.cracker_crack_func = self.lib.__getattr__(f"cracker_crack{prefix}")

        # cracker_get_password()
        self.lib.__getattr__(f"cracker_get_password{prefix}").argtypes = [ctypes.c_void_p]
        self.lib.__getattr__(f"cracker_get_password{prefix}").restype = ctypes.c_char_p
        self.cracker_get_password_func = self.lib.__getattr__(f"cracker_get_password{prefix}")

        # cracker_get_attempts()
        self.lib.__getattr__(f"cracker_get_attempts{prefix}").argtypes = [ctypes.c_void_p]
        self.lib.__getattr__(f"cracker_get_attempts{prefix}").restype = ctypes.c_uint64
        self.cracker_get_attempts_func = self.lib.__getattr__(f"cracker_get_attempts{prefix}")

        # cracker_destroy()
        self.lib.__getattr__(f"cracker_destroy{prefix}").argtypes = [ctypes.c_void_p]
        self.lib.__getattr__(f"cracker_destroy{prefix}").restype = None
        self.cracker_destroy_func = self.lib.__getattr__(f"cracker_destroy{prefix}")


        # If avx512, also setup check_avx512_support
        if self.cracker_type == "avx512":
            self.lib.check_avx512_support.argtypes = []
            self.lib.check_avx512_support.restype = ctypes.c_int
            self.check_avx512_support_func = self.lib.check_avx512_support
        else:
            self.check_avx512_support_func = None # Not available for other types

    def is_available(self) -> bool:
        """Check if any optimized cracking library is available"""
        return self.lib is not None and self.cracker_type is not None

    def get_cpu_info(self) -> dict:
        """Get CPU information based on the loaded cracker type"""
        info = {
            'cracker_type': self.cracker_type,
            'avx512_support_detected': False,
            'avx2_support_detected': False,
            'avx_support_detected': False,
            'p_cores': 0, # Only avx512_cracker.c truly detects P-cores
            'e_cores': 0,
            'total_cores': 0
        }

        if self.cracker_type == "avx512":
            info['avx512_support_detected'] = True
            if self.check_avx512_support_func:
                try:
                    # In avx512_cracker.c, this checks the *current* CPU
                    # For wrapper, this just indicates the compiled type.
                    # The topology detection in C is more robust.
                    pass
                except:
                    pass

        elif self.cracker_type == "avx2":
            info['avx2_support_detected'] = True
        elif self.cracker_type == "avx":
            info['avx_support_detected'] = True

        # Read /proc/cpuinfo for general core count
        try:
            with open('/proc/cpuinfo', 'r') as f:
                content = f.read()
            info['total_cores'] = content.count('processor')
        except:
            pass
        
        # P-core/E-core detection is only robust in the AVX-512 C code.
        # For other types, we can't reliably determine this from Python without
        # reimplementing the C logic, so we'll leave them at 0 unless avx512 is loaded
        # and its topology detection is exposed via a separate function.
        # The C library's topology detection is the authoritative source for P/E core counts.
        # If the library is not loaded or doesn't expose this, we only report total_cores.

        return info

    def crack(
        self,
        ssid: str,
        target_pmk: bytes,
        wordlist: List[str],
        num_threads: int = 0
    ) -> Tuple[Optional[str], int, float]:
        """
        Crack WiFi password using the loaded cracker module

        Args:
            ssid: Network SSID
            target_pmk: Target PMK (32 bytes)
            wordlist: List of passwords to try
            num_threads: Number of threads (0 = auto, uses all detected cores for generic/AVX/AVX2,
                         or all P-cores for AVX-512 if detected by C code)

        Returns:
            (password, attempts, time_seconds) or (None, attempts, time_seconds)
        """
        import time

        if not self.lib or not self.cracker_type:
            raise RuntimeError("Cracker library not loaded or type not determined")

        if len(target_pmk) != 32:
            raise ValueError("Target PMK must be 32 bytes")

        # Convert wordlist to C array
        wordlist_c = (ctypes.c_char_p * len(wordlist))()
        for i, pwd in enumerate(wordlist):
            wordlist_c[i] = pwd.encode('utf-8')

        # Convert PMK to C array
        pmk_array = (ctypes.c_uint8 * 32)()
        for i in range(32):
            pmk_array[i] = target_pmk[i]

        # Initialize cracker using the dynamically resolved function
        ctx = self.cracker_init_func(
            ssid.encode('utf-8'),
            pmk_array,
            wordlist_c,
            len(wordlist),
            num_threads
        )

        if not ctx:
            raise RuntimeError("Failed to initialize cracker")

        try:
            # Start cracking
            print(f"[*] Starting {self.cracker_type} crack with {len(wordlist):,} passwords...")
            start_time = time.time()

            found = self.cracker_crack_func(ctx)

            elapsed = time.time() - start_time

            # Get results
            attempts = self.cracker_get_attempts_func(ctx)

            if found:
                password = self.cracker_get_password_func(ctx)
                password_str = password.decode('utf-8') if password else None
                return (password_str, attempts, elapsed)
            else:
                return (None, attempts, elapsed)

        finally:
            # Cleanup
            self.cracker_destroy_func(ctx)


def test_cracker_wrapper():
    """Test the generic cracker wrapper"""
    print("Cracker Wrapper Test")
    print("=" * 60)

    cracker = AVX512Cracker() # Class name can remain, it's a wrapper for different types

    if not cracker.is_available():
        print("[-] No optimized cracker available.")
        print("[!] Falling back to Python-only cracking if available.")
        return

    print(f"[+] Cracker type '{cracker.cracker_type}' is available!")

    # Get CPU info
    info = cracker.get_cpu_info()
    print(f"\nCPU Information:")
    print(f"  Cracker Type: {info['cracker_type']}")
    print(f"  AVX-512 Support: {'Yes' if info['avx512_support_detected'] else 'No'}")
    print(f"  AVX2 Support: {'Yes' if info['avx2_support_detected'] else 'No'}")
    print(f"  AVX Support: {'Yes' if info['avx_support_detected'] else 'No'}")
    print(f"  Total cores: {info['total_cores']}")
    # P-core/E-core might only be accurately detected by AVX-512 C code
    if cracker.cracker_type == "avx512":
        print(f"  P-cores: {info['p_cores']}")
        print(f"  E-cores: {info['e_cores']}")


    print(f"\n[+] Cracker ({cracker.cracker_type}) is ready for use!")
