#!/usr/bin/env python3
"""
PBKDF2 Password Cracker Module
Integrated into WIFUCKER toolkit
Supports multiple cracking strategies: dictionary, mutations, context-aware
"""

import hashlib
from base64 import b64decode
import time
import threading
import queue
from multiprocessing import cpu_count
from pathlib import Path
from typing import List, Optional, Callable, Dict
from dataclasses import dataclass


@dataclass
class CrackingResult:
    """Result of password cracking attempt"""
    success: bool
    password: Optional[str] = None
    message: Optional[str] = None
    attempts: int = 0
    elapsed_time: float = 0.0
    rate: float = 0.0
    device: str = "CPU"


class PBKDF2Cracker:
    """PBKDF2 password cracker with multiple strategies"""

    def __init__(self, encrypted_data: str, iterations: int = 100000):
        """
        Initialize PBKDF2 cracker.

        Args:
            encrypted_data: Base64(salt)|Base64(ciphertext) format
            iterations: PBKDF2 iterations (default 100000)
        """
        self.encrypted_data = encrypted_data
        self.iterations = iterations
        self.result_queue = queue.Queue()
        self.threads = []
        self.found = False

    def decrypt_attempt(self, password: str) -> Optional[str]:
        """Try to decrypt with a password"""
        try:
            parts = self.encrypted_data.split('|')
            if len(parts) != 2:
                return None

            salt = b64decode(parts[0])
            ciphertext = b64decode(parts[1])

            key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, self.iterations)
            message_bytes = bytes(
                a ^ b for a, b in zip(
                    ciphertext,
                    (key * (len(ciphertext) // len(key) + 1))[:len(ciphertext)]
                )
            )

            result = message_bytes.decode('utf-8')
            if result and all(c.isprintable() or c in '\n\t' for c in result):
                return result
            return None
        except Exception:
            return None

    def _worker_thread(self, passwords: List[str], worker_id: int):
        """Worker thread for password testing"""
        tested = 0
        for password in passwords:
            if not password:
                continue

            result = self.decrypt_attempt(password)
            tested += 1

            if result:
                self.result_queue.put({
                    'found': True,
                    'password': password,
                    'message': result,
                    'worker_id': worker_id
                })
                self.found = True
                return

            if tested % 5000 == 0:
                self.result_queue.put({
                    'progress': True,
                    'worker_id': worker_id,
                    'tested': tested,
                    'password': password
                })

            if self.found:
                return

        self.result_queue.put({
            'progress': True,
            'worker_id': worker_id,
            'tested': tested,
            'complete': True
        })

    def crack_dictionary(
        self,
        wordlist: List[str],
        progress_callback: Optional[Callable] = None,
        max_workers: Optional[int] = None
    ) -> CrackingResult:
        """
        Crack password using dictionary attack.

        Args:
            wordlist: List of passwords to test
            progress_callback: Optional callback for progress updates
            max_workers: Maximum worker threads (default: CPU count)

        Returns:
            CrackingResult with findings
        """
        start_time = time.time()
        num_workers = max_workers or cpu_count()
        self.found = False
        self.threads = []
        self.result_queue = queue.Queue()

        # Split wordlist into chunks
        chunk_size = max(1, len(wordlist) // (num_workers * 2))
        chunks = [wordlist[i:i + chunk_size] for i in range(0, len(wordlist), chunk_size)]

        # Start workers
        for i, chunk in enumerate(chunks):
            t = threading.Thread(
                target=self._worker_thread,
                args=(chunk, i),
                daemon=True
            )
            t.start()
            self.threads.append(t)

        # Monitor progress
        active_workers = len(self.threads)
        worker_stats = {}
        total_tested = 0
        last_update = time.time()

        while active_workers > 0 and not self.found:
            try:
                msg = self.result_queue.get(timeout=2)

                if msg.get('found'):
                    self.found = True
                    elapsed = time.time() - start_time
                    return CrackingResult(
                        success=True,
                        password=msg['password'],
                        message=msg['message'],
                        attempts=total_tested,
                        elapsed_time=elapsed,
                        rate=total_tested / elapsed if elapsed > 0 else 0
                    )

                elif msg.get('progress'):
                    worker_id = msg['worker_id']
                    worker_stats[worker_id] = msg['tested']
                    total_tested = sum(worker_stats.values())

                    if msg.get('complete'):
                        active_workers -= 1

                    if progress_callback and (time.time() - last_update) > 2:
                        elapsed = time.time() - start_time
                        progress_callback(
                            total_tested,
                            len(wordlist),
                            (total_tested / len(wordlist) * 100) if wordlist else 0,
                            total_tested / elapsed if elapsed > 0 else 0
                        )
                        last_update = time.time()

            except queue.Empty:
                alive = sum(1 for t in self.threads if t.is_alive())
                if alive == 0:
                    active_workers = 0

        elapsed = time.time() - start_time
        return CrackingResult(
            success=False,
            attempts=total_tested,
            elapsed_time=elapsed,
            rate=total_tested / elapsed if elapsed > 0 else 0
        )

    def crack_rockyou(self, rockyou_path: Path, **kwargs) -> CrackingResult:
        """
        Crack password using rockyou wordlist.

        Args:
            rockyou_path: Path to rockyou.txt file
            **kwargs: Additional arguments passed to crack_dictionary

        Returns:
            CrackingResult
        """
        if not rockyou_path.exists():
            return CrackingResult(
                success=False,
                elapsed_time=0,
                message="rockyou.txt not found"
            )

        wordlist = []
        with open(rockyou_path, 'r', encoding='utf-8', errors='ignore') as f:
            wordlist = [line.strip() for line in f if line.strip()]

        return self.crack_dictionary(wordlist, **kwargs)
