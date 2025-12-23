#!/usr/bin/env python3
"""
Progress Reporter
=================

Reports operation progress for agent monitoring.
"""

import json
import time
from pathlib import Path
from typing import Optional


class ProgressReporter:
    """Report operation progress"""
    
    def __init__(self, progress_file: Optional[Path] = None, operation: Optional[str] = None):
        self.progress_file = progress_file
        self.operation = operation or "unknown"
        self.start_time = time.time()
        self.last_update_time = 0
        self.update_interval = 1.0  # Update at most once per second
    
    def update(self, current: int, total: int, rate: Optional[float] = None, status: str = "running"):
        """
        Update progress
        
        Args:
            current: Current progress value
            total: Total value
            rate: Current rate (operations per second)
            status: Status string (running, completed, failed, etc.)
        """
        current_time = time.time()
        
        # Throttle updates
        if current_time - self.last_update_time < self.update_interval:
            return
        
        self.last_update_time = current_time
        
        progress_pct = (current / total * 100) if total > 0 else 0
        elapsed = current_time - self.start_time
        estimated_remaining = ((total - current) / rate) if rate and rate > 0 else None
        
        progress = {
            "operation": self.operation,
            "status": status,
            "progress": round(progress_pct, 2),
            "current": current,
            "total": total,
            "rate": round(rate, 2) if rate else None,
            "elapsed": round(elapsed, 2),
            "estimated_remaining": round(estimated_remaining, 2) if estimated_remaining else None
        }
        
        if self.progress_file:
            try:
                self.progress_file.write_text(json.dumps(progress, indent=2))
            except Exception:
                pass  # Silently fail if can't write progress
    
    def complete(self, success: bool = True):
        """Mark operation as complete"""
        status = "completed" if success else "failed"
        if self.progress_file:
            try:
                progress = json.loads(self.progress_file.read_text())
                progress["status"] = status
                progress["elapsed"] = round(time.time() - self.start_time, 2)
                self.progress_file.write_text(json.dumps(progress, indent=2))
            except Exception:
                pass


