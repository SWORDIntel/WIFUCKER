#!/usr/bin/env python3
"""
Operation Manager
=================

Manages long-running operations for agent tracking and control.
"""

import json
import uuid
import signal
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, List
from dataclasses import dataclass, asdict
from enum import Enum


class OperationStatus(Enum):
    """Operation status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Operation:
    """Operation record"""
    id: str
    command: str
    args: Dict
    status: OperationStatus
    created: str
    started: Optional[str] = None
    completed: Optional[str] = None
    result: Optional[Dict] = None
    error: Optional[str] = None
    pid: Optional[int] = None


class OperationManager:
    """Manage long-running operations"""
    
    def __init__(self, operations_dir: Optional[Path] = None):
        if operations_dir is None:
            operations_dir = Path.home() / ".wifucker" / "operations"
        self.operations_dir = operations_dir
        self.operations_dir.mkdir(parents=True, exist_ok=True)
    
    def create_operation(self, command: str, args: Dict, pid: Optional[int] = None) -> str:
        """
        Create new operation, return ID
        
        Args:
            command: Command name
            args: Command arguments
            pid: Process ID if running
            
        Returns:
            Operation ID
        """
        operation_id = str(uuid.uuid4())
        operation = Operation(
            id=operation_id,
            command=command,
            args=args,
            status=OperationStatus.PENDING,
            created=datetime.now().isoformat(),
            pid=pid
        )
        self.save_operation(operation)
        return operation_id
    
    def save_operation(self, operation: Operation):
        """Save operation to disk"""
        operation_file = self.operations_dir / f"{operation.id}.json"
        operation_file.write_text(json.dumps(asdict(operation), indent=2, default=str))
    
    def get_operation(self, operation_id: str) -> Optional[Operation]:
        """Get operation by ID"""
        operation_file = self.operations_dir / f"{operation_id}.json"
        if not operation_file.exists():
            return None
        
        try:
            data = json.loads(operation_file.read_text())
            data["status"] = OperationStatus(data["status"])
            return Operation(**data)
        except Exception:
            return None
    
    def update_operation(
        self,
        operation_id: str,
        status: Optional[OperationStatus] = None,
        result: Optional[Dict] = None,
        error: Optional[str] = None
    ):
        """Update operation status"""
        operation = self.get_operation(operation_id)
        if not operation:
            return
        
        if status:
            operation.status = status
            if status == OperationStatus.RUNNING and not operation.started:
                operation.started = datetime.now().isoformat()
            elif status in (OperationStatus.COMPLETED, OperationStatus.FAILED, OperationStatus.CANCELLED):
                operation.completed = datetime.now().isoformat()
        
        if result is not None:
            operation.result = result
        
        if error:
            operation.error = error
        
        self.save_operation(operation)
    
    def list_operations(self, status: Optional[OperationStatus] = None) -> List[Operation]:
        """List all operations, optionally filtered by status"""
        operations = []
        for operation_file in self.operations_dir.glob("*.json"):
            try:
                data = json.loads(operation_file.read_text())
                data["status"] = OperationStatus(data["status"])
                operation = Operation(**data)
                if status is None or operation.status == status:
                    operations.append(operation)
            except Exception:
                continue
        
        return sorted(operations, key=lambda op: op.created, reverse=True)
    
    def cancel_operation(self, operation_id: str) -> bool:
        """Cancel running operation"""
        operation = self.get_operation(operation_id)
        if not operation:
            return False
        
        if operation.status not in (OperationStatus.PENDING, OperationStatus.RUNNING):
            return False
        
        # Try to kill process if PID available
        if operation.pid:
            try:
                os.kill(operation.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
        
        self.update_operation(operation_id, status=OperationStatus.CANCELLED)
        return True
    
    def cleanup_old_operations(self, days: int = 7):
        """Remove operations older than specified days"""
        cutoff = datetime.now().timestamp() - (days * 24 * 60 * 60)
        for operation_file in self.operations_dir.glob("*.json"):
            try:
                if operation_file.stat().st_mtime < cutoff:
                    operation_file.unlink()
            except Exception:
                pass


