#!/usr/bin/env python3
"""
JSON Output Formatter
=====================

Provides structured JSON output for CLI commands to enable agent automation.
"""

import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import IntEnum


class ExitCode(IntEnum):
    """Standard exit codes for CLI commands"""
    SUCCESS = 0
    GENERAL_ERROR = 1
    INVALID_ARGS = 2
    PERMISSION_DENIED = 3
    NOT_FOUND = 4
    TIMEOUT = 5
    HARDWARE_ERROR = 6
    NETWORK_ERROR = 7


class ErrorCode:
    """Error code constants"""
    INVALID_PCAP = "INVALID_PCAP"
    NO_HANDSHAKES = "NO_HANDSHAKES"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    INTERFACE_NOT_FOUND = "INTERFACE_NOT_FOUND"
    MONITOR_MODE_FAILED = "MONITOR_MODE_FAILED"
    CAPTURE_FAILED = "CAPTURE_FAILED"
    CRACK_FAILED = "CRACK_FAILED"
    HARDWARE_ERROR = "HARDWARE_ERROR"
    NETWORK_ERROR = "NETWORK_ERROR"
    TIMEOUT = "TIMEOUT"
    INVALID_ARGS = "INVALID_ARGS"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    NOT_FOUND = "NOT_FOUND"
    OPERATION_CANCEL_FAILED = "OPERATION_CANCEL_FAILED"
    MISSING_TOOLS = "MISSING_TOOLS"
    NO_INTERFACES = "NO_INTERFACES"
    DEVICE_NOT_FOUND = "DEVICE_NOT_FOUND"
    CANCELLED = "CANCELLED"


class JSONOutputFormatter:
    """Format command output as structured JSON"""
    
    def __init__(self):
        self.start_time = datetime.now()
        self.exit_code = ExitCode.SUCCESS
    
    def format_result(
        self,
        command: str,
        success: bool,
        data: Dict[str, Any],
        errors: Optional[List[Dict[str, Any]]] = None,
        warnings: Optional[List[str]] = None,
        operation_id: Optional[str] = None
    ) -> str:
        """
        Format result as JSON
        
        Args:
            command: Command name
            success: Whether command succeeded
            data: Result data
            errors: List of error dictionaries with code, message, details, suggestions
            warnings: List of warning messages
            operation_id: Optional operation ID for tracking
            
        Returns:
            JSON string
        """
        duration = (datetime.now() - self.start_time).total_seconds()
        
        output = {
            "success": success,
            "command": command,
            "timestamp": datetime.now().isoformat(),
            "data": data,
            "errors": errors or [],
            "warnings": warnings or [],
            "metadata": {
                "duration": duration,
                "exit_code": int(self.exit_code)
            }
        }
        
        if operation_id:
            output["operation_id"] = operation_id
        
        return json.dumps(output, indent=2, default=str)
    
    def format_error(
        self,
        command: str,
        error_code: str,
        message: str,
        details: Optional[str] = None,
        suggestions: Optional[List[str]] = None,
        exit_code: ExitCode = ExitCode.GENERAL_ERROR
    ) -> str:
        """
        Format error as JSON
        
        Args:
            command: Command name
            error_code: Error code constant
            message: Error message
            details: Additional error details
            suggestions: List of suggested actions
            exit_code: Exit code to use
            
        Returns:
            JSON string
        """
        self.exit_code = exit_code
        
        error = {
            "code": error_code,
            "message": message
        }
        
        if details:
            error["details"] = details
        
        if suggestions:
            error["suggestions"] = suggestions
        
        return self.format_result(
            command=command,
            success=False,
            data={},
            errors=[error]
        )
    
    def set_exit_code(self, exit_code: ExitCode):
        """Set exit code"""
        self.exit_code = exit_code


