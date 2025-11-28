"""
Hardware Optimizer Module
=========================

Selects the optimal hardware accelerator (NPU, GPU, CPU) for specific tasks
based on the Intel Meteor Lake architecture capabilities.
"""

import os
import logging
from typing import Dict, List, Optional
from rich.console import Console

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("HW_Optimizer")
console = Console()


class HardwareOptimizer:
    """
    Analyzes available hardware and selects the best execution provider
    for a given task type.
    """

    def __init__(self):
        self.cpu_info = self._get_cpu_info()
        self.has_npu = self._check_npu()
        self.has_arc_gpu = self._check_arc_gpu()

    def _get_cpu_info(self) -> str:
        """Get CPU model name."""
        try:
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if "model name" in line:
                        return line.split(":")[1].strip()
        except:
            return "Unknown CPU"
        return "Unknown CPU"

    def _check_npu(self) -> bool:
        """Check for Intel NPU (VPU)."""
        # Simple check for NPU device presence or driver
        # In a real scenario, we'd check via OpenVINO Core, but this is a heuristic
        return os.path.exists("/dev/accel/accel0") or os.path.exists("/sys/class/accel")

    def _check_arc_gpu(self) -> bool:
        """Check for Intel Arc Graphics."""
        try:
            # Check lspci for Intel Graphics
            import subprocess

            result = subprocess.run(["lspci"], capture_output=True, text=True)
            return "Intel" in result.stdout and (
                "Graphics" in result.stdout or "VGA" in result.stdout
            )
        except:
            return False

    def select_best_device(self, task_type: str) -> str:
        """
        Selects the best device for the task.

        Args:
            task_type: 'cracking', 'wordlist', 'inference', 'realtime'

        Returns:
            OpenVINO device string (e.g., 'NPU', 'GPU', 'CPU')
        """
        logger.info(f"Selecting device for task: {task_type}")

        # Priority Logic for Meteor Lake

        if task_type == "realtime":
            # NPU is best for low-latency, continuous background tasks
            if self.has_npu:
                console.print("[bold green]✓ Routing to NPU (Low Latency)[/]")
                return "NPU"
            elif self.has_arc_gpu:
                return "GPU"

        elif task_type == "wordlist" or task_type == "cracking":
            # GPU is best for high-throughput batch processing
            if self.has_arc_gpu:
                console.print("[bold green]✓ Routing to Arc GPU (High Throughput)[/]")
                return "GPU"
            elif self.has_npu:
                # NPU is decent fallback for matrix ops
                return "NPU"

        elif task_type == "inference":
            # General inference
            if self.has_npu:
                return "NPU"
            if self.has_arc_gpu:
                return "GPU"

        # Fallback to CPU with VNNI
        console.print("[yellow]⚠ Falling back to CPU (AVX-VNNI)[/]")
        return "CPU"

    def get_optimization_config(self, device: str) -> Dict:
        """Get OpenVINO config for the selected device."""
        config = {}

        if device == "CPU":
            # Enable VNNI and AVX512/AVX2 optimizations
            config["INFERENCE_PRECISION_HINT"] = "f32"  # or u8 if quantized
            config["NUM_STREAMS"] = "AUTO"

        elif device == "GPU":
            # Arc GPU optimizations
            config["PERFORMANCE_HINT"] = "THROUGHPUT"
            config["GPU_DISABLE_SYCL_EVENT"] = "YES"  # Reduce overhead

        elif device == "NPU":
            # NPU optimizations
            config["PERFORMANCE_HINT"] = "LATENCY"
            config["NPU_COMPILATION_MODE_HINT"] = "DEEP"

        return config

    def select_optimal_device(self, preferred: List[str] = None) -> str:
        """
        Selects the optimal device from a preferred list or auto-detects.

        Args:
            preferred: List of preferred devices (e.g. ['NPU', 'GPU'])

        Returns:
            Best available device string
        """
        if preferred:
            for dev in preferred:
                if dev.upper() == "NPU" and self.has_npu:
                    return "NPU"
                if dev.upper() == "GPU" and self.has_arc_gpu:
                    return "GPU"
                if dev.upper() == "CPU":
                    return "CPU"

        # Auto-selection if no preference matches or is provided
        if self.has_arc_gpu:
            return "GPU"
        if self.has_npu:
            return "NPU"

        return "CPU"
