#!/usr/bin/env python3
"""
Hardware Detection for OpenVINO Acceleration
=============================================

Detects and configures available hardware accelerators:
- Intel NPU (Neural Processing Unit) - Military-grade AI acceleration
- Intel NCS2 (Neural Compute Stick 2) - USB AI accelerator
- Intel ARC GPU - High-performance graphics acceleration
- CPU fallback

Features:
- Automatic device detection
- Performance benchmarking
- Multi-device configuration
- Device capability reporting
"""

import os
import subprocess
import platform
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class DeviceType(Enum):
    """Supported hardware device types"""

    NPU = "NPU"  # Neural Processing Unit (military-grade)
    NCS2 = "MYRIAD"  # Neural Compute Stick 2
    ARC_GPU = "GPU"  # Intel ARC GPU
    CPU = "CPU"  # CPU fallback
    MULTI = "MULTI"  # Multi-device execution


@dataclass
class DeviceInfo:
    """Information about detected hardware device"""

    device_type: DeviceType
    device_name: str
    is_available: bool
    performance_hint: str  # THROUGHPUT, LATENCY, CUMULATIVE_THROUGHPUT
    supports_batching: bool
    max_batch_size: int
    inference_precision: str  # FP32, FP16, INT8
    metrics: Dict[str, float] = None


class HardwareDetector:
    """
    Detects and configures OpenVINO hardware accelerators.

    Prioritizes devices: NPU > NCS2 > ARC GPU > CPU
    """

    def __init__(self):
        """Initialize hardware detector"""
        self.openvino_available = False
        self.core = None
        self.detected_devices: List[DeviceInfo] = []

        self._init_openvino()

    def _init_openvino(self):
        """Initialize OpenVINO runtime"""
        try:
            from openvino.runtime import Core

            self.core = Core()
            self.openvino_available = True
            print("[+] OpenVINO runtime initialized successfully")
        except ImportError:
            print("[!] OpenVINO not found. Install with: pip install openvino")
            print("[!] Falling back to CPU-only mode")
        except Exception as e:
            print(f"[!] OpenVINO initialization failed: {e}")

    def detect_devices(self) -> List[DeviceInfo]:
        """
        Detect all available hardware accelerators.

        Returns:
            List of detected devices
        """
        print("\n[*] Detecting hardware accelerators...")

        if not self.openvino_available or not self.core:
            # Fallback: CPU only
            cpu_info = DeviceInfo(
                device_type=DeviceType.CPU,
                device_name="CPU (Fallback)",
                is_available=True,
                performance_hint="THROUGHPUT",
                supports_batching=True,
                max_batch_size=128,
                inference_precision="FP32",
            )
            self.detected_devices = [cpu_info]
            print("[!] Using CPU fallback mode")
            return self.detected_devices

        available_devices = self.core.available_devices

        print(f"[*] Available OpenVINO devices: {available_devices}")

        # Detect NPU
        if "NPU" in available_devices:
            npu_info = self._detect_npu()
            if npu_info:
                self.detected_devices.append(npu_info)

        # Detect NCS2 (MYRIAD)
        myriad_devices = [d for d in available_devices if "MYRIAD" in d]
        if len(myriad_devices) > 1:
            print(f"[+] DUAL NEURAL COMPUTE STICKS DETECTED ({len(myriad_devices)}x NCS2)")
            print("    ✓ Custom Driver / OpenVINO Multi-Stick Support Active")

        for device in myriad_devices:
            ncs2_info = self._detect_ncs2(device)
            if ncs2_info:
                self.detected_devices.append(ncs2_info)

        # Detect ARC GPU
        if "GPU" in available_devices:
            gpu_info = self._detect_arc_gpu()
            if gpu_info:
                self.detected_devices.append(gpu_info)

        # Always add CPU as fallback
        cpu_info = self._detect_cpu()
        self.detected_devices.append(cpu_info)

        # Print summary
        self._print_device_summary()

        return self.detected_devices

    def _detect_npu(self) -> Optional[DeviceInfo]:
        """Detect Intel NPU (Neural Processing Unit)"""
        try:
            print("[*] Detecting Intel NPU (Military-grade accelerator)...")

            # Get NPU properties
            device_name = "NPU"
            full_name = self.core.get_property("NPU", "FULL_DEVICE_NAME")

            npu_info = DeviceInfo(
                device_type=DeviceType.NPU,
                device_name=f"Intel NPU - {full_name}",
                is_available=True,
                performance_hint="THROUGHPUT",
                supports_batching=True,
                max_batch_size=256,  # NPU can handle large batches
                inference_precision="INT8",  # NPU optimized for INT8
            )

            print(f"[+] Intel NPU detected: {full_name}")
            print("    ✓ Military-grade AI acceleration")
            print("    ✓ Optimized for high throughput")
            print("    ✓ Low power consumption")

            return npu_info

        except Exception as e:
            print(f"[-] NPU detection failed: {e}")
            return None

    def _detect_ncs2(self, device_id: str) -> Optional[DeviceInfo]:
        """Detect Intel Neural Compute Stick 2"""
        try:
            print(f"[*] Detecting Intel NCS2: {device_id}...")

            # Get NCS2 properties
            full_name = self.core.get_property(device_id, "FULL_DEVICE_NAME")

            ncs2_info = DeviceInfo(
                device_type=DeviceType.NCS2,
                device_name=f"Intel NCS2 - {full_name}",
                is_available=True,
                performance_hint="THROUGHPUT",
                supports_batching=True,
                max_batch_size=32,  # NCS2 has limited memory
                inference_precision="FP16",  # NCS2 optimized for FP16
            )

            print(f"[+] Intel NCS2 detected: {full_name}")
            print("    ✓ USB AI accelerator")
            print("    ✓ Portable acceleration")
            print("    ✓ FP16 optimized")

            return ncs2_info

        except Exception as e:
            print(f"[-] NCS2 detection failed: {e}")
            return None

    def _detect_arc_gpu(self) -> Optional[DeviceInfo]:
        """Detect Intel ARC GPU"""
        try:
            print("[*] Detecting Intel ARC GPU...")

            # Get GPU properties
            full_name = self.core.get_property("GPU", "FULL_DEVICE_NAME")

            # Check if it's an ARC GPU
            is_arc = "ARC" in full_name.upper() or "A" in full_name.upper()

            gpu_info = DeviceInfo(
                device_type=DeviceType.ARC_GPU,
                device_name=f"Intel GPU - {full_name}",
                is_available=True,
                performance_hint="THROUGHPUT",
                supports_batching=True,
                max_batch_size=512,  # GPU can handle very large batches
                inference_precision="FP16",  # GPU optimized for FP16
            )

            print(f"[+] Intel GPU detected: {full_name}")
            if is_arc:
                print("    ✓ ARC GPU - High performance gaming/AI GPU")
            print("    ✓ High throughput acceleration")
            print("    ✓ Large batch processing")

            return gpu_info

        except Exception as e:
            print(f"[-] GPU detection failed: {e}")
            return None

    def _detect_cpu(self) -> DeviceInfo:
        """Detect CPU capabilities"""
        try:
            full_name = self.core.get_property("CPU", "FULL_DEVICE_NAME")
        except:
            full_name = platform.processor() or "Unknown CPU"

        cpu_info = DeviceInfo(
            device_type=DeviceType.CPU,
            device_name=f"CPU - {full_name}",
            is_available=True,
            performance_hint="THROUGHPUT",
            supports_batching=True,
            max_batch_size=128,
            inference_precision="FP32",
        )

        print(f"[+] CPU available: {full_name}")

        return cpu_info

    def _print_device_summary(self):
        """Print summary of detected devices"""
        print("\n" + "=" * 70)
        print("HARDWARE ACCELERATION SUMMARY")
        print("=" * 70)

        for i, device in enumerate(self.detected_devices, 1):
            print(f"\n{i}. {device.device_name}")
            print(f"   Type: {device.device_type.value}")
            print(f"   Status: {'✓ Available' if device.is_available else '✗ Unavailable'}")
            print(f"   Performance: {device.performance_hint}")
            print(f"   Batch Size: {device.max_batch_size}")
            print(f"   Precision: {device.inference_precision}")

        print("\n" + "=" * 70 + "\n")

    def get_optimal_device(self, prefer_hardware: bool = True) -> DeviceInfo:
        """
        Get the optimal device for WiFi cracking.

        Priority: NPU > NCS2 > ARC GPU > CPU

        Args:
            prefer_hardware: If True, prefer hardware accelerators over CPU

        Returns:
            Best available device
        """
        if not self.detected_devices:
            self.detect_devices()

        if not prefer_hardware:
            # Find CPU
            for device in self.detected_devices:
                if device.device_type == DeviceType.CPU:
                    return device

        # Priority order
        priority = [DeviceType.NPU, DeviceType.NCS2, DeviceType.ARC_GPU, DeviceType.CPU]

        for device_type in priority:
            for device in self.detected_devices:
                if device.device_type == device_type and device.is_available:
                    print(f"\n[+] Selected device: {device.device_name}")
                    return device

        # Fallback to first available
        return self.detected_devices[0] if self.detected_devices else None

    def get_multi_device_config(self) -> Optional[Dict[str, int]]:
        """
        Get configuration for multi-device execution.

        Combines multiple accelerators for maximum performance.

        Returns:
            Dictionary mapping device types to optimal batch sizes, or None
        """
        if not self.detected_devices or len(self.detected_devices) < 2:
            return None

        # Build multi-device config
        multi_config = {}

        for device in self.detected_devices:
            if device.is_available and device.device_type != DeviceType.CPU:
                # Assign batch sizes based on device type
                if device.device_type == DeviceType.NPU:
                    multi_config["NPU"] = device.max_batch_size
                elif device.device_type == DeviceType.ARC_GPU:
                    multi_config["GPU"] = device.max_batch_size
                elif device.device_type == DeviceType.NCS2:
                    multi_config["MYRIAD"] = device.max_batch_size

        if len(multi_config) >= 2:
            print(f"[+] Multi-device configuration: {multi_config}")
            return multi_config

        return None

    def benchmark_device(self, device: DeviceInfo, model_path: str) -> Dict[str, float]:
        """
        Benchmark device performance.

        Args:
            device: Device to benchmark
            model_path: Path to model for benchmarking

        Returns:
            Performance metrics
        """
        print(f"\n[*] Benchmarking {device.device_name}...")

        if not self.openvino_available or not os.path.exists(model_path):
            print("[!] Skipping benchmark - prerequisites not met")
            return {}

        try:
            import time

            # Load and compile model
            model = self.core.read_model(model_path)
            compiled_model = self.core.compile_model(
                model,
                device.device_type.value,
                {
                    "PERFORMANCE_HINT": device.performance_hint,
                    "INFERENCE_PRECISION_HINT": device.inference_precision,
                },
            )

            # Create dummy input
            input_layer = compiled_model.input(0)
            dummy_input = np.zeros(input_layer.shape)

            # Warmup
            for _ in range(10):
                compiled_model([dummy_input])

            # Benchmark
            num_iterations = 100
            start_time = time.time()

            for _ in range(num_iterations):
                compiled_model([dummy_input])

            elapsed = time.time() - start_time

            metrics = {
                "throughput": num_iterations / elapsed,
                "latency": (elapsed / num_iterations) * 1000,  # ms
                "total_time": elapsed,
            }

            print(f"[+] Throughput: {metrics['throughput']:.2f} inferences/sec")
            print(f"[+] Latency: {metrics['latency']:.2f} ms")

            return metrics

        except Exception as e:
            print(f"[-] Benchmark failed: {e}")
            return {}


def main():
    """Example usage"""
    detector = HardwareDetector()

    # Detect all devices
    devices = detector.detect_devices()

    # Get optimal device
    optimal = detector.get_optimal_device()

    print(f"\n[+] Optimal device for WiFi cracking: {optimal.device_name}")

    # Try multi-device
    multi_config = detector.get_multi_device_config()
    if multi_config:
        print(f"[+] Multi-device available: {multi_config}")


if __name__ == "__main__":
    main()
