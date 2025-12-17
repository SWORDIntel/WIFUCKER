import importlib.util
import os
from typing import List


def _module_exists(module_name: str) -> bool:
    """Check if a module can be imported without importing it fully."""
    spec = importlib.util.find_spec(module_name)
    return spec is not None


def _repo_exists(path: str) -> bool:
    """Check if a local repository path exists (used for custom neural stick driver)."""
    return os.path.isdir(path)


def detect_accelerators() -> List[str]:
    """Detect available hardware acceleration back‑ends.

    Returns a list of identifiers such as "openvino_npu", "flex_fabric",
    "neural_stick", "tensorrt" and "langchain". The function is tolerant
    to missing packages – it simply skips them.
    """
    accelerators: List[str] = []

    # 1. Intel OpenVINO NPU SDK
    try:
        import openvino.runtime as ov

        core = ov.Core()
        devices = core.available_devices

        # Check for NPU
        if any(dev.upper().startswith("NPU") for dev in devices):
            accelerators.append("openvino_npu")

        # Check for NCS2 (MYRIAD)
        myriad_count = sum(1 for dev in devices if "MYRIAD" in dev.upper())
        if myriad_count > 0:
            if myriad_count > 1:
                accelerators.append(f"dual_neural_stick_x{myriad_count}")
            else:
                accelerators.append("neural_stick")
    except Exception:
        pass

    # 2. Flex Processing Fabric (check if module exists)
    if _module_exists("flex_fabric"):
        accelerators.append("flex_fabric")

    # 3. Custom Neural Stick driver (NUC2.1 repo)
    # Assume the repo is cloned under the project root at davbest/wifi/nn_stick
    repo_path = os.path.join(os.path.dirname(__file__), "nn_stick")
    if _repo_exists(repo_path):
        # Try importing a known entry point from the driver, e.g., ``nuc21``
        if _module_exists("nn_stick.nuc21"):
            accelerators.append("neural_stick")

    # 4. NVIDIA TensorRT
    if _module_exists("tensorrt"):
        accelerators.append("tensorrt")

    # 5. Optional LangChain (example of additional package)
    if _module_exists("langchain"):
        accelerators.append("langchain")

    return accelerators
