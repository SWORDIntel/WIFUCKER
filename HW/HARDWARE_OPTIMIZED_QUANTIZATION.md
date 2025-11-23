# Hardware Optimized Quantization: Intel Meteor Lake
## Tactical Computing Division - KYBERLOCK Research

### System Architecture
- **CPU**: Intel Core Ultra 7 165H (Meteor Lake)
  - 6 Performance Cores (Redwood Cove)
  - 8 Efficient Cores (Crestmont)
  - 2 Low Power Efficient Cores
- **GPU**: Intel Arc Graphics (Xe-LPG)
  - 128 Execution Units
  - XMX (Xe Matrix Extensions) Engines
- **NPU**: Intel AI Boost (NPU 3720)
  - 2 Neural Compute Engines
  - Dedicated INT8/FP16 Acceleration

### Quantization Strategy: INT8 Precision
To maximize throughput and minimize latency for cryptographic cracking and AI wordlist generation, we utilize a strict INT8 quantization pipeline.

#### 1. NPU Offloading (VPU 3720)
- **Target**: Low-latency, continuous inference (e.g., real-time packet analysis).
- **Format**: INT8 (Symmetric).
- **Optimization**: NNCF (Neural Network Compression Framework) with accuracy-aware quantization.

#### 2. GPU Acceleration (Arc Xe-LPG)
- **Target**: High-throughput batch processing (e.g., massive wordlist generation, hash cracking).
- **Format**: INT8 / FP16 Mixed Precision.
- **Extensions**: Intel XMX (Xe Matrix Extensions) for matrix multiplication acceleration.

#### 3. CPU Fallback (VNNI)
- **Target**: General purpose tasks and fallback.
- **Instruction Set**: AVX-VNNI (Vector Neural Network Instructions).
- **Optimization**: OpenVINO CPU plugin with `INFERENCE_PRECISION_HINT=f32` (or `u8` for quantized).

### Pipeline Workflow
1.  **Model Ingestion**: Load FP32/FP16 models (ONNX/OpenVINO IR).
2.  **Calibration**: Run representative dataset through `quantization_pipeline.py`.
3.  **Quantization**: Apply Post-training Optimization (POT) to generate INT8 IR.
4.  **Hardware Targeting**: `quantization_optimizer.py` selects the optimal execution provider (NPU vs GPU) based on workload size.

### Compiler Flags (Reference)
The runtime environment is built with specific flags to enable these features:
- `-march=meteorlake`: Enables AVX-VNNI, AVX2, and other relevant ISAs.
- `-DENABLE_INTEL_NPU=ON`: Builds OpenVINO with NPU plugin.
- `-DENABLE_INTEL_GPU=ON`: Builds OpenVINO with GPU plugin (OpenCL/Level Zero).

### Usage
```python
from davbest.wifi.HW.quantization_pipeline import QuantizationPipeline
from davbest.wifi.HW.quantization_optimizer import HardwareOptimizer

# 1. Optimize Hardware Selection
optimizer = HardwareOptimizer()
target_device = optimizer.select_best_device(task_type="cracking")

# 2. Run Quantization Pipeline
pipeline = QuantizationPipeline(target_device)
pipeline.quantize_model("models/transformer_v2.xml", output_dir="models/int8")
```
