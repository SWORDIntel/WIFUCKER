# Makefile for AMX/AES-NI WiFi Cracker
# =====================================

CC = gcc
COMMON_CFLAGS = -O3 -march=native -fopenmp -Wall -Wextra
SHARED_FLAGS = -shared -fPIC
LDFLAGS = -lpthread -lcrypto -lssl

# Detect CPU features
CPU_INFO := $(shell cat /proc/cpuinfo 2>/dev/null)

# Check for AMX support (Sapphire Rapids+)
HAS_AMX := $(shell echo "$(CPU_INFO)" | grep -o "amx" | head -1)
# Check for AES-NI support
HAS_AESNI := $(shell echo "$(CPU_INFO)" | grep -o "aes" | head -1)
# Check for AVX-512 support
HAS_AVX512 := $(shell echo "$(CPU_INFO)" | grep -o "avx512f" | head -1)
# Check for AVX2 support
HAS_AVX2 := $(shell echo "$(CPU_INFO)" | grep -o "avx2" | head -1)
# Check for AVX support
HAS_AVX := $(shell echo "$(CPU_INFO)" | grep -o "avx" | head -1)

# Priority: AMX+AES-NI > AES-NI+AVX-512 > AES-NI+AVX2 > AES-NI > Generic
ifeq ($(HAS_AMX), amx)
    TARGET_CRACKER = amx_aesni
    CRACKER_CFLAGS = $(COMMON_CFLAGS) -mamx-tile -mamx-int8 -mamx-bf16 -maes -mpclmul
    CRACKER_SRC = amx_pbkdf2.c
    CRACKER_SO = cracker_amx_aesni.so
    CHECK_MSG = "AMX + AES-NI support detected (Optimal - 15-30x speedup)."
else ifeq ($(HAS_AESNI), aes)
    ifeq ($(HAS_AVX512), avx512f)
        TARGET_CRACKER = aesni_avx512
        CRACKER_CFLAGS = $(COMMON_CFLAGS) -maes -mpclmul -mavx512f -mavx512bw -mavx512vl
        CRACKER_SRC = avx512_cracker.c
        CRACKER_SO = cracker_aesni_avx512.so
        CHECK_MSG = "AES-NI + AVX-512 support detected (High - 10-20x speedup)."
    else ifeq ($(HAS_AVX2), avx2)
        TARGET_CRACKER = aesni_avx2
        CRACKER_CFLAGS = $(COMMON_CFLAGS) -maes -mpclmul -mavx2 -mfma
        CRACKER_SRC = avx2_cracker.c
        CRACKER_SO = cracker_aesni_avx2.so
        CHECK_MSG = "AES-NI + AVX2 support detected (Good - 5-10x speedup)."
    else
        TARGET_CRACKER = aesni
        CRACKER_CFLAGS = $(COMMON_CFLAGS) -maes -mpclmul
        CRACKER_SRC = generic_cracker.c
        CRACKER_SO = cracker_aesni.so
        CHECK_MSG = "AES-NI support detected (Moderate - 3-5x speedup)."
    endif
else ifeq ($(HAS_AVX512), avx512f)
    TARGET_CRACKER = avx512
    CRACKER_CFLAGS = $(COMMON_CFLAGS) -mavx512f -mavx512bw -mavx512vl
    CRACKER_SRC = avx512_cracker.c
    CRACKER_SO = cracker_avx512.so
    CHECK_MSG = "AVX-512 support detected."
else ifeq ($(HAS_AVX2), avx2)
    TARGET_CRACKER = avx2
    CRACKER_CFLAGS = $(COMMON_CFLAGS) -mavx2 -mfma -mfpmath=sse
    CRACKER_SRC = avx2_cracker.c
    CRACKER_SO = cracker_avx2.so
    CHECK_MSG = "AVX2 support detected."
else ifeq ($(HAS_AVX), avx)
    TARGET_CRACKER = avx
    CRACKER_CFLAGS = $(COMMON_CFLAGS) -mavx
    CRACKER_SRC = avx_cracker.c
    CRACKER_SO = cracker_avx.so
    CHECK_MSG = "AVX support detected."
else
    TARGET_CRACKER = generic
    CRACKER_CFLAGS = $(COMMON_CFLAGS)
    CRACKER_SRC = generic_cracker.c
    CRACKER_SO = cracker_generic.so
    CHECK_MSG = "No advanced vector instruction set detected. Falling back to generic build."
endif

# Build detection libraries
CPU_DETECTOR_SO = cpu_feature_detector.so
AMX_DETECTOR_SO = amx_detector.so
AESNI_KEY_SO = aesni_key_derivation.so
AMX_TILE_SO = amx_tile_config.so

.PHONY: all clean test install check detectors

all: check detectors $(CRACKER_SO)

check:
	@echo "Checking CPU capabilities..."
	@echo $(CHECK_MSG)

detectors: $(CPU_DETECTOR_SO) $(AMX_DETECTOR_SO) $(AESNI_KEY_SO) $(AMX_TILE_SO)

$(CPU_DETECTOR_SO): cpu_feature_detector.c
	@echo "Compiling CPU feature detector..."
	$(CC) $(COMMON_CFLAGS) $(SHARED_FLAGS) -o $@ $< $(LDFLAGS)
	@echo "Built: $@"

$(AMX_DETECTOR_SO): amx_detector.c
	@echo "Compiling AMX detector..."
	@if echo "$(CPU_INFO)" | grep -q "amx"; then \
		$(CC) $(COMMON_CFLAGS) -mamx-tile -mamx-int8 -mamx-bf16 $(SHARED_FLAGS) -o $@ $< $(LDFLAGS); \
	else \
		echo "[!] AMX not detected, building without AMX intrinsics (will use fallback)"; \
		$(CC) $(COMMON_CFLAGS) $(SHARED_FLAGS) -o $@ $< $(LDFLAGS); \
	fi
	@echo "Built: $@"

$(AESNI_KEY_SO): aesni_key_derivation.c
	@echo "Compiling AES-NI key derivation..."
	@if echo "$(CPU_INFO)" | grep -q "aes"; then \
		$(CC) $(COMMON_CFLAGS) -maes -mpclmul $(SHARED_FLAGS) -o $@ $< $(LDFLAGS); \
	else \
		echo "[!] AES-NI not detected, building without AES-NI intrinsics (will use fallback)"; \
		$(CC) $(COMMON_CFLAGS) $(SHARED_FLAGS) -o $@ $< $(LDFLAGS); \
	fi
	@echo "Built: $@"

$(AMX_TILE_SO): amx_tile_config.c amx_detector.c
	@echo "Compiling AMX tile configuration..."
	@if echo "$(CPU_INFO)" | grep -q "amx"; then \
		$(CC) $(COMMON_CFLAGS) -mamx-tile -mamx-int8 -mamx-bf16 $(SHARED_FLAGS) -o $@ amx_tile_config.c amx_detector.c $(LDFLAGS); \
	else \
		echo "[!] AMX not detected, building without AMX intrinsics (will use fallback)"; \
		$(CC) $(COMMON_CFLAGS) $(SHARED_FLAGS) -o $@ amx_tile_config.c amx_detector.c $(LDFLAGS); \
	fi
	@echo "Built: $@"

$(CRACKER_SO): $(CRACKER_SRC)
	@echo "Compiling $(TARGET_CRACKER) cracker (shared library) from $<..."
	$(CC) $(CRACKER_CFLAGS) $(SHARED_FLAGS) -o $@ $< $(LDFLAGS)
	@echo "Built: $@"

test: $(CRACKER_SRC)
	@echo "Building test binary for $(TARGET_CRACKER)..."
	$(CC) $(CRACKER_CFLAGS) -o $(TARGET_CRACKER)_test $< $(LDFLAGS)
	@echo "Running test for $(TARGET_CRACKER)..."
	./$(TARGET_CRACKER)_test

install: $(CRACKER_SO)
	@echo "Installing $(CRACKER_SO) to current directory (no system install needed)"
	@echo "Python wrapper will load ./$(CRACKER_SO)"

clean:
	rm -f cracker_*.so \\
		cpu_feature_detector.so amx_detector.so aesni_key_derivation.so amx_tile_config.so \\
		*_test *.o

# Advanced optimizations
optimized: CRACKER_CFLAGS += -ffast-math -funroll-loops -fomit-frame-pointer
optimized: $(CRACKER_SO)

# Debug build
debug: CRACKER_CFLAGS = -g -O0 $(CRACKER_CFLAGS) # Prepend debug flags
debug: $(CRACKER_SO)

help:
	@echo "WiFi Cracker Makefile"
	@echo "======================"
	@echo ""
	@echo "Targets:"
	@echo "  all (default) - Build shared library based on detected CPU features"
	@echo "  test          - Build and run test binary for detected CPU features"
	@echo "  optimized     - Build with aggressive optimizations"
	@echo "  debug         - Build with debug symbols"
	@echo "  clean         - Remove built files"
	@echo "  check         - Check CPU capabilities"
	@echo "  install       - Install library (local)"
	@echo ""
	@echo "Requirements:"
	@echo "  - GCC with appropriate CPU feature support"
	@echo "  - OpenSSL development libraries"
	@echo ""
	@echo "Install dependencies:"
	@echo "  Debian/Ubuntu: apt install build-essential libssl-dev"
	@echo "  Fedora/RHEL:   dnf install gcc openssl-devel"

