# Makefile for AVX-512 WiFi Cracker
# ===================================

# Makefile for WiFi Cracker
# ===========================

CC = gcc
COMMON_CFLAGS = -O3 -march=native -fopenmp -Wall -Wextra
SHARED_FLAGS = -shared -fPIC
LDFLAGS = -lpthread -lcrypto -lssl

# Detect CPU features
CPU_INFO := $(shell cat /proc/cpuinfo 2>/dev/null)

# Check for AVX-512 support
HAS_AVX512 := $(shell echo "$(CPU_INFO)" | grep -o "avx512f" | head -1)
# Check for AVX2 support
HAS_AVX2 := $(shell echo "$(CPU_INFO)" | grep -o "avx2" | head -1)
# Check for AVX support
HAS_AVX := $(shell echo "$(CPU_INFO)" | grep -o "avx" | head -1)

ifeq ($(HAS_AVX512), avx512f)
    TARGET_CRACKER = avx512
    CRACKER_CFLAGS = $(COMMON_CFLAGS) -mavx512f -mavx512bw -mavx512vl
    CRACKER_SRC = avx512_cracker.c
    CRACKER_SO = cracker_avx512.so
    CHECK_MSG = "AVX-512 support detected."
else ifeq ($(HAS_AVX2), avx2)
    TARGET_CRACKER = avx2
    CRACKER_CFLAGS = $(COMMON_CFLAGS) -mavx2 -mfma -mfpmath=sse
    CRACKER_SRC = avx2_cracker.c # Assuming avx2_cracker.c exists for AVX2 specific code
    CRACKER_SO = cracker_avx2.so
    CHECK_MSG = "AVX2 support detected."
else ifeq ($(HAS_AVX), avx)
    TARGET_CRACKER = avx
    CRACKER_CFLAGS = $(COMMON_CFLAGS) -mavx
    CRACKER_SRC = avx_cracker.c # Assuming avx_cracker.c exists for AVX specific code
    CRACKER_SO = cracker_avx.so
    CHECK_MSG = "AVX support detected."
else
    TARGET_CRACKER = generic
    CRACKER_CFLAGS = $(COMMON_CFLAGS)
    CRACKER_SRC = generic_cracker.c # Assuming generic_cracker.c exists
    CRACKER_SO = cracker_generic.so
    CHECK_MSG = "No advanced vector instruction set detected. Falling back to generic build."
endif

.PHONY: all clean test install check

all: check $(CRACKER_SO)

check:
	@echo "Checking CPU capabilities..."
	@echo $(CHECK_MSG)

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
	rm -f cracker_avx512.so cracker_avx2.so cracker_avx.so cracker_generic.so \\
		avx512_test avx2_test avx_test generic_test *.o

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

