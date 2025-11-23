# Makefile for AVX-512 WiFi Cracker
# ===================================

CC = gcc
CFLAGS = -O3 -march=native -mavx512f -mavx512bw -mavx512vl -fopenmp -Wall -Wextra
LDFLAGS = -lpthread -lcrypto -lssl
SHARED_FLAGS = -shared -fPIC

# Detect CPU features
CPU_INFO := $(shell cat /proc/cpuinfo 2>/dev/null)

# Check for AVX-512 support
HAS_AVX512 := $(shell echo "$(CPU_INFO)" | grep -o "avx512f" | head -1)

.PHONY: all clean test install check

all: check avx512_cracker.so

check:
	@echo "Checking CPU capabilities..."
	@if [ -z "$(HAS_AVX512)" ]; then \
		echo "Warning: AVX-512 not detected on this CPU"; \
		echo "Module will compile but may not run on this machine"; \
	else \
		echo "AVX-512 support detected: $(HAS_AVX512)"; \
	fi

avx512_cracker.so: avx512_cracker.c
	@echo "Compiling AVX-512 cracker (shared library)..."
	$(CC) $(CFLAGS) $(SHARED_FLAGS) -o $@ $< $(LDFLAGS)
	@echo "Built: $@"

test: avx512_cracker.c
	@echo "Building test binary..."
	$(CC) $(CFLAGS) -o avx512_test $< $(LDFLAGS)
	@echo "Running test..."
	./avx512_test

install: avx512_cracker.so
	@echo "Installing to current directory (no system install needed)"
	@echo "Python wrapper will load ./avx512_cracker.so"

clean:
	rm -f avx512_cracker.so avx512_test *.o

# Advanced optimizations
optimized: CFLAGS += -ffast-math -funroll-loops -fomit-frame-pointer
optimized: avx512_cracker.so

# Debug build
debug: CFLAGS = -g -O0 -march=native -mavx512f -mavx512bw -mavx512vl -Wall -Wextra
debug: avx512_cracker.so

help:
	@echo "AVX-512 WiFi Cracker Makefile"
	@echo "=============================="
	@echo ""
	@echo "Targets:"
	@echo "  all (default) - Build shared library"
	@echo "  test          - Build and run test binary"
	@echo "  optimized     - Build with aggressive optimizations"
	@echo "  debug         - Build with debug symbols"
	@echo "  clean         - Remove built files"
	@echo "  check         - Check CPU capabilities"
	@echo "  install       - Install library (local)"
	@echo ""
	@echo "Requirements:"
	@echo "  - GCC with AVX-512 support"
	@echo "  - OpenSSL development libraries"
	@echo "  - CPU with AVX-512 support"
	@echo ""
	@echo "Install dependencies:"
	@echo "  Debian/Ubuntu: apt install build-essential libssl-dev"
	@echo "  Fedora/RHEL:   dnf install gcc openssl-devel"
