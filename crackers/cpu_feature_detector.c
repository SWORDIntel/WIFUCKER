/*
 * CPU Feature Detector
 * ====================
 *
 * Comprehensive CPU feature detection for AMX, AES-NI, and other instruction sets.
 * Provides fallback strategies for optimal performance on all Intel CPUs.
 *
 * Features:
 * - AMX (Advanced Matrix Extensions) detection
 * - AES-NI detection
 * - AVX-512, AVX2, AVX detection
 * - Intelligent fallback selection
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <cpuid.h>
#include <x86intrin.h>

/* CPU feature flags */
typedef struct {
    int has_amx;
    int has_amx_bf16;
    int has_amx_int8;
    int has_amx_tile;
    int has_aesni;
    int has_pclmulqdq;
    int has_avx512f;
    int has_avx512bw;
    int has_avx512vl;
    int has_avx2;
    int has_avx;
    int has_sse4_2;
    
    /* CPU info */
    char vendor[13];
    char brand[64];
    int family;
    int model;
    int stepping;
} cpu_features_t;

/*
 * Execute CPUID instruction
 */
static void cpuid(uint32_t leaf, uint32_t subleaf,
                  uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
    __cpuid_count(leaf, subleaf, *eax, *ebx, *ecx, *edx);
}

/*
 * Check if AMX is supported
 * AMX requires:
 * - CPUID.7.EDX[bit 22] = AMX-BF16
 * - CPUID.7.EDX[bit 23] = AMX-TILE
 * - CPUID.7.EDX[bit 24] = AMX-INT8
 * - XSAVE support for AMX state
 */
static int check_amx_support() {
    uint32_t eax, ebx, ecx, edx;
    
    /* Check for AMX features (CPUID leaf 7, subleaf 0) */
    eax = 7;
    ecx = 0;
    cpuid(7, 0, &eax, &ebx, &ecx, &edx);
    
    /* Check AMX bits in EDX */
    int has_amx_bf16 = (edx >> 22) & 1;  /* Bit 22: AMX-BF16 */
    int has_amx_tile = (edx >> 23) & 1;  /* Bit 23: AMX-TILE */
    int has_amx_int8 = (edx >> 24) & 1;  /* Bit 24: AMX-INT8 */
    
    if (!(has_amx_bf16 || has_amx_tile || has_amx_int8)) {
        return 0;
    }
    
    /* Check XSAVE support for AMX state management */
    eax = 0xd;
    ecx = 0;
    cpuid(0xd, 0, &eax, &ebx, &ecx, &edx);
    
    /* Check if XSAVE is supported */
    if (!(ecx & (1 << 1))) {  /* XSAVE bit */
        return 0;
    }
    
    /* Check AMX state component (XCR0 bit 18) */
    eax = 0xd;
    ecx = 1;  /* XCR0 register */
    cpuid(0xd, 1, &eax, &ebx, &ecx, &edx);
    
    if (!(eax & (1 << 18))) {  /* AMX state bit */
        return 0;
    }
    
    return 1;
}

/*
 * Check AMX sub-features
 */
static void check_amx_features(cpu_features_t *features) {
    uint32_t eax, ebx, ecx, edx;
    
    eax = 7;
    ecx = 0;
    cpuid(7, 0, &eax, &ebx, &ecx, &edx);
    
    features->has_amx_bf16 = (edx >> 22) & 1;
    features->has_amx_tile = (edx >> 23) & 1;
    features->has_amx_int8 = (edx >> 24) & 1;
    features->has_amx = features->has_amx_bf16 || features->has_amx_tile || features->has_amx_int8;
}

/*
 * Check AES-NI support
 * AES-NI: CPUID.1.ECX[bit 25] = AES
 */
static int check_aesni_support() {
    uint32_t eax, ebx, ecx, edx;
    
    eax = 1;
    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    
    return (ecx >> 25) & 1;  /* AES-NI bit */
}

/*
 * Check PCLMULQDQ support (for GHASH acceleration)
 * PCLMULQDQ: CPUID.1.ECX[bit 1]
 */
static int check_pclmulqdq_support() {
    uint32_t eax, ebx, ecx, edx;
    
    eax = 1;
    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    
    return (ecx >> 1) & 1;  /* PCLMULQDQ bit */
}

/*
 * Check AVX-512 support
 */
static void check_avx512_features(cpu_features_t *features) {
    uint32_t eax, ebx, ecx, edx;
    
    eax = 7;
    ecx = 0;
    cpuid(7, 0, &eax, &ebx, &ecx, &edx);
    
    features->has_avx512f = (ebx >> 16) & 1;   /* AVX-512F */
    features->has_avx512bw = (ebx >> 30) & 1;  /* AVX-512BW */
    features->has_avx512vl = (ebx >> 31) & 1;   /* AVX-512VL */
}

/*
 * Check AVX2 support
 */
static int check_avx2_support() {
    uint32_t eax, ebx, ecx, edx;
    
    eax = 7;
    ecx = 0;
    cpuid(7, 0, &eax, &ebx, &ecx, &edx);
    
    return (ebx >> 5) & 1;  /* AVX2 bit */
}

/*
 * Check AVX support
 */
static int check_avx_support() {
    uint32_t eax, ebx, ecx, edx;
    
    eax = 1;
    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    
    return (ecx >> 28) & 1;  /* AVX bit */
}

/*
 * Get CPU vendor string
 */
static void get_cpu_vendor(cpu_features_t *features) {
    uint32_t eax, ebx, ecx, edx;
    
    eax = 0;
    cpuid(0, 0, &eax, &ebx, &ecx, &edx);
    
    memcpy(&features->vendor[0], &ebx, 4);
    memcpy(&features->vendor[4], &edx, 4);
    memcpy(&features->vendor[8], &ecx, 4);
    features->vendor[12] = '\0';
}

/*
 * Get CPU brand string
 */
static void get_cpu_brand(cpu_features_t *features) {
    uint32_t eax, ebx, ecx, edx;
    char brand_buf[48];
    int i;
    
    /* CPUID leaves 0x80000002-0x80000004 contain brand string */
    for (i = 0; i < 3; i++) {
        eax = 0x80000002 + i;
        cpuid(eax, 0, &eax, &ebx, &ecx, &edx);
        
        memcpy(&brand_buf[i * 16], &eax, 4);
        memcpy(&brand_buf[i * 16 + 4], &ebx, 4);
        memcpy(&brand_buf[i * 16 + 8], &ecx, 4);
        memcpy(&brand_buf[i * 16 + 12], &edx, 4);
    }
    
    brand_buf[47] = '\0';
    strncpy(features->brand, brand_buf, 63);
    features->brand[63] = '\0';
    
    /* Trim whitespace */
    for (i = 47; i >= 0 && (brand_buf[i] == ' ' || brand_buf[i] == '\0'); i--) {
        features->brand[i] = '\0';
    }
}

/*
 * Get CPU family, model, stepping
 */
static void get_cpu_info(cpu_features_t *features) {
    uint32_t eax, ebx, ecx, edx;
    
    eax = 1;
    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    
    features->stepping = eax & 0xf;
    features->model = (eax >> 4) & 0xf;
    features->family = (eax >> 8) & 0xf;
    
    if (features->family == 0xf) {
        features->family += (eax >> 20) & 0xff;
    }
    if (features->family == 0x6 || features->family == 0xf) {
        features->model += ((eax >> 16) & 0xf) << 4;
    }
}

/*
 * Detect all CPU features
 */
cpu_features_t* detect_cpu_features() {
    cpu_features_t *features = calloc(1, sizeof(cpu_features_t));
    if (!features) {
        return NULL;
    }
    
    /* Get basic CPU info */
    get_cpu_vendor(features);
    get_cpu_brand(features);
    get_cpu_info(features);
    
    /* Detect instruction sets */
    features->has_amx = check_amx_support();
    if (features->has_amx) {
        check_amx_features(features);
    }
    
    features->has_aesni = check_aesni_support();
    features->has_pclmulqdq = check_pclmulqdq_support();
    
    check_avx512_features(features);
    features->has_avx2 = check_avx2_support();
    features->has_avx = check_avx_support();
    
    /* SSE4.2 check */
    uint32_t eax, ebx, ecx, edx;
    eax = 1;
    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    features->has_sse4_2 = (ecx >> 20) & 1;
    
    return features;
}

/*
 * Print CPU features (for debugging)
 */
void print_cpu_features(cpu_features_t *features) {
    if (!features) {
        printf("CPU features: NULL\n");
        return;
    }
    
    printf("CPU Features Detection\n");
    printf("=====================\n");
    printf("Vendor: %s\n", features->vendor);
    printf("Brand:  %s\n", features->brand);
    printf("Family: %d, Model: %d, Stepping: %d\n",
           features->family, features->model, features->stepping);
    printf("\n");
    
    printf("Instruction Sets:\n");
    printf("  AMX:        %s", features->has_amx ? "YES" : "NO");
    if (features->has_amx) {
        printf(" (BF16: %s, TILE: %s, INT8: %s)",
               features->has_amx_bf16 ? "YES" : "NO",
               features->has_amx_tile ? "YES" : "NO",
               features->has_amx_int8 ? "YES" : "NO");
    }
    printf("\n");
    
    printf("  AES-NI:     %s\n", features->has_aesni ? "YES" : "NO");
    printf("  PCLMULQDQ:  %s\n", features->has_pclmulqdq ? "YES" : "NO");
    printf("  AVX-512F:   %s\n", features->has_avx512f ? "YES" : "NO");
    printf("  AVX-512BW:  %s\n", features->has_avx512bw ? "YES" : "NO");
    printf("  AVX-512VL:  %s\n", features->has_avx512vl ? "YES" : "NO");
    printf("  AVX2:       %s\n", features->has_avx2 ? "YES" : "NO");
    printf("  AVX:        %s\n", features->has_avx ? "YES" : "NO");
    printf("  SSE4.2:     %s\n", features->has_sse4_2 ? "YES" : "NO");
    printf("\n");
    
    /* Recommend optimal instruction set */
    printf("Recommended Instruction Set:\n");
    if (features->has_amx && features->has_aesni) {
        printf("  → AMX + AES-NI (Optimal - 15-30x speedup)\n");
    } else if (features->has_aesni && features->has_avx512f) {
        printf("  → AES-NI + AVX-512 (High - 10-20x speedup)\n");
    } else if (features->has_aesni && features->has_avx2) {
        printf("  → AES-NI + AVX2 (Good - 5-10x speedup)\n");
    } else if (features->has_aesni) {
        printf("  → AES-NI only (Moderate - 3-5x speedup)\n");
    } else {
        printf("  → Software fallback (Baseline)\n");
    }
}

/*
 * Free CPU features structure
 */
void free_cpu_features(cpu_features_t *features) {
    if (features) {
        free(features);
    }
}

/*
 * Get optimal instruction set priority
 * Returns: 1=AMX+AES-NI, 2=AES-NI+AVX-512, 3=AES-NI+AVX2, 4=AES-NI, 5=Software
 */
int get_optimal_instruction_set(cpu_features_t *features) {
    if (!features) {
        return 5;  /* Software fallback */
    }
    
    if (features->has_amx && features->has_aesni) {
        return 1;  /* AMX + AES-NI */
    }
    if (features->has_aesni && features->has_avx512f) {
        return 2;  /* AES-NI + AVX-512 */
    }
    if (features->has_aesni && features->has_avx2) {
        return 3;  /* AES-NI + AVX2 */
    }
    if (features->has_aesni) {
        return 4;  /* AES-NI only */
    }
    
    return 5;  /* Software fallback */
}

/*
 * Test function
 */
#ifdef TEST_CPU_DETECTOR
int main() {
    printf("CPU Feature Detector Test\n");
    printf("========================\n\n");
    
    cpu_features_t *features = detect_cpu_features();
    if (!features) {
        printf("Failed to detect CPU features\n");
        return 1;
    }
    
    print_cpu_features(features);
    
    int priority = get_optimal_instruction_set(features);
    printf("\nOptimal instruction set priority: %d\n", priority);
    
    free_cpu_features(features);
    return 0;
}
#endif

