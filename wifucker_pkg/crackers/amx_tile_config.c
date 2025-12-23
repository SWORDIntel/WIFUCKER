/*
 * AMX Tile Configuration
 * =======================
 *
 * Optimal AMX tile configuration for maximum parallel password processing.
 * Configures TILECFG register for optimal tile sizes and balances between
 * tile count and tile size for WPA2-PSK password cracking.
 *
 * Features:
 * - Optimal tile configuration for PBKDF2 operations
 * - Dynamic tile sizing based on password batch size
 * - Memory-aligned tile allocation
 * - Zero-copy tile data movement
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <immintrin.h>
#include "amx_detector.c"

/* Tile configuration for password cracking */
typedef struct {
    amx_tilecfg_t config;
    int tile_rows;
    int tile_cols;
    int passwords_per_tile;
    int total_passwords;
    void *tile_data_buffer;
    size_t tile_data_size;
} password_tile_config_t;

/* Optimal tile configuration for different batch sizes */
static password_tile_config_t g_tile_config = {0};

/*
 * Calculate optimal tile dimensions for password batch
 * Target: Maximize passwords per tile while maintaining performance
 */
static void calculate_optimal_tile_size(int num_passwords, int max_password_len,
                                        int *tile_rows, int *tile_cols) {
    amx_state_t *amx_state = amx_get_state();
    if (!amx_state) {
        *tile_rows = 0;
        *tile_cols = 0;
        return;
    }
    
    /* For password cracking, we want to pack as many passwords as possible */
    /* Each password needs: length (1 byte) + data (max_password_len bytes) */
    int bytes_per_password = 1 + max_password_len;
    
    /* Maximum tile size: 64 bytes per row, up to 16 rows */
    int max_bytes_per_tile = amx_state->max_tile_cols * amx_state->max_tile_rows;
    
    /* Calculate how many passwords fit in one tile */
    int passwords_per_tile = max_bytes_per_tile / bytes_per_password;
    if (passwords_per_tile > num_passwords) {
        passwords_per_tile = num_passwords;
    }
    
    /* Calculate tile dimensions */
    int total_bytes_needed = passwords_per_tile * bytes_per_password;
    *tile_rows = (total_bytes_needed + amx_state->max_tile_cols - 1) / amx_state->max_tile_cols;
    if (*tile_rows > amx_state->max_tile_rows) {
        *tile_rows = amx_state->max_tile_rows;
    }
    *tile_cols = amx_state->max_tile_cols;
    
    /* Ensure we use at least one row */
    if (*tile_rows == 0) {
        *tile_rows = 1;
    }
}

/*
 * Configure tiles for password batch processing
 */
int amx_configure_password_tiles(int num_passwords, int max_password_len) {
    if (!amx_is_available()) {
        return 0;
    }
    
    amx_state_t *amx_state = amx_get_state();
    if (!amx_state) {
        return 0;
    }
    
    /* Calculate optimal tile size */
    int tile_rows, tile_cols;
    calculate_optimal_tile_size(num_passwords, max_password_len, &tile_rows, &tile_cols);
    
    if (tile_rows == 0 || tile_cols == 0) {
        return 0;
    }
    
    /* Initialize tile configuration */
    memset(&g_tile_config.config, 0, sizeof(amx_tilecfg_t));
    g_tile_config.config.palette_id = 1;  /* Palette 1 for AMX */
    g_tile_config.config.start_row = 0;
    
    /* Configure each tile register */
    int tiles_used = 0;
    int passwords_remaining = num_passwords;
    int bytes_per_password = 1 + max_password_len;
    
    for (int i = 0; i < amx_state->tile_count && i < 8 && passwords_remaining > 0; i++) {
        /* Calculate how many passwords fit in this tile */
        int max_bytes_per_tile = tile_cols * tile_rows;
        int passwords_in_tile = max_bytes_per_tile / bytes_per_password;
        
        if (passwords_in_tile > passwords_remaining) {
            passwords_in_tile = passwords_remaining;
        }
        
        if (passwords_in_tile > 0) {
            /* Configure this tile */
            g_tile_config.config.colsb[i] = tile_cols;
            g_tile_config.config.rows[i] = tile_rows;
            tiles_used++;
            passwords_remaining -= passwords_in_tile;
        }
    }
    
    g_tile_config.tile_rows = tile_rows;
    g_tile_config.tile_cols = tile_cols;
    g_tile_config.passwords_per_tile = (tile_cols * tile_rows) / bytes_per_password;
    g_tile_config.total_passwords = num_passwords - passwords_remaining;
    
    /* Allocate tile data buffer */
    size_t buffer_size = amx_state->tile_data_size;
    if (g_tile_config.tile_data_buffer) {
        free(g_tile_config.tile_data_buffer);
    }
    g_tile_config.tile_data_buffer = aligned_alloc(64, buffer_size);
    if (!g_tile_config.tile_data_buffer) {
        return 0;
    }
    memset(g_tile_config.tile_data_buffer, 0, buffer_size);
    g_tile_config.tile_data_size = buffer_size;
    
    /* Apply tile configuration */
    #ifdef __AMX_TILE__
    _tile_loadconfig(&g_tile_config.config);
    #endif
    
    return 1;
}

/*
 * Get current tile configuration
 */
password_tile_config_t* amx_get_tile_config() {
    if (!amx_is_available()) {
        return NULL;
    }
    return &g_tile_config;
}

/*
 * Pack passwords into AMX tile format
 */
int amx_pack_passwords(const char **passwords, const size_t *lengths, 
                       int num_passwords, int tile_index) {
    if (!amx_is_available() || !g_tile_config.tile_data_buffer) {
        return 0;
    }
    
    if (tile_index < 0 || tile_index >= 8) {
        return 0;
    }
    
    /* Get tile dimensions for this tile */
    int tile_cols = g_tile_config.config.colsb[tile_index];
    int tile_rows = g_tile_config.config.rows[tile_index];
    
    if (tile_cols == 0 || tile_rows == 0) {
        return 0;
    }
    
    /* Calculate offset in tile data buffer */
    amx_state_t *amx_state = amx_get_state();
    size_t tile_offset = tile_index * (tile_cols * tile_rows);
    
    if (tile_offset + (tile_cols * tile_rows) > g_tile_config.tile_data_size) {
        return 0;
    }
    
    uint8_t *tile_data = (uint8_t *)g_tile_config.tile_data_buffer + tile_offset;
    
    /* Pack passwords into tile */
    int offset = 0;
    int passwords_packed = 0;
    int max_bytes = tile_cols * tile_rows;
    
    for (int i = 0; i < num_passwords && offset < max_bytes - 1; i++) {
        size_t pwd_len = lengths[i];
        if (pwd_len > 255) {
            pwd_len = 255;  /* Limit to 255 bytes */
        }
        
        /* Check if password fits */
        if (offset + 1 + pwd_len > max_bytes) {
            break;
        }
        
        /* Store length byte */
        tile_data[offset++] = (uint8_t)pwd_len;
        
        /* Store password data */
        memcpy(&tile_data[offset], passwords[i], pwd_len);
        offset += pwd_len;
        
        passwords_packed++;
    }
    
    /* Zero remaining bytes */
    if (offset < max_bytes) {
        memset(&tile_data[offset], 0, max_bytes - offset);
    }
    
    /* Load tile data into AMX tile register */
    #ifdef __AMX_TILE__
    _tile_loadd(tile_index, tile_data, tile_cols);
    #endif
    
    return passwords_packed;
}

/*
 * Extract results from AMX tile
 */
int amx_extract_results(int tile_index, uint8_t *output_buffer, size_t output_size) {
    if (!amx_is_available()) {
        return 0;
    }
    
    if (tile_index < 0 || tile_index >= 8) {
        return 0;
    }
    
    /* Get tile dimensions */
    int tile_cols = g_tile_config.config.colsb[tile_index];
    int tile_rows = g_tile_config.config.rows[tile_index];
    
    if (tile_cols == 0 || tile_rows == 0) {
        return 0;
    }
    
    size_t tile_size = tile_cols * tile_rows;
    if (output_size < tile_size) {
        return 0;
    }
    
    /* Calculate offset in tile data buffer */
    amx_state_t *amx_state = amx_get_state();
    size_t tile_offset = tile_index * tile_size;
    
    if (tile_offset + tile_size > g_tile_config.tile_data_size) {
        return 0;
    }
    
    /* Store tile data back to buffer */
    #ifdef __AMX_TILE__
    _tile_stored(tile_index, g_tile_config.tile_data_buffer + tile_offset, tile_cols);
    #endif
    
    /* Copy to output buffer */
    memcpy(output_buffer, g_tile_config.tile_data_buffer + tile_offset, tile_size);
    
    return tile_size;
}

/*
 * Cleanup tile configuration
 */
void amx_cleanup_tiles() {
    if (g_tile_config.tile_data_buffer) {
        free(g_tile_config.tile_data_buffer);
        g_tile_config.tile_data_buffer = NULL;
    }
    
    memset(&g_tile_config, 0, sizeof(password_tile_config_t));
    
    /* Zero tile configuration */
    #ifdef __AMX_TILE__
    amx_tilecfg_t zero_config = {0};
    _tile_loadconfig(&zero_config);
    #endif
}

/*
 * Print tile configuration info
 */
void amx_print_tile_config() {
    if (!amx_is_available()) {
        printf("AMX tiles: Not configured (AMX not available)\n");
        return;
    }
    
    printf("AMX Tile Configuration\n");
    printf("======================\n");
    printf("Tile Rows:  %d\n", g_tile_config.tile_rows);
    printf("Tile Cols:  %d bytes\n", g_tile_config.tile_cols);
    printf("Passwords per tile: %d\n", g_tile_config.passwords_per_tile);
    printf("Total passwords: %d\n", g_tile_config.total_passwords);
    printf("Tile data buffer: %p (%zu bytes)\n", 
           g_tile_config.tile_data_buffer, g_tile_config.tile_data_size);
    printf("\n");
    
    printf("Tile Register Configuration:\n");
    for (int i = 0; i < 8; i++) {
        if (g_tile_config.config.colsb[i] > 0) {
            printf("  Tile %d: %d rows x %d bytes = %d bytes\n",
                   i,
                   g_tile_config.config.rows[i],
                   g_tile_config.config.colsb[i],
                   g_tile_config.config.rows[i] * g_tile_config.config.colsb[i]);
        }
    }
    printf("\n");
}

