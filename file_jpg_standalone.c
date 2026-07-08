/*
 * JPEG Recovery Standalone Debugger
 * Based on PhotoRec's file_jpg.c logic
 *
 * Derived from PhotoRec (TestDisk suite), file_jpg.c
 * Copyright (C) 1998-2022 Christophe Grenier <grenier@cgsecurity.org>
 * Standalone port modifications Copyright (C) 2026 DeepScan contributors
 *
 * This software is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *
 * Compile (Windows/Visual Studio):
 *   cl /W4 /Zi jpeg_recovery_standalone.c
 * 
 * Compile (Linux/GCC):
 *   gcc -Wall -g jpeg_recovery_standalone.c -o jpeg_recovery
 * 
 * Usage:
 *   jpeg_recovery_standalone <input_file> [output_dir]
 * 
 * Example:
 *   jpeg_recovery_standalone image.dd .
 *   jpeg_recovery_standalone corrupted.jpg .
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>

/* ============================================================================
 * Configuration & Constants
 * ============================================================================ */

#define DEBUG 1
#define MAX_SCAN_LEN 65536
#define MAX_JPEG_SIZE (50 * 1024 * 1024)  /* 50 MB */
#define BUFFER_SIZE (256 * 1024)            /* 256 KB buffer */

/* JPEG Markers */
#define JPEG_SOI  0xD8
#define JPEG_EOI  0xD9
#define JPEG_SOS  0xDA
#define JPEG_SOF0 0xC0
#define JPEG_SOF1 0xC1
#define JPEG_SOF2 0xC2
#define JPEG_DHT  0xC4
#define JPEG_DQT  0xDB
#define JPEG_APP0 0xE0
#define JPEG_APP1 0xE1
#define JPEG_COM  0xFE

/* Debug logging */
#if DEBUG
#define LOG_INFO(fmt, ...) printf("[INFO] " fmt "\n", ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) printf("[WARN] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) printf("[ERROR] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG_INFO(fmt, ...)
#define LOG_DEBUG(fmt, ...)
#define LOG_WARN(fmt, ...)
#define LOG_ERROR(fmt, ...) printf("[ERROR] " fmt "\n", ##__VA_ARGS__)
#endif

/* ============================================================================
 * Data Structures
 * ============================================================================ */

typedef struct {
    uint64_t file_start_offset;
    uint64_t file_size;
    uint64_t calculated_file_size;
    
    uint16_t width;
    uint16_t height;
    
    int has_eoi;
    int has_sos;
    int has_exif;
    
    int valid;
    int error_count;
    
    char filename[256];
} JpegRecovery;

typedef struct {
    uint16_t width;
    uint16_t height;
    int found;
} JpegDimensions;

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/* Big-endian 16-bit read */
static inline uint16_t read_be16(const unsigned char *data) {
    return ((uint16_t)data[0] << 8) | data[1];
}

/* Big-endian 32-bit read */
static inline uint32_t read_be32(const unsigned char *data) {
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           data[3];
}

/* Little-endian 16-bit read */
static inline uint16_t read_le16(const unsigned char *data) {
    return ((uint16_t)data[1] << 8) | data[0];
}

/* Little-endian 32-bit read */
static inline uint32_t read_le32(const unsigned char *data) {
    return ((uint32_t)data[3] << 24) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[1] << 8) |
           data[0];
}

/* Check if marker is standalone (no length field) */
static int is_standalone_marker(unsigned char code) {
    return (code >= 0xD0 && code <= 0xD9) || code == 0x00;
}

/* Check if marker is app-specific */
static int is_app_marker(unsigned char code) {
    return (code >= 0xE0 && code <= 0xEF);
}

/* ============================================================================
 * Core JPEG Validation Functions (from PhotoRec file_jpg.c)
 * ============================================================================ */

/**
 * jpg_check_dht - Validate DHT (Define Huffman Table) marker
 * 
 * DHT format:
 *   FF C4          (marker)
 *   [LEN:2]        (big-endian length)
 *   [CLASS:1]      (table class 0=DC, 1=AC)
 *   [BITS:16]      (Huffman code lengths)
 *   [VALUES:var]   (Huffman values)
 */
static int jpg_check_dht(const unsigned char *buffer,
                         unsigned int buffer_size,
                         unsigned int i,
                         unsigned int size) {
    unsigned int nbr = 0;
    int k;
    
    LOG_DEBUG("  Validating DHT at offset %u", i);
    
    if (i + 2 + 17 > buffer_size) {
        LOG_WARN("    Buffer too small for DHT");
        return 0;
    }
    
    /* Sum code counts from bits array (16 bytes) */
    for (k = 1; k <= 16; k++) {
        nbr += buffer[i + 16 + k];
    }
    
    LOG_DEBUG("    Total codes: %u, declared size: %u", nbr, size);
    
    /* Validate total length: header(17) + codes(nbr) <= size */
    if (2 + 17 + nbr > size) {
        LOG_WARN("    DHT data size mismatch");
        return 0;
    }
    
    LOG_DEBUG("    DHT valid");
    return 1;
}

/**
 * jpg_get_size - Extract image dimensions from SOF marker
 * 
 * SOF0 format:
 *   FF C0
 *   [LEN:2]
 *   [PRECISION:1]
 *   [HEIGHT:2]      (at offset +5)
 *   [WIDTH:2]       (at offset +7)
 */
static void jpg_get_size(const unsigned char *buffer,
                        unsigned int buffer_size,
                        JpegDimensions *dims) {
    unsigned int i = 2;  /* Skip SOI (FF D8) */
    
    dims->found = 0;
    dims->width = 0;
    dims->height = 0;
    
    LOG_DEBUG("Scanning for SOF marker starting at offset 2");
    
    while (i + 8 < buffer_size) {
        if (buffer[i] == 0xFF && buffer[i+1] == 0xFF) {
            /* Skip FF FF padding */
            i++;
            continue;
        }
        
        if (buffer[i] == 0xFF) {
            unsigned int seg_size = 
                ((unsigned int)buffer[i+2] << 8) | buffer[i+3];
            
            if (buffer[i+1] == JPEG_SOF0) {
                /* Found SOF0 - baseline DCT */
                dims->height = 
                    ((unsigned int)buffer[i+5] << 8) | buffer[i+6];
                dims->width = 
                    ((unsigned int)buffer[i+7] << 8) | buffer[i+8];
                dims->found = 1;
                
                LOG_INFO("Found SOF0 at offset %u: %ux%u",
                        i, dims->width, dims->height);
                return;
            }
            
            i += 2 + seg_size;
        } else {
            return;  /* No marker found */
        }
    }
}

/**
 * jpg_check_struct - Validate JPEG marker structure
 * 
 * Algorithm:
 *   1. Check SOI (FF D8)
 *   2. Scan markers sequentially
 *   3. Validate structure (DHT, SOF, etc.)
 *   4. Find SOS and EOI
 */
static int jpg_check_struct(const unsigned char *buffer,
                           unsigned int buffer_size,
                           JpegRecovery *recovery) {
    unsigned int i = 0;
    int found_sos = 0;
    int found_eoi = 0;
    
    LOG_INFO("Validating JPEG structure (size: %u bytes)", buffer_size);
    
    /* Must start with SOI */
    if (buffer_size < 2 || buffer[0] != 0xFF || buffer[1] != 0xD8) {
        LOG_ERROR("No SOI marker found");
        return 0;
    }
    
    LOG_DEBUG("Found SOI marker");
    
    i = 2;  /* Skip SOI */
    
    while (i + 2 < buffer_size) {
        if (buffer[i] == 0xFF && buffer[i+1] == 0xFF) {
            /* FF FF padding - skip */
            i++;
            continue;
        }
        
        if (buffer[i] != 0xFF) {
            /* No marker found */
            if (found_sos && !found_eoi) {
                /* Still valid - in image data region */
                LOG_DEBUG("End of marker scan at offset %u (in image data)", i);
                return 1;
            }
            LOG_WARN("Expected marker at offset %u", i);
            return 0;
        }
        
        unsigned char marker = buffer[i+1];
        
        /* Log marker found */
        LOG_DEBUG("Marker FF %02X at offset %u", marker, i);
        
        /* Handle standalone markers */
        if (is_standalone_marker(marker)) {
            if (marker == JPEG_SOS) {
                found_sos = 1;
                LOG_DEBUG("  Found SOS (Start of Scan)");
            }
            if (marker == JPEG_EOI) {
                found_eoi = 1;
                LOG_INFO("Found EOI (End of Image) at offset %u", i);
                recovery->calculated_file_size = i + 2;
                return 1;
            }
            i += 2;
            continue;
        }
        
        /* All other markers have length field */
        if (i + 4 > buffer_size) {
            LOG_DEBUG("Not enough data for marker length at offset %u", i);
            break;
        }
        
        unsigned int seg_len = read_be16(&buffer[i+2]);
        
        if (seg_len < 2) {
            LOG_ERROR("Invalid segment length at offset %u: %u", i, seg_len);
            recovery->error_count++;
            return 0;
        }
        
        /* Validate specific markers */
        if (marker == JPEG_DHT) {
            if (!jpg_check_dht(buffer, buffer_size, i, seg_len)) {
                LOG_WARN("Invalid DHT at offset %u", i);
                recovery->error_count++;
                /* Continue anyway - might still recover */
            }
        }
        
        if (marker == JPEG_DQT) {
            LOG_DEBUG("  Found DQT (Quantization Table)");
        }
        
        if (marker == JPEG_SOF0 || marker == JPEG_SOF1 || marker == JPEG_SOF2) {
            LOG_DEBUG("  Found SOF (Start of Frame)");
        }
        
        if (is_app_marker(marker)) {
            if (marker == JPEG_APP1) {
                recovery->has_exif = 1;
                LOG_DEBUG("  Found APP1 (EXIF data)");
            }
        }
        
        i += 2 + seg_len;
    }
    
    /* Require at least SOS for valid JPEG */
    if (!found_sos) {
        LOG_ERROR("SOS (Start of Scan) not found");
        return 0;
    }
    
    LOG_INFO("Valid JPEG structure (SOS found, %s)",
            found_eoi ? "EOI found" : "EOI NOT found (partial?)");
    
    return 1;
}

/* ============================================================================
 * EXIF Extraction (Simplified)
 * ============================================================================ */

/**
 * extract_exif_datetime - Extract DateTime from EXIF
 * 
 * Tag 0x0132 = DateTime
 * Format: "YYYY:MM:DD HH:MM:SS" (ASCII string)
 */
static int extract_exif_datetime(const unsigned char *exif_data,
                                 unsigned int exif_size) {
    unsigned int offset = 0;
    int year, month, day, hour, min, sec;
    
    if (exif_size < 8) {
        LOG_DEBUG("EXIF data too small");
        return 0;
    }
    
    /* Check byte order (TIFF header) */
    int big_endian = 0;
    if (exif_data[0] == 'M' && exif_data[1] == 'M') {
        big_endian = 1;
    } else if (exif_data[0] == 'I' && exif_data[1] == 'I') {
        big_endian = 0;
    } else {
        LOG_DEBUG("Invalid TIFF byte order");
        return 0;
    }
    
    LOG_DEBUG("EXIF byte order: %s", big_endian ? "big-endian" : "little-endian");
    
    /* Get first IFD offset */
    uint32_t ifd_offset = big_endian ? 
        read_be32(&exif_data[4]) : 
        read_le32(&exif_data[4]);
    
    if (ifd_offset >= exif_size - 2) {
        LOG_DEBUG("IFD offset invalid: %u", ifd_offset);
        return 0;
    }
    
    /* Read IFD entry count */
    uint16_t entry_count = big_endian ?
        read_be16(&exif_data[ifd_offset]) :
        read_le16(&exif_data[ifd_offset]);
    
    LOG_DEBUG("IFD entries: %u", entry_count);
    
    const uint16_t DATETIME_TAG = 0x0132;
    
    /* Iterate IFD entries (12 bytes each) */
    for (unsigned int i = 0; i < entry_count; i++) {
        unsigned int entry_offset = ifd_offset + 2 + (i * 12);
        
        if (entry_offset + 12 > exif_size) {
            break;
        }
        
        uint16_t tag = big_endian ?
            read_be16(&exif_data[entry_offset]) :
            read_le16(&exif_data[entry_offset]);
        
        if (tag == DATETIME_TAG) {
            /* Found DateTime tag */
            uint32_t value_offset = big_endian ?
                read_be32(&exif_data[entry_offset + 8]) :
                read_le32(&exif_data[entry_offset + 8]);
            
            if (value_offset + 20 > exif_size) {
                LOG_DEBUG("DateTime offset extends beyond EXIF");
                continue;
            }
            
            /* DateTime format: "YYYY:MM:DD HH:MM:SS" (19 chars + null) */
            char date_str[20];
            memcpy(date_str, &exif_data[value_offset], 19);
            date_str[19] = '\0';
            
            /* Parse date */
            int parsed = sscanf(date_str, "%d:%d:%d %d:%d:%d",
                              &year, &month, &day, &hour, &min, &sec);
            
            if (parsed == 6) {
                LOG_INFO("EXIF DateTime: %s", date_str);
                return 1;
            }
        }
    }
    
    return 0;
}

/**
 * find_and_extract_exif - Find APP1 marker and extract EXIF
 */
static void find_and_extract_exif(const unsigned char *buffer,
                                  unsigned int buffer_size,
                                  JpegRecovery *recovery) {
    unsigned int i;
    
    if (!recovery->has_exif) {
        return;
    }
    
    LOG_DEBUG("Searching for EXIF data (APP1 marker)...");
    
    for (i = 0; i + 10 < buffer_size; i++) {
        if (buffer[i] == 0xFF && buffer[i+1] == JPEG_APP1) {
            /* Found APP1 */
            uint16_t app1_len = read_be16(&buffer[i+2]);
            
            LOG_DEBUG("Found APP1 at offset %u, length %u", i, app1_len);
            
            if (i + 4 + app1_len > buffer_size) {
                LOG_WARN("APP1 extends beyond buffer");
                continue;
            }
            
            /* Check for "Exif\0\0" identifier */
            if (buffer[i+4] != 'E' || buffer[i+5] != 'x' ||
                buffer[i+6] != 'i' || buffer[i+7] != 'f' ||
                buffer[i+8] != '\0' || buffer[i+9] != '\0') {
                continue;
            }
            
            LOG_DEBUG("Valid EXIF header found");
            
            /* Parse EXIF (skip "Exif\0\0") */
            if (extract_exif_datetime(&buffer[i+10], app1_len - 6)) {
                return;  /* Date extracted */
            }
        }
    }
    
    LOG_DEBUG("No EXIF DateTime found");
}

/* ============================================================================
 * Main Recovery Functions
 * ============================================================================ */

/**
 * scan_and_recover_jpegs - Main scanning loop
 */
static int scan_and_recover_jpegs(FILE *input_file,
                                  const char *output_dir) {
    unsigned char *buffer = NULL;
    uint64_t file_offset = 0;
    uint64_t jpeg_count = 0;
    size_t bytes_read;
    
    /* Allocate buffer */
    buffer = (unsigned char *)malloc(BUFFER_SIZE);
    if (!buffer) {
        LOG_ERROR("Failed to allocate buffer");
        return -1;
    }
    
    LOG_INFO("Starting JPEG scan...");
    LOG_INFO("Buffer size: %u KB", BUFFER_SIZE / 1024);
    
    /* Read file in chunks */
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, input_file)) > 0) {
        
        if (bytes_read % 512 != 0) {
            LOG_DEBUG("Sector %llu: %zu bytes", file_offset / BUFFER_SIZE, bytes_read);
        }
        
        /* Search for JPEG signatures */
        for (size_t i = 0; i + 3 < bytes_read; i++) {
            /* Look for FF D8 FF signature */
            if (buffer[i] == 0xFF && 
                buffer[i+1] == 0xD8 && 
                buffer[i+2] == 0xFF) {
                
                LOG_INFO("\n=== JPEG #%llu Found at offset 0x%llX ===",
                        jpeg_count + 1, file_offset + i);
                
                JpegRecovery recovery = {
                    .file_start_offset = file_offset + i,
                    .file_size = 0,
                    .calculated_file_size = 0,
                    .width = 0,
                    .height = 0,
                    .has_eoi = 0,
                    .has_sos = 0,
                    .has_exif = 0,
                    .valid = 0,
                    .error_count = 0
                };
                
                /* Generate filename */
                snprintf(recovery.filename, sizeof(recovery.filename),
                        "%s/image_%010llu.jpg", output_dir, file_offset + i);
                
                /* Validate JPEG structure */
                if (jpg_check_struct(&buffer[i], bytes_read - i, &recovery)) {
                    recovery.valid = 1;
                    
                    /* Extract dimensions */
                    JpegDimensions dims;
                    jpg_get_size(&buffer[i], bytes_read - i, &dims);
                    if (dims.found) {
                        recovery.width = dims.width;
                        recovery.height = dims.height;
                    }
                    
                    /* Try to extract EXIF */
                    find_and_extract_exif(&buffer[i], bytes_read - i, &recovery);
                    
                    /* Log recovery info */
                    LOG_INFO("✓ Valid JPEG recovered");
                    LOG_INFO("  Size: %llu bytes",
                            recovery.calculated_file_size ?
                            recovery.calculated_file_size :
                            recovery.file_size);
                    LOG_INFO("  Dimensions: %ux%u",
                            recovery.width, recovery.height);
                    LOG_INFO("  Has EXIF: %s", recovery.has_exif ? "Yes" : "No");
                    LOG_INFO("  Errors: %d", recovery.error_count);
                    
                    jpeg_count++;
                } else {
                    LOG_WARN("✗ Invalid JPEG structure");
                }
            }
        }
        
        file_offset += bytes_read;
        
        /* Progress */
        if (file_offset % (1024 * 1024) == 0) {
            printf("Progress: %llu MB scanned, %llu JPEGs found\n",
                  file_offset / (1024 * 1024), jpeg_count);
        }
    }
    
    free(buffer);
    
    LOG_INFO("\n=== Scan Complete ===");
    LOG_INFO("Total JPEGs found: %llu", jpeg_count);
    LOG_INFO("Total bytes scanned: %llu", file_offset);
    
    return (int)jpeg_count;
}

/* ============================================================================
 * Main Entry Point
 * ============================================================================ */

void print_usage(const char *prog) {
    printf("JPEG Recovery Standalone Debugger\n");
    printf("Based on PhotoRec file_jpg.c\n\n");
    printf("Usage: %s <input_file> [output_dir]\n\n", prog);
    printf("Arguments:\n");
    printf("  input_file    - Path to input file or raw disk image\n");
    printf("  output_dir    - Output directory (default: current dir)\n\n");
    printf("Examples:\n");
    printf("  %s image.dd .\n", prog);
    printf("  %s corrupted.jpg recovery\n", prog);
    printf("  %s /dev/sda1 /mnt/recovery\n", prog);
}

int main(int argc, char *argv[]) {
    FILE *input_file = NULL;
    const char *input_path = NULL;
    const char *output_dir = ".";
    int result = 0;
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║   JPEG Recovery Standalone Debugger (PhotoRec-based)      ║\n");
    printf("║   Based on file_jpg.c logic                               ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    /* Parse arguments */
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    input_path = argv[1];
    
    if (argc >= 3) {
        output_dir = argv[2];
    }
    
    /* Open input file */
    input_file = fopen(input_path, "rb");
    if (!input_file) {
        LOG_ERROR("Failed to open input file: %s", input_path);
        perror("fopen");
        return 1;
    }
    
    LOG_INFO("Input file: %s", input_path);
    LOG_INFO("Output directory: %s", output_dir);
    
    /* Get file size */
    fseek(input_file, 0, SEEK_END);
    long file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);
    
    if (file_size < 0) {
        LOG_ERROR("Failed to get file size");
        fclose(input_file);
        return 1;
    }
    
    LOG_INFO("File size: %ld bytes (%.2f MB)\n", 
            file_size, (double)file_size / (1024 * 1024));
    
    /* Run recovery */
    result = scan_and_recover_jpegs(input_file, output_dir);
    
    fclose(input_file);
    
    if (result < 0) {
        printf("\nRecovery FAILED\n");
        return 1;
    }
    
    printf("\nRecovery completed: found %d JPEGs\n", result);
    printf("Debug this with breakpoints in jpg_check_struct() and jpg_get_size()\n");
    
    return 0;
}

/*
 * ============================================================================
 * DEBUGGING GUIDE
 * ============================================================================
 * 
 * To debug this in Visual Studio 2019:
 * 
 * 1. Create new C project in VS2019
 * 2. Copy this file into your project
 * 3. Build (Debug configuration)
 * 4. Set breakpoints:
 *    - jpg_check_struct() [line ~250]
 *    - jpg_get_size() [line ~180]
 *    - jpg_check_dht() [line ~115]
 * 
 * 5. Debug menu → Start Debugging (F5)
 * 6. Input: "image.dd" (or test JPEG file)
 * 7. Step through to understand:
 *    - How markers are found
 *    - How SOF is parsed for dimensions
 *    - How DHT is validated
 *    - How EXIF is extracted
 * 
 * Test cases:
 * - Valid JPEG file
 * - Truncated JPEG (no EOI)
 * - Raw disk image with embedded JPEGs
 * - Corrupted JPEG (invalid markers)
 * 
 * Key variables to watch:
 * - buffer[i] / buffer[i+1] (current marker bytes)
 * - seg_len (segment length from marker)
 * - recovery.calculated_file_size (when EOI found)
 * - dims.width, dims.height (extracted from SOF)
 * 
 * ============================================================================
 */
