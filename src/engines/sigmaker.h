#ifndef IREM_SIGMAKER_H
#define IREM_SIGMAKER_H

#include "irem_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t byte_val;
    bool    is_wildcard;
} IremSigByte;

typedef struct {
    int         byte_count;
    IremSigByte bytes[256];

    char        ida_pattern[512];    /* "48 8B 05 ?? ?? ?? ?? 48 85 C0" */
    char        ce_pattern[512];     /* "48 8B 05 * * * * 48 85 C0" */
    char        c_byte_escaped[512]; /* "\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0" */
    char        c_mask[256];         /* "xxx????xxx" */

    int         match_count;
    bool        is_unique;
    uint64_t    first_match_va;
} IremSignature;

typedef struct {
    uint64_t match_va;
    uint32_t match_rva;
    uint32_t match_file_offset;
} IremScanMatch;

/* Generate signature from a slice of flat instructions */
bool irem_sigmaker_generate(
    const IremFlatInstruction* instructions,
    size_t count,
    size_t start_idx,
    size_t end_idx,
    IremSignature* out_sig
);

/* Parse an IDA-style signature string (e.g. "48 8B 05 ?? ?? ?? ?? 48 85 C0") */
bool irem_sigmaker_parse_ida_pattern(
    const char* pattern_str,
    IremSigByte* out_bytes,
    int max_bytes,
    int* out_count
);

/* Scan PE binary data for a pattern */
int irem_aob_scan(
    const uint8_t* pe_data,
    size_t pe_size,
    uint64_t image_base,
    uint32_t scan_start_offset,
    size_t scan_length,
    uint32_t base_rva,
    const IremSigByte* pattern,
    int pattern_len,
    IremScanMatch* out_matches,
    int max_matches
);

#ifdef __cplusplus
}
#endif

#endif /* IREM_SIGMAKER_H */

