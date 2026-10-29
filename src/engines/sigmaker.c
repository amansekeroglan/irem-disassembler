#include "sigmaker.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#include <immintrin.h>
#endif

bool irem_sigmaker_generate(
    const IremFlatInstruction* instructions,
    size_t count,
    size_t start_idx,
    size_t end_idx,
    IremSignature* out_sig
) {
    if (!instructions || start_idx >= count || end_idx >= count || start_idx > end_idx || !out_sig) {
        return false;
    }

    memset(out_sig, 0, sizeof(IremSignature));

    for (size_t i = start_idx; i <= end_idx; ++i) {
        const IremFlatInstruction* ins = &instructions[i];
        if (ins->length == 0 || ins->length > 15) continue;

        int wild_start = -1;
        int wild_end = -1;

        /* Rule 1: Direct CALL rel32 (E8 xx xx xx xx) */
        if (ins->is_call && ins->length == 5 && ins->raw_bytes[0] == 0xE8) {
            wild_start = 1;
            wild_end = 4;
        }
        /* Rule 2: Conditional Jump rel32 (0F 8x xx xx xx xx) */
        else if (ins->is_conditional_jump && ins->length == 6 && ins->raw_bytes[0] == 0x0F) {
            wild_start = 2;
            wild_end = 5;
        }
        /* Rule 3: RIP-relative memory operand (last 4 bytes are displacement) */
        else {
            bool has_rip_rel = false;
            for (uint8_t op = 0; op < ins->op_count; ++op) {
                if (ins->ops[op].type == IREM_OP_MEM && ins->ops[op].mem.is_rip_relative) {
                    has_rip_rel = true;
                    break;
                }
            }
            if (has_rip_rel && ins->length >= 4) {
                wild_start = (int)ins->length - 4;
                wild_end = (int)ins->length - 1;
            }
        }

        /* Rule 4: mov reg64, imm64 (last 8 bytes are immediate) */
        if (ins->length >= 10 && (ins->raw_bytes[0] == 0x48 || ins->raw_bytes[0] == 0x49) &&
            (ins->raw_bytes[1] >= 0xB8 && ins->raw_bytes[1] <= 0xBF)) {
            wild_start = (int)ins->length - 8;
            wild_end = (int)ins->length - 1;
        }

        for (uint8_t b = 0; b < ins->length; ++b) {
            if (out_sig->byte_count >= 256) break;

            IremSigByte* sb = &out_sig->bytes[out_sig->byte_count++];
            sb->byte_val = ins->raw_bytes[b];
            sb->is_wildcard = (wild_start >= 0 && (int)b >= wild_start && (int)b <= wild_end);
        }
    }

    /* Format IDA pattern, Cheat Engine pattern, C array and mask */
    size_t ida_pos = 0;
    size_t ce_pos = 0;
    size_t c_pos = 0;
    size_t mask_pos = 0;

    for (int b = 0; b < out_sig->byte_count; ++b) {
        if (out_sig->bytes[b].is_wildcard) {
            ida_pos += (size_t)snprintf(out_sig->ida_pattern + ida_pos, sizeof(out_sig->ida_pattern) - ida_pos, "?? ");
            ce_pos += (size_t)snprintf(out_sig->ce_pattern + ce_pos, sizeof(out_sig->ce_pattern) - ce_pos, "* ");
            c_pos += (size_t)snprintf(out_sig->c_byte_escaped + c_pos, sizeof(out_sig->c_byte_escaped) - c_pos, "\\x00");
            out_sig->c_mask[mask_pos++] = '?';
        } else {
            ida_pos += (size_t)snprintf(out_sig->ida_pattern + ida_pos, sizeof(out_sig->ida_pattern) - ida_pos, "%02X ", out_sig->bytes[b].byte_val);
            ce_pos += (size_t)snprintf(out_sig->ce_pattern + ce_pos, sizeof(out_sig->ce_pattern) - ce_pos, "%02X ", out_sig->bytes[b].byte_val);
            c_pos += (size_t)snprintf(out_sig->c_byte_escaped + c_pos, sizeof(out_sig->c_byte_escaped) - c_pos, "\\x%02X", out_sig->bytes[b].byte_val);
            out_sig->c_mask[mask_pos++] = 'x';
        }
    }

    /* Trim trailing spaces */
    if (ida_pos > 0 && out_sig->ida_pattern[ida_pos - 1] == ' ') out_sig->ida_pattern[ida_pos - 1] = '\0';
    if (ce_pos > 0 && out_sig->ce_pattern[ce_pos - 1] == ' ') out_sig->ce_pattern[ce_pos - 1] = '\0';
    out_sig->c_mask[mask_pos] = '\0';

    return (out_sig->byte_count > 0);
}

bool irem_sigmaker_parse_ida_pattern(
    const char* pattern_str,
    IremSigByte* out_bytes,
    int max_bytes,
    int* out_count
) {
    if (!pattern_str || !out_bytes || max_bytes <= 0 || !out_count) return false;

    int count = 0;
    const char* p = pattern_str;

    while (*p && count < max_bytes) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;

        if (*p == '?' || *p == '*') {
            out_bytes[count].byte_val = 0;
            out_bytes[count].is_wildcard = true;
            count++;
            p++;
            if (*p == '?') p++;
        } else if (isxdigit((unsigned char)*p)) {
            char hex[3] = { 0 };
            hex[0] = *p++;
            if (isxdigit((unsigned char)*p)) {
                hex[1] = *p++;
            }
            out_bytes[count].byte_val = (uint8_t)strtoul(hex, NULL, 16);
            out_bytes[count].is_wildcard = false;
            count++;
        } else {
            p++;
        }
    }

    *out_count = count;
    return (count > 0);
}

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
) {
    if (!pe_data || pe_size == 0 || !pattern || pattern_len <= 0 || !out_matches || max_matches <= 0) {
        return 0;
    }

    if (scan_start_offset >= pe_size) return 0;
    if (scan_start_offset + scan_length > pe_size) {
        scan_length = pe_size - scan_start_offset;
    }
    if (scan_length < (size_t)pattern_len) return 0;

    int match_count = 0;
    const uint8_t* haystack = pe_data + scan_start_offset;
    size_t max_scan = scan_length - (size_t)pattern_len;

    /* Find the first non-wildcard anchor byte for fast skipping */
    int first_fixed_idx = -1;
    uint8_t first_fixed_val = 0;
    for (int k = 0; k < pattern_len; ++k) {
        if (!pattern[k].is_wildcard) {
            first_fixed_idx = k;
            first_fixed_val = pattern[k].byte_val;
            break;
        }
    }

    for (size_t i = 0; i <= max_scan && match_count < max_matches; ) {
        /* If an anchor byte exists, skip ahead until it matches */
        if (first_fixed_idx >= 0) {
            if (haystack[i + first_fixed_idx] != first_fixed_val) {
                i++;
                continue;
            }
        }

        /* Verify full pattern match */
        bool full_match = true;
        for (int j = 0; j < pattern_len; ++j) {
            if (!pattern[j].is_wildcard && haystack[i + j] != pattern[j].byte_val) {
                full_match = false;
                break;
            }
        }

        if (full_match) {
            IremScanMatch* m = &out_matches[match_count++];
            m->match_file_offset = scan_start_offset + (uint32_t)i;
            m->match_rva = base_rva + (uint32_t)i;
            m->match_va = image_base + m->match_rva;
            i++;
        } else {
            i++;
        }
    }

    return match_count;
}

