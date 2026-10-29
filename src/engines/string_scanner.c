#include "string_scanner.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#include <immintrin.h>
#endif

static inline bool is_ascii_printable(uint8_t c) {
    return (c >= 0x20 && c <= 0x7E) || (c == '\t') || (c == '\r') || (c == '\n');
}

void irem_strings_init(IremStringDatabase* db) {
    if (!db) return;
    memset(db, 0, sizeof(IremStringDatabase));
}

void irem_strings_free(IremStringDatabase* db) {
    if (!db) return;
    if (db->strings) {
        free(db->strings);
        db->strings = NULL;
    }
    if (db->xrefs) {
        free(db->xrefs);
        db->xrefs = NULL;
    }
    memset(db, 0, sizeof(IremStringDatabase));
}

static bool append_string(IremStringDatabase* db, const IremStringEntry* entry) {
    if (db->string_count >= db->string_capacity) {
        int new_cap = db->string_capacity == 0 ? 256 : db->string_capacity * 2;
        IremStringEntry* new_arr = (IremStringEntry*)realloc(db->strings, (size_t)new_cap * sizeof(IremStringEntry));
        if (!new_arr) return false;
        db->strings = new_arr;
        db->string_capacity = new_cap;
    }
    db->strings[db->string_count++] = *entry;
    if (entry->encoding == IREM_STR_ASCII) {
        db->ascii_count++;
    } else {
        db->utf16_count++;
    }
    return true;
}

static bool append_xref(IremStringDatabase* db, const IremStringXref* xref) {
    if (db->xref_count >= db->xref_capacity) {
        int new_cap = db->xref_capacity == 0 ? 256 : db->xref_capacity * 2;
        IremStringXref* new_arr = (IremStringXref*)realloc(db->xrefs, (size_t)new_cap * sizeof(IremStringXref));
        if (!new_arr) return false;
        db->xrefs = new_arr;
        db->xref_capacity = new_cap;
    }
    db->xrefs[db->xref_count++] = *xref;
    return true;
}

static int compare_strings_by_va(const void* a, const void* b) {
    const IremStringEntry* sa = (const IremStringEntry*)a;
    const IremStringEntry* sb = (const IremStringEntry*)b;
    if (sa->va < sb->va) return -1;
    if (sa->va > sb->va) return 1;
    return 0;
}

static int compare_xrefs_by_code_va(const void* a, const void* b) {
    const IremStringXref* xa = (const IremStringXref*)a;
    const IremStringXref* xb = (const IremStringXref*)b;
    if (xa->code_va < xb->code_va) return -1;
    if (xa->code_va > xb->code_va) return 1;
    return 0;
}

bool irem_strings_scan_binary(
    IremStringDatabase* db,
    const uint8_t* pe_data,
    size_t pe_size,
    uint64_t image_base,
    const IremSectionDesc* sections,
    size_t section_count,
    int min_length
) {
    if (!db || !pe_data || pe_size == 0) return false;
    if (min_length < 3) min_length = 3;

    for (size_t s = 0; s < section_count; ++s) {
        const IremSectionDesc* sec = &sections[s];
        /* Scan sections that have raw data */
        if (sec->raw_offset >= pe_size || sec->raw_size == 0) continue;

        size_t sec_end = (size_t)sec->raw_offset + sec->raw_size;
        if (sec_end > pe_size) sec_end = pe_size;
        size_t sec_len = sec_end - sec->raw_offset;
        const uint8_t* data = pe_data + sec->raw_offset;

        /* --- 1. ASCII String Scan --- */
        size_t i = 0;
        while (i < sec_len) {
            if (is_ascii_printable(data[i])) {
                size_t start = i;
                while (i < sec_len && is_ascii_printable(data[i])) {
                    i++;
                }
                size_t len = i - start;
                /* Check if ended with null terminator or at section boundary */
                bool has_null = (i < sec_len && data[i] == 0);
                if (len >= (size_t)min_length && has_null) {
                    IremStringEntry entry;
                    memset(&entry, 0, sizeof(entry));
                    entry.file_offset = (uint32_t)(sec->raw_offset + start);
                    entry.rva = sec->virtual_address + (uint32_t)start;
                    entry.va = image_base + entry.rva;
                    entry.byte_length = (uint32_t)(len + 1);
                    entry.char_count = (int)len;
                    entry.encoding = IREM_STR_ASCII;

                    size_t copy_len = len < 255 ? len : 255;
                    memcpy(entry.preview, data + start, copy_len);
                    entry.preview[copy_len] = '\0';
                    strncpy_s(entry.section_name, sizeof(entry.section_name), sec->name, sizeof(entry.section_name) - 1);

                    append_string(db, &entry);
                }
            } else {
                i++;
            }
        }

        /* --- 2. UTF-16LE String Scan --- */
        size_t u = 0;
        while (u + 1 < sec_len) {
            uint8_t lo = data[u];
            uint8_t hi = data[u + 1];

            if (is_ascii_printable(lo) && hi == 0) {
                size_t start = u;
                size_t chars = 0;
                while (u + 1 < sec_len && is_ascii_printable(data[u]) && data[u + 1] == 0) {
                    chars++;
                    u += 2;
                }
                bool has_null16 = (u + 1 < sec_len && data[u] == 0 && data[u + 1] == 0);
                if (chars >= (size_t)min_length && has_null16) {
                    IremStringEntry entry;
                    memset(&entry, 0, sizeof(entry));
                    entry.file_offset = (uint32_t)(sec->raw_offset + start);
                    entry.rva = sec->virtual_address + (uint32_t)start;
                    entry.va = image_base + entry.rva;
                    entry.byte_length = (uint32_t)((chars + 1) * 2);
                    entry.char_count = (int)chars;
                    entry.encoding = IREM_STR_UTF16LE;

                    /* Convert UTF-16LE characters to ASCII/UTF-8 preview */
                    size_t copy_chars = chars < 255 ? chars : 255;
                    for (size_t c = 0; c < copy_chars; ++c) {
                        entry.preview[c] = (char)data[start + c * 2];
                    }
                    entry.preview[copy_chars] = '\0';
                    strncpy_s(entry.section_name, sizeof(entry.section_name), sec->name, sizeof(entry.section_name) - 1);

                    append_string(db, &entry);
                }
            } else {
                u += 2;
            }
        }
    }

    /* Sort all strings by VA for fast binary search */
    if (db->string_count > 1) {
        qsort(db->strings, (size_t)db->string_count, sizeof(IremStringEntry), compare_strings_by_va);
    }

    return true;
}

const IremStringEntry* irem_strings_find_by_va(const IremStringDatabase* db, uint64_t va) {
    if (!db || db->string_count == 0 || !db->strings) return NULL;

    int left = 0;
    int right = db->string_count - 1;

    while (left <= right) {
        int mid = left + (right - left) / 2;
        const IremStringEntry* e = &db->strings[mid];
        if (e->va == va) {
            return e;
        }
        if (e->va < va) {
            /* Check if va falls inside the string length */
            if (va < e->va + e->byte_length) {
                return e;
            }
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    return NULL;
}

void irem_strings_build_xrefs(
    IremStringDatabase* db,
    const IremFlatInstruction* instructions,
    size_t instruction_count
) {
    if (!db || !instructions || instruction_count == 0) return;

    for (size_t i = 0; i < instruction_count; ++i) {
        const IremFlatInstruction* ins = &instructions[i];

        for (uint8_t op_idx = 0; op_idx < ins->op_count; ++op_idx) {
            const IremFlatOperand* op = &ins->ops[op_idx];
            if (op->type == IREM_OP_MEM && op->mem.is_rip_relative && op->mem.resolved_target_va != 0) {
                const IremStringEntry* found = irem_strings_find_by_va(db, op->mem.resolved_target_va);
                if (found) {
                    IremStringXref xref;
                    xref.code_va = ins->va;
                    xref.string_va = found->va;
                    xref.string_index = (int)(found - db->strings);
                    append_xref(db, &xref);
                }
            }
        }
    }

    if (db->xref_count > 1) {
        qsort(db->xrefs, (size_t)db->xref_count, sizeof(IremStringXref), compare_xrefs_by_code_va);
    }
}

const IremStringXref* irem_strings_find_xref_by_code_va(const IremStringDatabase* db, uint64_t code_va) {
    if (!db || db->xref_count == 0 || !db->xrefs) return NULL;

    int left = 0;
    int right = db->xref_count - 1;

    while (left <= right) {
        int mid = left + (right - left) / 2;
        if (db->xrefs[mid].code_va == code_va) {
            return &db->xrefs[mid];
        }
        if (db->xrefs[mid].code_va < code_va) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    return NULL;
}

