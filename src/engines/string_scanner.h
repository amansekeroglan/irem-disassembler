#ifndef IREM_STRING_SCANNER_H
#define IREM_STRING_SCANNER_H

#include "irem_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    IREM_STR_ASCII = 0,
    IREM_STR_UTF16LE = 1
} IremStringEncoding;

typedef struct {
    uint64_t           va;
    uint32_t           rva;
    uint32_t           file_offset;
    uint32_t           byte_length;
    int                char_count;
    IremStringEncoding encoding;
    char               preview[256];
    char               section_name[16];
} IremStringEntry;

typedef struct {
    uint64_t code_va;
    uint64_t string_va;
    int      string_index;
} IremStringXref;

typedef struct {
    int              string_count;
    int              string_capacity;
    IremStringEntry* strings;

    int              xref_count;
    int              xref_capacity;
    IremStringXref*  xrefs;

    int              ascii_count;
    int              utf16_count;
} IremStringDatabase;

/* Initialize an empty string database */
void irem_strings_init(IremStringDatabase* db);

/* Free all resources in the database */
void irem_strings_free(IremStringDatabase* db);

/* Scan given sections of a PE file for ASCII and UTF-16LE strings */
bool irem_strings_scan_binary(
    IremStringDatabase* db,
    const uint8_t* pe_data,
    size_t pe_size,
    uint64_t image_base,
    const IremSectionDesc* sections,
    size_t section_count,
    int min_length
);

/* Match decoded instructions containing RIP-relative references against the string database */
void irem_strings_build_xrefs(
    IremStringDatabase* db,
    const IremFlatInstruction* instructions,
    size_t instruction_count
);

/* Find string entry at exact VA (binary search) */
const IremStringEntry* irem_strings_find_by_va(const IremStringDatabase* db, uint64_t va);

/* Find xref from a specific instruction VA */
const IremStringXref* irem_strings_find_xref_by_code_va(const IremStringDatabase* db, uint64_t code_va);

#ifdef __cplusplus
}
#endif

#endif /* IREM_STRING_SCANNER_H */

