#ifndef IREM_API_HASH_RESOLVER_H
#define IREM_API_HASH_RESOLVER_H

#include "irem_types.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    IREM_HASH_ALGO_NONE     = 0,
    IREM_HASH_ALGO_ROR13    = 1,
    IREM_HASH_ALGO_ROR13_DLL= 2,
    IREM_HASH_ALGO_DJB2     = 3,
    IREM_HASH_ALGO_FNV1A    = 4,
    IREM_HASH_ALGO_CRC32    = 5,
    IREM_HASH_ALGO_ADDITIVE = 6,
    IREM_HASH_ALGO_COUNT
} IremHashAlgo;

typedef struct {
    size_t       insn_index;
    uint64_t     va;
    uint32_t     hash_value;
    IremHashAlgo algo;
    char         api_name[64];
    char         dll_name[32];
    char         annotation[160];
    int          risk_level;
} IremHashMatch;

typedef struct {
    IremHashMatch* matches;
    int            count;
    int            capacity;
} IremHashMatchDB;

void irem_hash_db_init(IremHashMatchDB* db);
void irem_hash_db_free(IremHashMatchDB* db);

/* One-time initialization of hash lookup tables (sorted for binary search) */
void irem_hash_init_tables(void);

/* Scan instructions for immediate operands matching known Win32 API hashes */
bool irem_hash_scan_instructions(
    const IremFlatInstruction* instructions,
    size_t                     count,
    IremHashMatchDB*           out_matches
);

/* Single lookup: given a 32-bit hash, returns matching API name & algorithm if found */
const char* irem_hash_lookup(uint32_t hash_val, const char** out_dll, IremHashAlgo* out_algo, int* out_risk);

/* Calculate hash values directly */
uint32_t irem_calc_ror13(const char* str);
uint32_t irem_calc_ror13_dll(const char* dll_name, const char* api_name);
uint32_t irem_calc_djb2(const char* str);
uint32_t irem_calc_fnv1a(const char* str);
uint32_t irem_calc_crc32(const char* str);
uint32_t irem_calc_additive(const char* str);

#ifdef __cplusplus
}
#endif

#endif /* IREM_API_HASH_RESOLVER_H */

