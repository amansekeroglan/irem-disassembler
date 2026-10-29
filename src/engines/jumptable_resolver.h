#ifndef IREM_JUMPTABLE_RESOLVER_H
#define IREM_JUMPTABLE_RESOLVER_H

#include "irem_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    IREM_JUMPTABLE_NONE = 0,
    IREM_JUMPTABLE_REL32,    /* movsxd rax, [table + rax*4]; add rax, table; jmp rax */
    IREM_JUMPTABLE_DIRECT64  /* jmp [table + rax*8] */
} IremJumpTableType;

typedef struct {
    uint64_t case_va;
    int      case_index;
    bool     is_default;
} IremSwitchCase;

typedef struct {
    uint64_t          switch_jmp_va;
    uint64_t          table_va;
    uint32_t          table_rva;
    IremJumpTableType type;
    int               case_count;
    uint64_t          default_va;
    IremSwitchCase    cases[256];
} IremJumpTable;

/* Attempt to resolve an indirect jump instruction at `jmp_idx` into a switch jump table.
 * Returns true if a valid jump table pattern was recognized and resolved. */
bool irem_jumptable_resolve(
    const IremFlatInstruction* instructions,
    size_t count,
    size_t jmp_idx,
    const uint8_t* pe_data,
    size_t pe_size,
    uint64_t image_base,
    const IremSectionDesc* sections,
    size_t section_count,
    IremJumpTable* out_table
);

/* Scan an instruction buffer for all jump tables */
int irem_jumptable_scan_all(
    const IremFlatInstruction* instructions,
    size_t count,
    const uint8_t* pe_data,
    size_t pe_size,
    uint64_t image_base,
    const IremSectionDesc* sections,
    size_t section_count,
    IremJumpTable* out_tables,
    size_t max_tables
);

#ifdef __cplusplus
}
#endif

#endif /* IREM_JUMPTABLE_RESOLVER_H */

