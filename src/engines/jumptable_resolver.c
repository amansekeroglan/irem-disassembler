#include "jumptable_resolver.h"
#include "unwind_parser.h"
#include <string.h>

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
) {
    if (!instructions || jmp_idx >= count || !pe_data || !out_table) return false;

    const IremFlatInstruction* jmp_ins = &instructions[jmp_idx];
    if (strcmp(jmp_ins->mnemonic, "jmp") != 0) return false;

    /* Jump must be indirect (to a register or memory with index) */
    bool is_reg_indirect = (jmp_ins->op_count >= 1 && jmp_ins->ops[0].type == IREM_OP_REG);
    bool is_mem_indirect = (jmp_ins->op_count >= 1 && jmp_ins->ops[0].type == IREM_OP_MEM);

    if (!is_reg_indirect && !is_mem_indirect) return false;

    memset(out_table, 0, sizeof(IremJumpTable));
    out_table->switch_jmp_va = jmp_ins->va;

    /* Scan backwards up to 12 instructions for cmp and lea patterns */
    size_t scan_start = (jmp_idx > 12) ? (jmp_idx - 12) : 0;
    int max_case = -1;
    uint64_t table_va = 0;
    uint64_t default_va = 0;
    bool is_rel32 = false;

    for (size_t i = jmp_idx; i > scan_start; --i) {
        const IremFlatInstruction* prev = &instructions[i - 1];

        /* Detect `cmp reg, imm` */
        if (strcmp(prev->mnemonic, "cmp") == 0 && prev->op_count >= 2) {
            if (prev->ops[1].type == IREM_OP_IMM && prev->ops[1].imm <= 256) {
                max_case = (int)prev->ops[1].imm;
            }
        }

        /* Detect `ja / jae default` */
        if ((strcmp(prev->mnemonic, "ja") == 0 || strcmp(prev->mnemonic, "jae") == 0) && prev->branch_target_va != 0) {
            default_va = prev->branch_target_va;
        }

        /* Detect `lea reg, [rip + disp]` -> Jump Table base */
        if (strcmp(prev->mnemonic, "lea") == 0 && prev->op_count >= 2) {
            if (prev->ops[1].type == IREM_OP_MEM && prev->ops[1].mem.is_rip_relative) {
                table_va = prev->ops[1].mem.resolved_target_va;
            }
        }

        /* Detect `movsxd` -> 32-bit relative offset table */
        if (strcmp(prev->mnemonic, "movsxd") == 0) {
            is_rel32 = true;
        }
    }

    if (max_case <= 0 || max_case > 256 || table_va == 0) {
        return false;
    }

    int total_cases = max_case + 1;
    out_table->case_count = total_cases;
    out_table->table_va = table_va;
    out_table->table_rva = (table_va >= image_base) ? (uint32_t)(table_va - image_base) : 0;
    out_table->default_va = default_va;
    out_table->type = is_rel32 ? IREM_JUMPTABLE_REL32 : IREM_JUMPTABLE_DIRECT64;

    /* Read jump table entries from PE raw data */
    uint32_t file_off = irem_rva_to_file_offset(out_table->table_rva, sections, section_count);
    if (file_off == 0) return false;

    size_t entry_size = is_rel32 ? sizeof(int32_t) : sizeof(uint64_t);
    if (file_off + (size_t)total_cases * entry_size > pe_size) {
        return false;
    }

    const uint8_t* table_data = pe_data + file_off;
    for (int c = 0; c < total_cases && c < 256; ++c) {
        out_table->cases[c].case_index = c;
        if (is_rel32) {
            int32_t rel_offset = *(const int32_t*)(table_data + (size_t)c * sizeof(int32_t));
            out_table->cases[c].case_va = table_va + (int64_t)rel_offset;
        } else {
            uint64_t abs_addr = *(const uint64_t*)(table_data + (size_t)c * sizeof(uint64_t));
            out_table->cases[c].case_va = abs_addr;
        }
    }

    return true;
}

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
) {
    if (!instructions || count == 0 || !pe_data || !out_tables || max_tables == 0) return 0;

    int total = 0;
    for (size_t i = 0; i < count && (size_t)total < max_tables; ++i) {
        if (strcmp(instructions[i].mnemonic, "jmp") == 0) {
            if (irem_jumptable_resolve(instructions, count, i, pe_data, pe_size, image_base, sections, section_count, &out_tables[total])) {
                total++;
            }
        }
    }
    return total;
}

