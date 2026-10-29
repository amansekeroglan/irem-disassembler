#include "fastcall_analyzer.h"
#include <string.h>
#include <stdio.h>

static int get_param_slot_for_reg(IremReg r) {
    IremReg canon = irem_get_canonical_64(r);
    switch (canon) {
    case IREM_REG_RCX: return 0;
    case IREM_REG_RDX: return 1;
    case IREM_REG_R8:  return 2;
    case IREM_REG_R9:  return 3;
    default:           return -1;
    }
}

static int get_stack_slot_for_disp(int64_t disp) {
    switch (disp) {
    case 0x20: return 4;
    case 0x28: return 5;
    case 0x30: return 6;
    case 0x38: return 7;
    default:   return -1;
    }
}

bool irem_fastcall_analyze_call(
    const IremFlatInstruction* instructions,
    size_t count,
    size_t call_idx,
    IremCallSiteAnalysis* out_analysis
) {
    if (!instructions || call_idx >= count || !out_analysis) return false;

    const IremFlatInstruction* call_ins = &instructions[call_idx];
    if (!call_ins->is_call) return false;

    memset(out_analysis, 0, sizeof(IremCallSiteAnalysis));
    out_analysis->call_site_va = call_ins->va;
    out_analysis->target_va = call_ins->branch_target_va;

    for (int s = 0; s < 8; ++s) {
        out_analysis->params[s].slot = s;
    }

    /* Trace backwards up to 24 instructions */
    size_t start_idx = (call_idx > 24) ? (call_idx - 24) : 0;
    bool reg_clobbered[4] = { false, false, false, false };

    for (size_t i = call_idx; i > start_idx; --i) {
        const IremFlatInstruction* ins = &instructions[i - 1];

        /* Stop backward tracing on basic block boundary */
        if (ins->is_ret || ins->is_jump) {
            break;
        }

        /* If we cross an earlier CALL, all unassigned volatile param registers are clobbered */
        if (ins->is_call) {
            for (int r = 0; r < 4; ++r) {
                reg_clobbered[r] = true;
            }
            continue;
        }

        /* 1. Check Register Parameters: RCX, RDX, R8, R9 */
        if (ins->op_count >= 2 && ins->ops[0].type == IREM_OP_REG) {
            int slot = get_param_slot_for_reg(ins->ops[0].reg);
            if (slot >= 0 && slot < 4 && !reg_clobbered[slot] && !out_analysis->params[slot].is_set) {
                IremRecoveredParam* p = &out_analysis->params[slot];

                /* Special idiom: xor reg, reg -> imm = 0 */
                if (strcmp(ins->mnemonic, "xor") == 0 &&
                    ins->ops[1].type == IREM_OP_REG &&
                    ins->ops[0].reg == ins->ops[1].reg) {
                    p->is_set = true;
                    p->src_type = IREM_PARAM_SRC_IMM;
                    p->imm_val = 0;
                }
                /* mov reg, ... */
                else if (strcmp(ins->mnemonic, "mov") == 0 || strcmp(ins->mnemonic, "movsxd") == 0 || strcmp(ins->mnemonic, "movzx") == 0) {
                    p->is_set = true;
                    if (ins->ops[1].type == IREM_OP_IMM) {
                        p->src_type = IREM_PARAM_SRC_IMM;
                        p->imm_val = ins->ops[1].imm;
                    } else if (ins->ops[1].type == IREM_OP_REG) {
                        p->src_type = IREM_PARAM_SRC_REG;
                        p->src_reg = ins->ops[1].reg;
                    } else if (ins->ops[1].type == IREM_OP_MEM) {
                        if (ins->ops[1].mem.is_rip_relative) {
                            p->src_type = IREM_PARAM_SRC_RIP_REL;
                            p->resolved_addr = ins->ops[1].mem.resolved_target_va;
                        } else {
                            p->src_type = IREM_PARAM_SRC_MEM;
                        }
                    }
                }
                /* lea reg, [rip + ...] */
                else if (strcmp(ins->mnemonic, "lea") == 0 && ins->ops[1].type == IREM_OP_MEM) {
                    p->is_set = true;
                    if (ins->ops[1].mem.is_rip_relative) {
                        p->src_type = IREM_PARAM_SRC_RIP_REL;
                        p->resolved_addr = ins->ops[1].mem.resolved_target_va;
                    } else {
                        p->src_type = IREM_PARAM_SRC_MEM;
                    }
                }
            }
        }

        /* 2. Check Stack Parameters: [RSP + 0x20], [RSP + 0x28], etc. */
        if (ins->op_count >= 2 && ins->ops[0].type == IREM_OP_MEM) {
            if (irem_get_canonical_64(ins->ops[0].mem.base) == IREM_REG_RSP) {
                int slot = get_stack_slot_for_disp(ins->ops[0].mem.disp);
                if (slot >= 4 && slot < 8 && !out_analysis->params[slot].is_set) {
                    IremRecoveredParam* p = &out_analysis->params[slot];
                    p->is_set = true;
                    if (ins->ops[1].type == IREM_OP_IMM) {
                        p->src_type = IREM_PARAM_SRC_IMM;
                        p->imm_val = ins->ops[1].imm;
                    } else if (ins->ops[1].type == IREM_OP_REG) {
                        p->src_type = IREM_PARAM_SRC_REG;
                        p->src_reg = ins->ops[1].reg;
                    }
                }
            }
        }
    }

    /* Compute highest continuous parameter count */
    int highest_slot = -1;
    for (int s = 7; s >= 0; --s) {
        if (out_analysis->params[s].is_set) {
            highest_slot = s;
            break;
        }
    }

    out_analysis->param_count = (highest_slot >= 0) ? (highest_slot + 1) : 0;
    return true;
}

int irem_fastcall_analyze_all_calls(
    const IremFlatInstruction* instructions,
    size_t count,
    IremCallSiteAnalysis* out_calls,
    size_t max_calls
) {
    if (!instructions || count == 0 || !out_calls || max_calls == 0) return 0;

    int total_calls = 0;
    for (size_t i = 0; i < count && (size_t)total_calls < max_calls; ++i) {
        if (instructions[i].is_call) {
            if (irem_fastcall_analyze_call(instructions, count, i, &out_calls[total_calls])) {
                total_calls++;
            }
        }
    }
    return total_calls;
}

