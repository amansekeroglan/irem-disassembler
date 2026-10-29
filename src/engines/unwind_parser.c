#include "unwind_parser.h"
#include <string.h>

#define UNW_FLAG_NHANDLER   0x0
#define UNW_FLAG_EHANDLER   0x1
#define UNW_FLAG_UHANDLER   0x2
#define UNW_FLAG_CHAININFO  0x4

#define UWOP_PUSH_NONVOL     0
#define UWOP_ALLOC_LARGE     1
#define UWOP_ALLOC_SMALL     2
#define UWOP_SET_FPREG       3
#define UWOP_SAVE_NONVOL     4
#define UWOP_SAVE_NONVOL_FAR 5
#define UWOP_SAVE_XMM128     8
#define UWOP_SAVE_XMM128_FAR 9
#define UWOP_PUSH_MACHFRAME  10

static IremReg decode_unwind_reg(uint8_t op_info) {
    static const IremReg map[16] = {
        IREM_REG_RAX, IREM_REG_RCX, IREM_REG_RDX, IREM_REG_RBX,
        IREM_REG_RSP, IREM_REG_RBP, IREM_REG_RSI, IREM_REG_RDI,
        IREM_REG_R8,  IREM_REG_R9,  IREM_REG_R10, IREM_REG_R11,
        IREM_REG_R12, IREM_REG_R13, IREM_REG_R14, IREM_REG_R15
    };
    return (op_info < 16) ? map[op_info] : IREM_REG_NONE;
}

uint32_t irem_rva_to_file_offset(
    uint32_t rva,
    const IremSectionDesc* sections,
    size_t section_count
) {
    if (!sections || section_count == 0) return 0;

    for (size_t i = 0; i < section_count; ++i) {
        const IremSectionDesc* sec = &sections[i];
        uint32_t sec_size = sec->virtual_size ? sec->virtual_size : sec->raw_size;
        if (rva >= sec->virtual_address && rva < sec->virtual_address + sec_size) {
            uint32_t delta = rva - sec->virtual_address;
            if (delta < sec->raw_size) {
                return sec->raw_offset + delta;
            }
        }
    }
    return 0;
}

bool irem_unwind_parse_function(
    const uint8_t* pe_data,
    size_t pe_size,
    uint64_t image_base,
    uint32_t begin_rva,
    uint32_t end_rva,
    uint32_t unwind_info_rva,
    const IremSectionDesc* sections,
    size_t section_count,
    IremStackFrame* out_frame
) {
    if (!pe_data || pe_size < 0x200 || !out_frame) return false;

    memset(out_frame, 0, sizeof(IremStackFrame));
    out_frame->func_rva = begin_rva;
    out_frame->func_va = image_base + begin_rva;
    out_frame->func_length = (end_rva > begin_rva) ? (end_rva - begin_rva) : 0;
    out_frame->unwind_info_rva = unwind_info_rva;

    if (unwind_info_rva == 0) return false;

    uint32_t file_offset = irem_rva_to_file_offset(unwind_info_rva, sections, section_count);
    if (file_offset == 0 || file_offset + 4 > pe_size) {
        return false;
    }

    const uint8_t* p = pe_data + file_offset;
    uint8_t ver_flags = p[0];
    uint8_t version = ver_flags & 0x7;
    uint8_t flags = (ver_flags >> 3) & 0x1F;
    uint8_t size_of_prolog = p[1];
    uint8_t count_of_codes = p[2];
    uint8_t frame_reg_and_offset = p[3];

    if (version != 1 && version != 2) {
        return false;
    }

    out_frame->prolog_size = size_of_prolog;

    uint8_t frame_reg_idx = frame_reg_and_offset & 0x0F;
    uint8_t frame_offset_scaled = (frame_reg_and_offset >> 4) & 0x0F;
    if (frame_reg_idx != 0) {
        out_frame->has_frame_pointer = true;
        out_frame->frame_register = decode_unwind_reg(frame_reg_idx);
        out_frame->frame_offset = (uint32_t)frame_offset_scaled * 16;
    }

    /* Unwind code array starts at byte offset 4 */
    size_t codes_offset = file_offset + 4;
    size_t codes_bytes = (size_t)count_of_codes * 2;
    if (codes_offset + codes_bytes > pe_size) {
        return false;
    }

    const uint16_t* codes = (const uint16_t*)(pe_data + codes_offset);
    uint32_t total_alloc = 0;
    uint32_t push_size = 0;

    for (uint8_t i = 0; i < count_of_codes; ) {
        uint16_t code = codes[i];
        uint8_t op = (code >> 8) & 0x0F;
        uint8_t info = (code >> 12) & 0x0F;

        switch (op) {
        case UWOP_PUSH_NONVOL: {
            if (out_frame->saved_reg_count < 16) {
                out_frame->saved_regs[out_frame->saved_reg_count].reg = decode_unwind_reg(info);
                out_frame->saved_regs[out_frame->saved_reg_count].save_type = IREM_SAVE_PUSH;
                out_frame->saved_regs[out_frame->saved_reg_count].stack_offset = -1;
                out_frame->saved_reg_count++;
            }
            push_size += 8;
            i += 1;
            break;
        }
        case UWOP_ALLOC_LARGE: {
            if (info == 0) {
                if (i + 1 < count_of_codes) {
                    uint32_t alloc = (uint32_t)codes[i + 1] * 8;
                    total_alloc += alloc;
                    i += 2;
                } else {
                    i += 1;
                }
            } else if (info == 1) {
                if (i + 2 < count_of_codes) {
                    uint32_t alloc = (uint32_t)codes[i + 1] | ((uint32_t)codes[i + 2] << 16);
                    total_alloc += alloc;
                    i += 3;
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
            break;
        }
        case UWOP_ALLOC_SMALL: {
            uint32_t alloc = (uint32_t)info * 8 + 8;
            total_alloc += alloc;
            i += 1;
            break;
        }
        case UWOP_SET_FPREG: {
            i += 1;
            break;
        }
        case UWOP_SAVE_NONVOL: {
            if (i + 1 < count_of_codes) {
                uint32_t off = (uint32_t)codes[i + 1] * 8;
                if (out_frame->saved_reg_count < 16) {
                    out_frame->saved_regs[out_frame->saved_reg_count].reg = decode_unwind_reg(info);
                    out_frame->saved_regs[out_frame->saved_reg_count].save_type = IREM_SAVE_OFFSET;
                    out_frame->saved_regs[out_frame->saved_reg_count].stack_offset = (int32_t)off;
                    out_frame->saved_reg_count++;
                }
                i += 2;
            } else {
                i += 1;
            }
            break;
        }
        case UWOP_SAVE_NONVOL_FAR: {
            if (i + 2 < count_of_codes) {
                uint32_t off = (uint32_t)codes[i + 1] | ((uint32_t)codes[i + 2] << 16);
                if (out_frame->saved_reg_count < 16) {
                    out_frame->saved_regs[out_frame->saved_reg_count].reg = decode_unwind_reg(info);
                    out_frame->saved_regs[out_frame->saved_reg_count].save_type = IREM_SAVE_OFFSET;
                    out_frame->saved_regs[out_frame->saved_reg_count].stack_offset = (int32_t)off;
                    out_frame->saved_reg_count++;
                }
                i += 3;
            } else {
                i += 1;
            }
            break;
        }
        case UWOP_SAVE_XMM128: {
            i += 2;
            break;
        }
        case UWOP_SAVE_XMM128_FAR: {
            i += 3;
            break;
        }
        case UWOP_PUSH_MACHFRAME: {
            push_size += (info == 0) ? 40 : 48;
            i += 1;
            break;
        }
        default:
            i += 1;
            break;
        }
    }

    out_frame->total_stack_size = total_alloc + push_size;
    out_frame->saved_regs_size = push_size;
    out_frame->local_vars_size = total_alloc;

    /* Check for trailing exception handler or chain info */
    uint32_t aligned_code_count = (count_of_codes + 1) & ~1;
    size_t trailing_offset = file_offset + 4 + (size_t)aligned_code_count * 2;

    if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
        if (trailing_offset + 4 <= pe_size) {
            uint32_t handler_rva = *(const uint32_t*)(pe_data + trailing_offset);
            out_frame->has_exception_handler = true;
            out_frame->handler_rva = handler_rva;
            out_frame->handler_va = image_base + handler_rva;
        }
    } else if (flags & UNW_FLAG_CHAININFO) {
        if (trailing_offset + 12 <= pe_size) {
            uint32_t chain_begin = *(const uint32_t*)(pe_data + trailing_offset);
            out_frame->is_chained = true;
            out_frame->chain_parent_rva = chain_begin;
        }
    }

    return true;
}

