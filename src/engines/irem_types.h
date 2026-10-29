#ifndef IREM_TYPES_H
#define IREM_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Register IDs matching agy::disasm::Reg */
typedef enum {
    IREM_REG_NONE = 0,
    /* 64-bit */
    IREM_REG_RAX, IREM_REG_RCX, IREM_REG_RDX, IREM_REG_RBX,
    IREM_REG_RSP, IREM_REG_RBP, IREM_REG_RSI, IREM_REG_RDI,
    IREM_REG_R8,  IREM_REG_R9,  IREM_REG_R10, IREM_REG_R11,
    IREM_REG_R12, IREM_REG_R13, IREM_REG_R14, IREM_REG_R15,
    IREM_REG_RIP,

    /* 32-bit */
    IREM_REG_EAX, IREM_REG_ECX, IREM_REG_EDX, IREM_REG_EBX,
    IREM_REG_ESP, IREM_REG_EBP, IREM_REG_ESI, IREM_REG_EDI,
    IREM_REG_R8D, IREM_REG_R9D, IREM_REG_R10D, IREM_REG_R11D,
    IREM_REG_R12D, IREM_REG_R13D, IREM_REG_R14D, IREM_REG_R15D,

    /* 16-bit */
    IREM_REG_AX, IREM_REG_CX, IREM_REG_DX, IREM_REG_BX,
    IREM_REG_SP, IREM_REG_BP, IREM_REG_SI, IREM_REG_DI,
    IREM_REG_R8W, IREM_REG_R9W, IREM_REG_R10W, IREM_REG_R11W,
    IREM_REG_R12W, IREM_REG_R13W, IREM_REG_R14W, IREM_REG_R15W,

    /* 8-bit */
    IREM_REG_AL, IREM_REG_CL, IREM_REG_DL, IREM_REG_BL,
    IREM_REG_SPL, IREM_REG_BPL, IREM_REG_SIL, IREM_REG_DIL,
    IREM_REG_R8B, IREM_REG_R9B, IREM_REG_R10B, IREM_REG_R11B,
    IREM_REG_R12B, IREM_REG_R13B, IREM_REG_R14B, IREM_REG_R15B,
    IREM_REG_AH, IREM_REG_CH, IREM_REG_DH, IREM_REG_BH,
    IREM_REG_MAX
} IremReg;

typedef enum {
    IREM_OP_NONE = 0,
    IREM_OP_REG,
    IREM_OP_IMM,
    IREM_OP_MEM
} IremOpType;

typedef enum {
    IREM_SEG_NONE = 0,
    IREM_SEG_ES,
    IREM_SEG_CS,
    IREM_SEG_SS,
    IREM_SEG_DS,
    IREM_SEG_FS,
    IREM_SEG_GS
} IremSegmentOverride;

typedef struct {
    IremReg             base;
    IremReg             index;
    uint8_t             scale;          /* 1, 2, 4, 8 */
    int64_t             disp;
    uint8_t             size_bytes;     /* 1, 2, 4, 8 */
    bool                is_rip_relative;
    uint64_t            resolved_target_va;
    IremSegmentOverride segment_override;
} IremMemoryOperand;

typedef struct {
    IremOpType        type;
    IremReg           reg;
    uint64_t          imm;
    bool              imm_signed;
    IremMemoryOperand mem;
} IremFlatOperand;

typedef struct {
    uint64_t        va;
    uint32_t        rva;
    uint32_t        file_offset;
    uint8_t         length;
    uint8_t         raw_bytes[15];
    char            mnemonic[16];

    uint8_t         op_count;
    IremFlatOperand ops[4];

    bool            is_jump;
    bool            is_conditional_jump;
    bool            is_call;
    bool            is_ret;
    uint64_t        branch_target_va;
} IremFlatInstruction;

/* Raw PE Section descriptor for C engines */
typedef struct {
    char     name[16];
    uint32_t virtual_size;
    uint32_t virtual_address; /* RVA */
    uint32_t raw_size;
    uint32_t raw_offset;      /* file offset */
    uint32_t characteristics;
    bool     is_executable;
    bool     is_readable;
    bool     is_writable;
} IremSectionDesc;

/* Helper: Map any register sub-register to its 64-bit root canonical register */
static inline IremReg irem_get_canonical_64(IremReg r) {
    switch (r) {
    case IREM_REG_RAX: case IREM_REG_EAX: case IREM_REG_AX: case IREM_REG_AL: case IREM_REG_AH:
        return IREM_REG_RAX;
    case IREM_REG_RCX: case IREM_REG_ECX: case IREM_REG_CX: case IREM_REG_CL: case IREM_REG_CH:
        return IREM_REG_RCX;
    case IREM_REG_RDX: case IREM_REG_EDX: case IREM_REG_DX: case IREM_REG_DL: case IREM_REG_DH:
        return IREM_REG_RDX;
    case IREM_REG_RBX: case IREM_REG_EBX: case IREM_REG_BX: case IREM_REG_BL: case IREM_REG_BH:
        return IREM_REG_RBX;
    case IREM_REG_RSP: case IREM_REG_ESP: case IREM_REG_SP: case IREM_REG_SPL:
        return IREM_REG_RSP;
    case IREM_REG_RBP: case IREM_REG_EBP: case IREM_REG_BP: case IREM_REG_BPL:
        return IREM_REG_RBP;
    case IREM_REG_RSI: case IREM_REG_ESI: case IREM_REG_SI: case IREM_REG_SIL:
        return IREM_REG_RSI;
    case IREM_REG_RDI: case IREM_REG_EDI: case IREM_REG_DI: case IREM_REG_DIL:
        return IREM_REG_RDI;
    case IREM_REG_R8:  case IREM_REG_R8D:  case IREM_REG_R8W:  case IREM_REG_R8B:
        return IREM_REG_R8;
    case IREM_REG_R9:  case IREM_REG_R9D:  case IREM_REG_R9W:  case IREM_REG_R9B:
        return IREM_REG_R9;
    case IREM_REG_R10: case IREM_REG_R10D: case IREM_REG_R10W: case IREM_REG_R10B:
        return IREM_REG_R10;
    case IREM_REG_R11: case IREM_REG_R11D: case IREM_REG_R11W: case IREM_REG_R11B:
        return IREM_REG_R11;
    case IREM_REG_R12: case IREM_REG_R12D: case IREM_REG_R12W: case IREM_REG_R12B:
        return IREM_REG_R12;
    case IREM_REG_R13: case IREM_REG_R13D: case IREM_REG_R13W: case IREM_REG_R13B:
        return IREM_REG_R13;
    case IREM_REG_R14: case IREM_REG_R14D: case IREM_REG_R14W: case IREM_REG_R14B:
        return IREM_REG_R14;
    case IREM_REG_R15: case IREM_REG_R15D: case IREM_REG_R15W: case IREM_REG_R15B:
        return IREM_REG_R15;
    case IREM_REG_RIP:
        return IREM_REG_RIP;
    default:
        return IREM_REG_NONE;
    }
}

#ifdef __cplusplus
}
#endif

#endif /* IREM_TYPES_H */

