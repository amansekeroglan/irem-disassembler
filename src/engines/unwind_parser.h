#ifndef IREM_UNWIND_PARSER_H
#define IREM_UNWIND_PARSER_H

#include "irem_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    IREM_SAVE_PUSH = 0,
    IREM_SAVE_OFFSET
} IremRegSaveType;

typedef struct {
    IremReg         reg;
    IremRegSaveType save_type;
    int32_t         stack_offset; /* -1 if pushed */
} IremSavedReg;

typedef struct {
    uint64_t func_va;
    uint32_t func_rva;
    uint32_t func_length;
    uint32_t unwind_info_rva;

    uint8_t  prolog_size;
    uint32_t total_stack_size;
    uint32_t local_vars_size;
    uint32_t saved_regs_size;

    bool     has_frame_pointer;
    IremReg  frame_register;
    uint32_t frame_offset;

    int          saved_reg_count;
    IremSavedReg saved_regs[16];

    bool     has_exception_handler;
    uint32_t handler_rva;
    uint64_t handler_va;

    bool     is_chained;
    uint32_t chain_parent_rva;
} IremStackFrame;

/* Parses UNWIND_INFO for a single function starting from PE raw bytes.
 * Returns true if parsed successfully. */
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
);

/* RVA to file offset helper using section headers */
uint32_t irem_rva_to_file_offset(
    uint32_t rva,
    const IremSectionDesc* sections,
    size_t section_count
);

#ifdef __cplusplus
}
#endif

#endif /* IREM_UNWIND_PARSER_H */

