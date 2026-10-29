#ifndef IREM_FASTCALL_ANALYZER_H
#define IREM_FASTCALL_ANALYZER_H

#include "irem_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    IREM_PARAM_SRC_UNKNOWN = 0,
    IREM_PARAM_SRC_IMM,
    IREM_PARAM_SRC_REG,
    IREM_PARAM_SRC_MEM,
    IREM_PARAM_SRC_RIP_REL
} IremParamSrcType;

typedef struct {
    int              slot;            /* 0=RCX, 1=RDX, 2=R8, 3=R9, 4=[rsp+20h], 5=[rsp+28h] */
    IremParamSrcType src_type;
    uint64_t         imm_val;
    IremReg          src_reg;
    uint64_t         resolved_addr;
    bool             is_set;
} IremRecoveredParam;

typedef struct {
    uint64_t           call_site_va;
    uint64_t           target_va;
    int                param_count;
    IremRecoveredParam params[8];      /* Up to 8 parameters */
} IremCallSiteAnalysis;

typedef struct {
    uint64_t func_va;
    int      estimated_params;
    int      call_sites_analyzed;
    char     signature_str[128];      /* e.g. "sub_140001000(arg0, arg1, arg2)" */
} IremFuncSignature;

/* Analyze a single CALL instruction at index `call_idx` in `instructions` */
bool irem_fastcall_analyze_call(
    const IremFlatInstruction* instructions,
    size_t count,
    size_t call_idx,
    IremCallSiteAnalysis* out_analysis
);

/* Analyze all call instructions in a buffer */
int irem_fastcall_analyze_all_calls(
    const IremFlatInstruction* instructions,
    size_t count,
    IremCallSiteAnalysis* out_calls,
    size_t max_calls
);

#ifdef __cplusplus
}
#endif

#endif /* IREM_FASTCALL_ANALYZER_H */

