#ifndef IREM_CFG_BUILDER_H
#define IREM_CFG_BUILDER_H

#include "irem_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    IREM_EDGE_FALLTHROUGH = 0,
    IREM_EDGE_JUMP_UNCOND,
    IREM_EDGE_JUMP_TRUE,
    IREM_EDGE_JUMP_FALSE,
    IREM_EDGE_CALL
} IremEdgeType;

typedef struct {
    int          src_block_id;
    int          dst_block_id;
    uint64_t     src_va;
    uint64_t     dst_va;
    IremEdgeType type;
    bool         is_back_edge; /* Loop back-edge */
} IremCFGEdge;

typedef struct {
    int      block_id;
    uint64_t start_va;
    uint64_t end_va;
    size_t   start_idx;
    size_t   end_idx;      /* inclusive */
    int      instruction_count;

    bool     is_entry;
    bool     is_exit;
    bool     is_loop_header;
    bool     is_unreachable;
    int      loop_depth;

    /* Successors and predecessors */
    int      succ_count;
    int      succ_ids[8];
    int      pred_count;
    int      pred_ids[16];

    /* Terminator info */
    bool     has_terminator;
    bool     is_conditional;
    bool     is_call;
    bool     is_return;
    uint64_t branch_target_va;
} IremBasicBlock;

typedef struct {
    uint64_t        func_va;
    uint32_t        func_length;

    int             block_count;
    int             block_capacity;
    IremBasicBlock* blocks;

    int             edge_count;
    int             edge_capacity;
    IremCFGEdge*    edges;

    int             loop_count;
    int             cyclomatic_complexity;
    int             unreachable_block_count;
} IremCFG;

/* Initialize empty CFG */
void irem_cfg_init(IremCFG* cfg);

/* Free CFG resources */
void irem_cfg_free(IremCFG* cfg);

/* Build CFG for a function given its slice of instructions */
bool irem_cfg_build(
    IremCFG* cfg,
    uint64_t func_start_va,
    uint32_t func_length,
    const IremFlatInstruction* instructions,
    size_t count
);

/* Find basic block containing given VA */
const IremBasicBlock* irem_cfg_find_block_by_va(const IremCFG* cfg, uint64_t va);

#ifdef __cplusplus
}
#endif

#endif /* IREM_CFG_BUILDER_H */

