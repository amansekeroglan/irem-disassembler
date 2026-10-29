#include "cfg_builder.h"
#include <stdlib.h>
#include <string.h>

void irem_cfg_init(IremCFG* cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(IremCFG));
}

void irem_cfg_free(IremCFG* cfg) {
    if (!cfg) return;
    if (cfg->blocks) {
        free(cfg->blocks);
        cfg->blocks = NULL;
    }
    if (cfg->edges) {
        free(cfg->edges);
        cfg->edges = NULL;
    }
    memset(cfg, 0, sizeof(IremCFG));
}

static bool append_block(IremCFG* cfg, const IremBasicBlock* b) {
    if (cfg->block_count >= cfg->block_capacity) {
        int new_cap = cfg->block_capacity == 0 ? 32 : cfg->block_capacity * 2;
        IremBasicBlock* arr = (IremBasicBlock*)realloc(cfg->blocks, (size_t)new_cap * sizeof(IremBasicBlock));
        if (!arr) return false;
        cfg->blocks = arr;
        cfg->block_capacity = new_cap;
    }
    cfg->blocks[cfg->block_count++] = *b;
    return true;
}

static bool append_edge(IremCFG* cfg, const IremCFGEdge* e) {
    if (cfg->edge_count >= cfg->edge_capacity) {
        int new_cap = cfg->edge_capacity == 0 ? 64 : cfg->edge_capacity * 2;
        IremCFGEdge* arr = (IremCFGEdge*)realloc(cfg->edges, (size_t)new_cap * sizeof(IremCFGEdge));
        if (!arr) return false;
        cfg->edges = arr;
        cfg->edge_capacity = new_cap;
    }
    cfg->edges[cfg->edge_count++] = *e;
    return true;
}

static int find_block_id_by_va(const IremCFG* cfg, uint64_t va) {
    for (int i = 0; i < cfg->block_count; ++i) {
        if (va >= cfg->blocks[i].start_va && va <= cfg->blocks[i].end_va) {
            return i;
        }
    }
    return -1;
}

static void add_successor(IremBasicBlock* b, int succ_id) {
    for (int i = 0; i < b->succ_count; ++i) {
        if (b->succ_ids[i] == succ_id) return;
    }
    if (b->succ_count < 8) {
        b->succ_ids[b->succ_count++] = succ_id;
    }
}

static void add_predecessor(IremBasicBlock* b, int pred_id) {
    for (int i = 0; i < b->pred_count; ++i) {
        if (b->pred_ids[i] == pred_id) return;
    }
    if (b->pred_count < 16) {
        b->pred_ids[b->pred_count++] = pred_id;
    }
}

/* DFS cycle / loop detector */
static void dfs_find_loops(
    IremCFG* cfg,
    int current_id,
    bool* visited,
    bool* in_stack
) {
    visited[current_id] = true;
    in_stack[current_id] = true;

    IremBasicBlock* curr_blk = &cfg->blocks[current_id];

    for (int i = 0; i < curr_blk->succ_count; ++i) {
        int next_id = curr_blk->succ_ids[i];

        /* Check if edge is back-edge (points to an ancestor in the active DFS stack) */
        if (in_stack[next_id]) {
            cfg->loop_count++;
            cfg->blocks[next_id].is_loop_header = true;

            for (int e = 0; e < cfg->edge_count; ++e) {
                if (cfg->edges[e].src_block_id == current_id && cfg->edges[e].dst_block_id == next_id) {
                    cfg->edges[e].is_back_edge = true;
                    break;
                }
            }
        } else if (!visited[next_id]) {
            dfs_find_loops(cfg, next_id, visited, in_stack);
        }
    }

    in_stack[current_id] = false;
}

bool irem_cfg_build(
    IremCFG* cfg,
    uint64_t func_start_va,
    uint32_t func_length,
    const IremFlatInstruction* instructions,
    size_t count
) {
    if (!cfg || !instructions || count == 0) return false;

    irem_cfg_free(cfg);
    cfg->func_va = func_start_va;
    cfg->func_length = func_length;

    uint64_t func_end_va = func_start_va + func_length;

    /* 1. Mark basic block leader instructions */
    bool* is_leader = (bool*)calloc(count, sizeof(bool));
    if (!is_leader) return false;

    is_leader[0] = true; /* First instruction is always leader */

    for (size_t i = 0; i < count; ++i) {
        const IremFlatInstruction* ins = &instructions[i];

        /* Target of any branch within this function is a leader */
        if (ins->branch_target_va >= func_start_va && ins->branch_target_va < func_end_va) {
            for (size_t j = 0; j < count; ++j) {
                if (instructions[j].va == ins->branch_target_va) {
                    is_leader[j] = true;
                    break;
                }
            }
        }

        /* Instruction immediately after a jump/ret is a leader */
        if (ins->is_jump || ins->is_conditional_jump || ins->is_ret) {
            if (i + 1 < count) {
                is_leader[i + 1] = true;
            }
        }
    }

    /* 2. Construct Basic Blocks */
    size_t blk_start_idx = 0;
    while (blk_start_idx < count) {
        size_t blk_end_idx = blk_start_idx;

        while (blk_end_idx + 1 < count && !is_leader[blk_end_idx + 1]) {
            const IremFlatInstruction* cur = &instructions[blk_end_idx];
            if (cur->is_jump || cur->is_conditional_jump || cur->is_ret) {
                break;
            }
            blk_end_idx++;
        }

        IremBasicBlock blk;
        memset(&blk, 0, sizeof(blk));
        blk.block_id = cfg->block_count;
        blk.start_va = instructions[blk_start_idx].va;
        blk.end_va = instructions[blk_end_idx].va + instructions[blk_end_idx].length - 1;
        blk.start_idx = blk_start_idx;
        blk.end_idx = blk_end_idx;
        blk.instruction_count = (int)(blk_end_idx - blk_start_idx + 1);
        blk.is_entry = (blk.block_id == 0);

        const IremFlatInstruction* term = &instructions[blk_end_idx];
        if (term->is_ret) {
            blk.is_exit = true;
            blk.has_terminator = true;
            blk.is_return = true;
        } else if (term->is_jump || term->is_conditional_jump) {
            blk.has_terminator = true;
            blk.is_conditional = term->is_conditional_jump;
            blk.branch_target_va = term->branch_target_va;
        } else if (term->is_call) {
            blk.is_call = true;
            blk.branch_target_va = term->branch_target_va;
        }

        append_block(cfg, &blk);
        blk_start_idx = blk_end_idx + 1;
    }

    free(is_leader);

    /* 3. Build Edges between Blocks */
    for (int i = 0; i < cfg->block_count; ++i) {
        IremBasicBlock* blk = &cfg->blocks[i];
        const IremFlatInstruction* term = &instructions[blk->end_idx];

        if (term->is_ret) {
            /* Exit block, no successors */
            continue;
        }

        if (term->is_conditional_jump) {
            /* True Branch: Target */
            int target_id = find_block_id_by_va(cfg, term->branch_target_va);
            if (target_id >= 0) {
                IremCFGEdge e_true = { i, target_id, term->va, term->branch_target_va, IREM_EDGE_JUMP_TRUE, false };
                append_edge(cfg, &e_true);
                add_successor(blk, target_id);
                add_predecessor(&cfg->blocks[target_id], i);
            }

            /* False Branch: Fallthrough to next block */
            if (i + 1 < cfg->block_count) {
                IremCFGEdge e_false = { i, i + 1, term->va, cfg->blocks[i + 1].start_va, IREM_EDGE_JUMP_FALSE, false };
                append_edge(cfg, &e_false);
                add_successor(blk, i + 1);
                add_predecessor(&cfg->blocks[i + 1], i);
            }
        } else if (term->is_jump) {
            /* Unconditional Jump */
            int target_id = find_block_id_by_va(cfg, term->branch_target_va);
            if (target_id >= 0) {
                IremCFGEdge e_jmp = { i, target_id, term->va, term->branch_target_va, IREM_EDGE_JUMP_UNCOND, false };
                append_edge(cfg, &e_jmp);
                add_successor(blk, target_id);
                add_predecessor(&cfg->blocks[target_id], i);
            }
        } else {
            /* Normal fallthrough */
            if (i + 1 < cfg->block_count) {
                IremCFGEdge e_fall = { i, i + 1, term->va, cfg->blocks[i + 1].start_va, IREM_EDGE_FALLTHROUGH, false };
                append_edge(cfg, &e_fall);
                add_successor(blk, i + 1);
                add_predecessor(&cfg->blocks[i + 1], i);
            }
        }
    }

    /* 4. Reachability & Loop Detection */
    if (cfg->block_count > 0) {
        bool* visited = (bool*)calloc(cfg->block_count, sizeof(bool));
        bool* in_stack = (bool*)calloc(cfg->block_count, sizeof(bool));

        if (visited && in_stack) {
            dfs_find_loops(cfg, 0, visited, in_stack);

            for (int i = 0; i < cfg->block_count; ++i) {
                if (!visited[i]) {
                    cfg->blocks[i].is_unreachable = true;
                    cfg->unreachable_block_count++;
                }
            }
        }

        free(visited);
        free(in_stack);
    }

    /* 5. Cyclomatic Complexity: M = E - N + 2P */
    int complexity = cfg->edge_count - cfg->block_count + 2;
    cfg->cyclomatic_complexity = (complexity >= 1) ? complexity : 1;

    return true;
}

const IremBasicBlock* irem_cfg_find_block_by_va(const IremCFG* cfg, uint64_t va) {
    if (!cfg || cfg->block_count == 0) return NULL;
    int id = find_block_id_by_va(cfg, va);
    return (id >= 0) ? &cfg->blocks[id] : NULL;
}

