#include "cfg_layout.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

void irem_cfg_layout_init(IremCFGLayout* layout) {
    if (!layout) return;
    memset(layout, 0, sizeof(*layout));
}

void irem_cfg_layout_free(IremCFGLayout* layout) {
    if (!layout) return;
    if (layout->nodes) {
        free(layout->nodes);
        layout->nodes = NULL;
    }
    if (layout->edges) {
        free(layout->edges);
        layout->edges = NULL;
    }
    memset(layout, 0, sizeof(*layout));
}

/* Helper: estimate text line width for instruction in characters */
static int estimate_insn_char_count(const IremFlatInstruction* ins) {
    int len = (int)strlen(ins->mnemonic) + 1;
    for (uint8_t op = 0; op < ins->op_count; ++op) {
        if (op > 0) len += 2;
        switch (ins->ops[op].type) {
        case IREM_OP_REG: len += 4; break;
        case IREM_OP_IMM: len += 10; break;
        case IREM_OP_MEM: len += 18; break;
        default: break;
        }
    }
    return len > 20 ? len : 20;
}

bool irem_cfg_layout_compute(
    IremCFGLayout*             layout,
    const IremCFG*             cfg,
    const IremFlatInstruction* instructions,
    size_t                     insn_count,
    float                      char_width,
    float                      line_height
) {
    if (!layout || !cfg || cfg->block_count == 0) return false;

    (void)instructions;
    (void)insn_count;

    irem_cfg_layout_free(layout);

    layout->func_va = cfg->func_va;
    layout->node_count = cfg->block_count;
    layout->nodes = (IremCFGNodeLayout*)calloc(cfg->block_count, sizeof(IremCFGNodeLayout));
    if (!layout->nodes) return false;

    if (char_width <= 0.0f) char_width = 8.0f;
    if (line_height <= 0.0f) line_height = 18.0f;

    /* 1. Calculate dimensions for each basic block node */
    for (int i = 0; i < cfg->block_count; ++i) {
        const IremBasicBlock* bb = &cfg->blocks[i];
        IremCFGNodeLayout* node = &layout->nodes[i];
        node->block_id = bb->block_id;

        int max_chars = 24;
        if (instructions && bb->start_idx <= bb->end_idx && bb->end_idx < insn_count) {
            for (size_t k = bb->start_idx; k <= bb->end_idx; ++k) {
                int c = estimate_insn_char_count(&instructions[k]);
                if (c > max_chars) max_chars = c;
            }
        }

        /* Width = address col + text + padding */
        float w = (float)(max_chars + 14) * char_width + 32.0f;
        if (w < 260.0f) w = 260.0f;
        if (w > 480.0f) w = 480.0f;

        /* Height = header bar (28px) + instruction rows + margin */
        int insn_rows = bb->instruction_count > 0 ? bb->instruction_count : 1;
        float h = 32.0f + ((float)insn_rows * line_height) + 12.0f;

        node->width = w;
        node->height = h;
        node->layer = -1;
    }

    /* 2. Layer Assignment using BFS from Entry Block (block 0) */
    int q_capacity = cfg->block_count * 8 + 64;
    int* queue = (int*)malloc(q_capacity * sizeof(int));
    if (!queue) return false;

    int q_head = 0, q_tail = 0;

    /* Entry block is layer 0 */
    layout->nodes[0].layer = 0;
    queue[q_tail++] = 0;

    while (q_head < q_tail) {
        int curr_id = queue[q_head++];
        int curr_layer = layout->nodes[curr_id].layer;
        const IremBasicBlock* curr_bb = &cfg->blocks[curr_id];

        if (curr_layer >= cfg->block_count) continue; /* Cycle guard */

        for (int s = 0; s < curr_bb->succ_count; ++s) {
            int succ_id = curr_bb->succ_ids[s];
            if (succ_id < 0 || succ_id >= cfg->block_count) continue;

            /* Check if this edge is a back-edge (loop) */
            bool is_back = false;
            for (int e = 0; e < cfg->edge_count; ++e) {
                if (cfg->edges[e].src_block_id == curr_id && cfg->edges[e].dst_block_id == succ_id) {
                    if (cfg->edges[e].is_back_edge) {
                        is_back = true;
                        break;
                    }
                }
            }
            if (is_back) continue;

            if (layout->nodes[succ_id].layer < curr_layer + 1) {
                layout->nodes[succ_id].layer = curr_layer + 1;
                if (q_tail >= q_capacity) {
                    int new_cap = q_capacity * 2;
                    int* new_q = (int*)realloc(queue, new_cap * sizeof(int));
                    if (!new_q) break;
                    queue = new_q;
                    q_capacity = new_cap;
                }
                queue[q_tail++] = succ_id;
            }
        }
    }
    free(queue);

    /* Assign any unreached blocks to layer 0 or 1 */
    int max_layer = 0;
    for (int i = 0; i < cfg->block_count; ++i) {
        if (layout->nodes[i].layer < 0) {
            layout->nodes[i].layer = 0;
        }
        if (layout->nodes[i].layer > max_layer) {
            max_layer = layout->nodes[i].layer;
        }
    }

    /* 3. Compute layer node groups and horizontal positions */
    int* layer_counts = (int*)calloc(max_layer + 1, sizeof(int));
    float* layer_max_heights = (float*)calloc(max_layer + 1, sizeof(float));
    float* layer_total_widths = (float*)calloc(max_layer + 1, sizeof(float));

    if (!layer_counts || !layer_max_heights || !layer_total_widths) {
        free(layer_counts); free(layer_max_heights); free(layer_total_widths);
        return false;
    }

    const float H_GAP = 50.0f;
    const float V_GAP = 70.0f;

    for (int i = 0; i < cfg->block_count; ++i) {
        int l = layout->nodes[i].layer;
        layer_counts[l]++;
        if (layout->nodes[i].height > layer_max_heights[l]) {
            layer_max_heights[l] = layout->nodes[i].height;
        }
    }

    for (int l = 0; l <= max_layer; ++l) {
        float w_sum = 0.0f;
        for (int i = 0; i < cfg->block_count; ++i) {
            if (layout->nodes[i].layer == l) {
                w_sum += layout->nodes[i].width;
            }
        }
        if (layer_counts[l] > 1) {
            w_sum += (float)(layer_counts[l] - 1) * H_GAP;
        }
        layer_total_widths[l] = w_sum;
    }

    /* Find max layer width to center entire graph */
    float graph_max_w = 0.0f;
    for (int l = 0; l <= max_layer; ++l) {
        if (layer_total_widths[l] > graph_max_w) {
            graph_max_w = layer_total_widths[l];
        }
    }

    /* Assign X and Y coordinates to each node */
    float current_y = 50.0f;
    for (int l = 0; l <= max_layer; ++l) {
        float start_x = 50.0f + (graph_max_w - layer_total_widths[l]) * 0.5f;
        float cur_x = start_x;
        int pos = 0;

        for (int i = 0; i < cfg->block_count; ++i) {
            if (layout->nodes[i].layer == l) {
                layout->nodes[i].x = cur_x;
                layout->nodes[i].y = current_y;
                layout->nodes[i].pos_in_layer = pos++;
                cur_x += layout->nodes[i].width + H_GAP;
            }
        }

        current_y += layer_max_heights[l] + V_GAP;
    }

    free(layer_counts);
    free(layer_max_heights);
    free(layer_total_widths);

    /* 4. Route Edges */
    layout->edge_count = cfg->edge_count;
    layout->edges = (IremCFGEdgeLayout*)calloc(cfg->edge_count, sizeof(IremCFGEdgeLayout));
    if (!layout->edges) return false;

    for (int e = 0; e < cfg->edge_count; ++e) {
        const IremCFGEdge* ce = &cfg->edges[e];
        IremCFGEdgeLayout* le = &layout->edges[e];

        le->src_block_id = ce->src_block_id;
        le->dst_block_id = ce->dst_block_id;
        le->type = ce->type;
        le->is_back_edge = ce->is_back_edge;

        if (ce->src_block_id >= 0 && ce->src_block_id < cfg->block_count &&
            ce->dst_block_id >= 0 && ce->dst_block_id < cfg->block_count) {
            const IremCFGNodeLayout* sn = &layout->nodes[ce->src_block_id];
            const IremCFGNodeLayout* dn = &layout->nodes[ce->dst_block_id];

            if (!ce->is_back_edge && sn->y < dn->y) {
                /* Downward forward-edge */
                float exit_x = sn->x + (sn->width * 0.5f);
                if (ce->type == IREM_EDGE_JUMP_TRUE) {
                    exit_x = sn->x + (sn->width * 0.35f);
                } else if (ce->type == IREM_EDGE_JUMP_FALSE) {
                    exit_x = sn->x + (sn->width * 0.65f);
                }

                le->start_x = exit_x;
                le->start_y = sn->y + sn->height;

                le->end_x = dn->x + (dn->width * 0.5f);
                le->end_y = dn->y;

                float mid_y = le->start_y + (le->end_y - le->start_y) * 0.5f;
                le->mid_x1 = le->start_x;
                le->mid_y1 = mid_y;
                le->mid_x2 = le->end_x;
                le->mid_y2 = mid_y;
                le->point_count = 4;
            } else {
                /* Loop back-edge: route outward to the left */
                float loop_gutter_x = sn->x < dn->x ? (sn->x - 30.0f) : (dn->x - 30.0f);
                if (loop_gutter_x < 20.0f) loop_gutter_x = 20.0f;

                le->start_x = sn->x;
                le->start_y = sn->y + (sn->height * 0.5f);

                le->mid_x1 = loop_gutter_x;
                le->mid_y1 = le->start_y;

                le->mid_x2 = loop_gutter_x;
                le->mid_y2 = dn->y + 12.0f;

                le->end_x = dn->x;
                le->end_y = dn->y + 12.0f;
                le->point_count = 4;
            }
        }
    }

    /* 5. Compute bounding box */
    float min_x = 999999.0f, min_y = 999999.0f;
    float max_x = -999999.0f, max_y = -999999.0f;

    for (int i = 0; i < layout->node_count; ++i) {
        const IremCFGNodeLayout* n = &layout->nodes[i];
        if (n->x < min_x) min_x = n->x;
        if (n->y < min_y) min_y = n->y;
        if (n->x + n->width > max_x) max_x = n->x + n->width;
        if (n->y + n->height > max_y) max_y = n->y + n->height;
    }

    layout->bounds_min_x = min_x;
    layout->bounds_min_y = min_y;
    layout->bounds_max_x = max_x + 50.0f;
    layout->bounds_max_y = max_y + 50.0f;
    layout->total_width = layout->bounds_max_x - layout->bounds_min_x;
    layout->total_height = layout->bounds_max_y - layout->bounds_min_y;

    return true;
}

