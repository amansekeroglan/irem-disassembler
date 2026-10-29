#ifndef IREM_CFG_LAYOUT_H
#define IREM_CFG_LAYOUT_H

#include "cfg_builder.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int      block_id;
    float    x;             /* World-space X */
    float    y;             /* World-space Y */
    float    width;         /* Width in pixels */
    float    height;        /* Height in pixels */
    int      layer;         /* Layer index (0 = entry) */
    int      pos_in_layer;
} IremCFGNodeLayout;

typedef struct {
    int          src_block_id;
    int          dst_block_id;
    IremEdgeType type;
    bool         is_back_edge;
    float        start_x, start_y;
    float        end_x, end_y;
    float        mid_x1, mid_y1;
    float        mid_x2, mid_y2;
    int          point_count; /* 2 to 4 waypoints */
} IremCFGEdgeLayout;

typedef struct {
    uint64_t           func_va;
    int                node_count;
    IremCFGNodeLayout* nodes;
    int                edge_count;
    IremCFGEdgeLayout* edges;
    float              bounds_min_x;
    float              bounds_min_y;
    float              bounds_max_x;
    float              bounds_max_y;
    float              total_width;
    float              total_height;
} IremCFGLayout;

void irem_cfg_layout_init(IremCFGLayout* layout);
void irem_cfg_layout_free(IremCFGLayout* layout);

/* Calculates visual layout (layered tree / Sugiyama simplified) for a function CFG */
bool irem_cfg_layout_compute(
    IremCFGLayout*             layout,
    const IremCFG*             cfg,
    const IremFlatInstruction* instructions,
    size_t                     insn_count,
    float                      char_width,
    float                      line_height
);

#ifdef __cplusplus
}
#endif

#endif /* IREM_CFG_LAYOUT_H */

