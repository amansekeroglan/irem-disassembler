#ifndef IREM_STRUCT_RESOLVER_H
#define IREM_STRUCT_RESOLVER_H

#include "irem_types.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    IREM_STRUCT_NONE = 0,
    IREM_STRUCT_TEB,
    IREM_STRUCT_PEB,
    IREM_STRUCT_PEB_LDR,
    IREM_STRUCT_LDR_ENTRY,
    IREM_STRUCT_RTL_PARAMS,
    IREM_STRUCT_KPCR,
    IREM_STRUCT_KPRCB,
    IREM_STRUCT_KTHREAD,
    IREM_STRUCT_EPROCESS
} IremStructType;

typedef struct {
    size_t         insn_index;
    uint64_t       va;
    IremStructType struct_type;
    int64_t        offset;
    char           struct_name[32];
    char           field_name[64];
    char           annotation[160];
    int            depth;
    bool           is_kernel_mode;
    bool           is_anti_debug;
} IremStructAnnotation;

typedef struct {
    IremStructAnnotation* annotations;
    int                   count;
    int                   capacity;
} IremStructAnnotationDB;

void irem_struct_db_init(IremStructAnnotationDB* db);
void irem_struct_db_free(IremStructAnnotationDB* db);

/* Main resolver entry: scans flat instructions, detects TEB/PEB/KPCR access, and chains dereferences */
bool irem_resolve_struct_accesses(
    const IremFlatInstruction* instructions,
    size_t                     count,
    bool                       is_kernel_driver,
    IremStructAnnotationDB*    out_db
);

/* Query individual offsets */
const char* irem_struct_resolve_teb_offset(int64_t offset, IremStructType* out_target_type, bool* out_is_anti_debug);
const char* irem_struct_resolve_peb_offset(int64_t offset, IremStructType* out_target_type, bool* out_is_anti_debug);
const char* irem_struct_resolve_ldr_offset(int64_t offset, IremStructType* out_target_type);
const char* irem_struct_resolve_ldr_entry_offset(int64_t offset, IremStructType* out_target_type);
const char* irem_struct_resolve_rtl_params_offset(int64_t offset, IremStructType* out_target_type);
const char* irem_struct_resolve_kpcr_offset(int64_t offset, IremStructType* out_target_type);
const char* irem_struct_resolve_kthread_offset(int64_t offset, IremStructType* out_target_type);
const char* irem_struct_resolve_eprocess_offset(int64_t offset, IremStructType* out_target_type);

#ifdef __cplusplus
}
#endif

#endif /* IREM_STRUCT_RESOLVER_H */

