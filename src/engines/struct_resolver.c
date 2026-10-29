#include "struct_resolver.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    int64_t        offset;
    const char*    field_name;
    IremStructType target_type;
    bool           is_anti_debug;
} StructFieldEntry;

/* TEB field definitions (gs:[offset]) */
static const StructFieldEntry TEB_FIELDS[] = {
    { 0x00, "NtTib.ExceptionList",               IREM_STRUCT_NONE,       false },
    { 0x08, "NtTib.StackBase",                   IREM_STRUCT_NONE,       false },
    { 0x10, "NtTib.StackLimit",                  IREM_STRUCT_NONE,       false },
    { 0x18, "NtTib.SubSystemTib",                IREM_STRUCT_NONE,       false },
    { 0x20, "NtTib.FiberData",                   IREM_STRUCT_NONE,       false },
    { 0x28, "NtTib.ArbitraryUserPointer",        IREM_STRUCT_NONE,       false },
    { 0x30, "NtTib.Self",                        IREM_STRUCT_TEB,        false },
    { 0x38, "EnvironmentPointer",                IREM_STRUCT_NONE,       false },
    { 0x40, "ClientId.UniqueProcess (PID)",      IREM_STRUCT_NONE,       false },
    { 0x48, "ClientId.UniqueThread (TID)",       IREM_STRUCT_NONE,       false },
    { 0x50, "ActiveRpcHandle",                   IREM_STRUCT_NONE,       false },
    { 0x58, "ThreadLocalStoragePointer (TLS)",   IREM_STRUCT_NONE,       false },
    { 0x60, "ProcessEnvironmentBlock (PEB)",     IREM_STRUCT_PEB,        false },
    { 0x68, "LastErrorValue",                    IREM_STRUCT_NONE,       false },
    { 0x70, "CountOfOwnedCriticalSections",      IREM_STRUCT_NONE,       false },
    { 0x78, "CsrClientThread",                   IREM_STRUCT_NONE,       false },
    { 0x80, "Win32ThreadInfo",                   IREM_STRUCT_NONE,       false },
    { 0x1478, "DeallocationStack",               IREM_STRUCT_NONE,       false },
    { 0x1480, "TlsSlots[0]",                     IREM_STRUCT_NONE,       false },
    { 0x1780, "TlsExpansionSlots",               IREM_STRUCT_NONE,       false },
    { -1, NULL, IREM_STRUCT_NONE, false }
};

/* PEB field definitions */
static const StructFieldEntry PEB_FIELDS[] = {
    { 0x00, "InheritedAddressSpace",             IREM_STRUCT_NONE,       false },
    { 0x01, "ReadImageFileExecOptions",          IREM_STRUCT_NONE,       false },
    { 0x02, "BeingDebugged",                     IREM_STRUCT_NONE,       true  },
    { 0x03, "BitField",                          IREM_STRUCT_NONE,       false },
    { 0x04, "Mutant",                            IREM_STRUCT_NONE,       false },
    { 0x08, "ImageBaseAddress",                  IREM_STRUCT_NONE,       false },
    { 0x10, "Ldr (PEB_LDR_DATA*)",               IREM_STRUCT_PEB_LDR,    false },
    { 0x18, "ProcessParameters (RTL_PARAMS*)",   IREM_STRUCT_RTL_PARAMS, false },
    { 0x20, "SubSystemData",                     IREM_STRUCT_NONE,       false },
    { 0x28, "ProcessHeap",                       IREM_STRUCT_NONE,       false },
    { 0x30, "FastPebLock",                       IREM_STRUCT_NONE,       false },
    { 0x38, "AtlThunkSListPtr",                  IREM_STRUCT_NONE,       false },
    { 0x40, "IFEOKey",                           IREM_STRUCT_NONE,       false },
    { 0x44, "CrossProcessFlags",                 IREM_STRUCT_NONE,       false },
    { 0x48, "KernelCallbackTable",               IREM_STRUCT_NONE,       false },
    { 0x50, "UserSharedInfoPtr",                 IREM_STRUCT_NONE,       false },
    { 0x58, "SystemReserved",                    IREM_STRUCT_NONE,       false },
    { 0x60, "AtlThunkSListPtr32",                IREM_STRUCT_NONE,       false },
    { 0x64, "ApiSetMap",                         IREM_STRUCT_NONE,       false },
    { 0x68, "TlsExpansionCounter",               IREM_STRUCT_NONE,       false },
    { 0x70, "TlsBitmap",                         IREM_STRUCT_NONE,       false },
    { 0x78, "TlsBitmapBits[2]",                  IREM_STRUCT_NONE,       false },
    { 0x80, "ReadOnlySharedMemoryBase",          IREM_STRUCT_NONE,       false },
    { 0x88, "HotpatchInformation",               IREM_STRUCT_NONE,       false },
    { 0x90, "ReadOnlyStaticServerData",          IREM_STRUCT_NONE,       false },
    { 0x98, "AnsiCodePageData",                  IREM_STRUCT_NONE,       false },
    { 0xA0, "OemCodePageData",                   IREM_STRUCT_NONE,       false },
    { 0xA8, "UnicodeCaseTableData",              IREM_STRUCT_NONE,       false },
    { 0xB0, "NumberOfProcessors",                IREM_STRUCT_NONE,       false },
    { 0xB4, "NtGlobalFlag",                      IREM_STRUCT_NONE,       true  },
    { 0xC0, "CriticalSectionTimeout",            IREM_STRUCT_NONE,       false },
    { 0xC8, "HeapSegmentReserve",                IREM_STRUCT_NONE,       false },
    { 0xD0, "HeapSegmentCommit",                 IREM_STRUCT_NONE,       false },
    { 0xD8, "HeapDeCommitTotalFreeThreshold",    IREM_STRUCT_NONE,       false },
    { 0xE0, "HeapDeCommitFreeBlockThreshold",    IREM_STRUCT_NONE,       false },
    { 0xE8, "NumberOfHeaps",                     IREM_STRUCT_NONE,       false },
    { 0xEC, "MaximumNumberOfHeaps",              IREM_STRUCT_NONE,       false },
    { 0xF0, "ProcessHeaps",                      IREM_STRUCT_NONE,       false },
    { -1, NULL, IREM_STRUCT_NONE, false }
};

/* PEB_LDR_DATA field definitions */
static const StructFieldEntry LDR_FIELDS[] = {
    { 0x00, "Length",                            IREM_STRUCT_NONE,       false },
    { 0x04, "Initialized",                       IREM_STRUCT_NONE,       false },
    { 0x08, "SsHandle",                          IREM_STRUCT_NONE,       false },
    { 0x10, "InLoadOrderModuleList",             IREM_STRUCT_LDR_ENTRY,  false },
    { 0x20, "InMemoryOrderModuleList",           IREM_STRUCT_LDR_ENTRY,  false },
    { 0x30, "InInitializationOrderModuleList",   IREM_STRUCT_LDR_ENTRY,  false },
    { 0x40, "EntryInProgress",                   IREM_STRUCT_NONE,       false },
    { 0x48, "ShutdownInProgress",                IREM_STRUCT_NONE,       false },
    { 0x50, "ShutdownThreadId",                  IREM_STRUCT_NONE,       false },
    { -1, NULL, IREM_STRUCT_NONE, false }
};

/* LDR_DATA_TABLE_ENTRY field definitions */
static const StructFieldEntry LDR_ENTRY_FIELDS[] = {
    { 0x00, "InLoadOrderLinks.Flink",            IREM_STRUCT_LDR_ENTRY,  false },
    { 0x08, "InLoadOrderLinks.Blink",            IREM_STRUCT_LDR_ENTRY,  false },
    { 0x10, "InMemoryOrderLinks.Flink",          IREM_STRUCT_LDR_ENTRY,  false },
    { 0x18, "InMemoryOrderLinks.Blink",          IREM_STRUCT_LDR_ENTRY,  false },
    { 0x20, "InInitOrderLinks.Flink",            IREM_STRUCT_LDR_ENTRY,  false },
    { 0x28, "InInitOrderLinks.Blink",            IREM_STRUCT_LDR_ENTRY,  false },
    { 0x30, "DllBase",                           IREM_STRUCT_NONE,       false },
    { 0x38, "EntryPoint",                        IREM_STRUCT_NONE,       false },
    { 0x40, "SizeOfImage",                       IREM_STRUCT_NONE,       false },
    { 0x48, "FullDllName (UNICODE_STRING)",      IREM_STRUCT_NONE,       false },
    { 0x58, "BaseDllName (UNICODE_STRING)",      IREM_STRUCT_NONE,       false },
    { 0x68, "Flags",                             IREM_STRUCT_NONE,       false },
    { 0x6C, "ObsoleteLoadCount",                 IREM_STRUCT_NONE,       false },
    { 0x6E, "TlsIndex",                          IREM_STRUCT_NONE,       false },
    { -1, NULL, IREM_STRUCT_NONE, false }
};

/* ========================================================================= */
/* RTL_USER_PROCESS_PARAMETERS Table                                         */
/* ========================================================================= */
static const StructFieldEntry RTL_PARAMS_FIELDS[] = {
    { 0x00, "MaximumLength",                     IREM_STRUCT_NONE,       false },
    { 0x04, "Length",                            IREM_STRUCT_NONE,       false },
    { 0x08, "Flags",                             IREM_STRUCT_NONE,       false },
    { 0x10, "ConsoleHandle",                     IREM_STRUCT_NONE,       false },
    { 0x18, "ConsoleFlags",                      IREM_STRUCT_NONE,       false },
    { 0x20, "StandardInput",                     IREM_STRUCT_NONE,       false },
    { 0x28, "StandardOutput",                    IREM_STRUCT_NONE,       false },
    { 0x30, "StandardError",                     IREM_STRUCT_NONE,       false },
    { 0x38, "CurrentDirectory.DosPath",          IREM_STRUCT_NONE,       false },
    { 0x50, "DllPath (UNICODE_STRING)",          IREM_STRUCT_NONE,       false },
    { 0x60, "ImagePathName (UNICODE_STRING)",    IREM_STRUCT_NONE,       false },
    { 0x70, "CommandLine (UNICODE_STRING)",      IREM_STRUCT_NONE,       false },
    { 0x80, "Environment",                       IREM_STRUCT_NONE,       false },
    { -1, NULL, IREM_STRUCT_NONE, false }
};

/* ========================================================================= */
/* KPCR & KPRCB (Kernel-mode, gs:[offset]) Table                             */
/* ========================================================================= */
static const StructFieldEntry KPCR_FIELDS[] = {
    { 0x00,  "NtTib.ExceptionList",              IREM_STRUCT_NONE,       false },
    { 0x08,  "NtTib.StackBase",                  IREM_STRUCT_NONE,       false },
    { 0x10,  "NtTib.StackLimit",                 IREM_STRUCT_NONE,       false },
    { 0x18,  "Self (PKPCR)",                     IREM_STRUCT_KPCR,       false },
    { 0x20,  "CurrentPrcb (PKPRCB)",             IREM_STRUCT_KPRCB,      false },
    { 0x28,  "LockArray",                        IREM_STRUCT_NONE,       false },
    { 0x38,  "IdtBase",                          IREM_STRUCT_NONE,       false },
    { 0x40,  "GdtBase",                          IREM_STRUCT_NONE,       false },
    { 0x48,  "TssBase",                          IREM_STRUCT_NONE,       false },
    { 0x180, "Prcb (Embedded KPRCB)",            IREM_STRUCT_KPRCB,      false },
    { 0x188, "Prcb.CurrentThread (PKTHREAD)",    IREM_STRUCT_KTHREAD,    false },
    { 0x190, "Prcb.NextThread (PKTHREAD)",       IREM_STRUCT_KTHREAD,    false },
    { 0x198, "Prcb.IdleThread (PKTHREAD)",       IREM_STRUCT_KTHREAD,    false },
    { 0x1A0, "Prcb.Number (Core Index)",         IREM_STRUCT_NONE,       false },
    { 0x1A8, "Prcb.RspBase",                     IREM_STRUCT_NONE,       false },
    { 0x1B0, "Prcb.PrcbLock",                    IREM_STRUCT_NONE,       false },
    { -1, NULL, IREM_STRUCT_NONE, false }
};

/* ========================================================================= */
/* KTHREAD Table                                                             */
/* ========================================================================= */
static const StructFieldEntry KTHREAD_FIELDS[] = {
    { 0x28,  "InitialStack",                     IREM_STRUCT_NONE,       false },
    { 0x30,  "StackLimit",                       IREM_STRUCT_NONE,       false },
    { 0x38,  "KernelStack",                      IREM_STRUCT_NONE,       false },
    { 0x78,  "State",                            IREM_STRUCT_NONE,       false },
    { 0xB8,  "ApcState.ApcListHead",             IREM_STRUCT_NONE,       false },
    { 0xD8,  "ApcState.Process (EPROCESS*)",     IREM_STRUCT_EPROCESS,   false },
    { 0xE8,  "ContextSwitches",                  IREM_STRUCT_NONE,       false },
    { 0x220, "Teb (PTEB)",                       IREM_STRUCT_TEB,        false },
    { 0x238, "PreviousMode",                     IREM_STRUCT_NONE,       false },
    { -1, NULL, IREM_STRUCT_NONE, false }
};

/* ========================================================================= */
/* EPROCESS Table                                                            */
/* ========================================================================= */
static const StructFieldEntry EPROCESS_FIELDS[] = {
    { 0x2E0, "DirectoryTableBase (CR3)",         IREM_STRUCT_NONE,       false },
    { 0x3B8, "Token (EX_FAST_REF)",              IREM_STRUCT_NONE,       false },
    { 0x440, "UniqueProcessId (PID)",            IREM_STRUCT_NONE,       false },
    { 0x448, "ActiveProcessLinks (LIST_ENTRY)",  IREM_STRUCT_NONE,       false },
    { 0x5A0, "ImageFileName (15 chars)",         IREM_STRUCT_NONE,       false },
    { 0x5A8, "ThreadListHead",                   IREM_STRUCT_NONE,       false },
    { 0x5E8, "Peb (PPEB)",                       IREM_STRUCT_PEB,        false },
    { -1, NULL, IREM_STRUCT_NONE, false }
};

static const StructFieldEntry* lookup_field(const StructFieldEntry* table, int64_t offset) {
    for (int i = 0; table[i].field_name != NULL; ++i) {
        if (table[i].offset == offset) {
            return &table[i];
        }
    }
    return NULL;
}

const char* irem_struct_resolve_teb_offset(int64_t offset, IremStructType* out_target_type, bool* out_is_anti_debug) {
    const StructFieldEntry* e = lookup_field(TEB_FIELDS, offset);
    if (e) {
        if (out_target_type) *out_target_type = e->target_type;
        if (out_is_anti_debug) *out_is_anti_debug = e->is_anti_debug;
        return e->field_name;
    }
    return NULL;
}

const char* irem_struct_resolve_peb_offset(int64_t offset, IremStructType* out_target_type, bool* out_is_anti_debug) {
    const StructFieldEntry* e = lookup_field(PEB_FIELDS, offset);
    if (e) {
        if (out_target_type) *out_target_type = e->target_type;
        if (out_is_anti_debug) *out_is_anti_debug = e->is_anti_debug;
        return e->field_name;
    }
    return NULL;
}

const char* irem_struct_resolve_ldr_offset(int64_t offset, IremStructType* out_target_type) {
    const StructFieldEntry* e = lookup_field(LDR_FIELDS, offset);
    if (e) {
        if (out_target_type) *out_target_type = e->target_type;
        return e->field_name;
    }
    return NULL;
}

const char* irem_struct_resolve_ldr_entry_offset(int64_t offset, IremStructType* out_target_type) {
    const StructFieldEntry* e = lookup_field(LDR_ENTRY_FIELDS, offset);
    if (e) {
        if (out_target_type) *out_target_type = e->target_type;
        return e->field_name;
    }
    return NULL;
}

const char* irem_struct_resolve_rtl_params_offset(int64_t offset, IremStructType* out_target_type) {
    const StructFieldEntry* e = lookup_field(RTL_PARAMS_FIELDS, offset);
    if (e) {
        if (out_target_type) *out_target_type = e->target_type;
        return e->field_name;
    }
    return NULL;
}

const char* irem_struct_resolve_kpcr_offset(int64_t offset, IremStructType* out_target_type) {
    const StructFieldEntry* e = lookup_field(KPCR_FIELDS, offset);
    if (e) {
        if (out_target_type) *out_target_type = e->target_type;
        return e->field_name;
    }
    return NULL;
}

const char* irem_struct_resolve_kthread_offset(int64_t offset, IremStructType* out_target_type) {
    const StructFieldEntry* e = lookup_field(KTHREAD_FIELDS, offset);
    if (e) {
        if (out_target_type) *out_target_type = e->target_type;
        return e->field_name;
    }
    return NULL;
}

const char* irem_struct_resolve_eprocess_offset(int64_t offset, IremStructType* out_target_type) {
    const StructFieldEntry* e = lookup_field(EPROCESS_FIELDS, offset);
    if (e) {
        if (out_target_type) *out_target_type = e->target_type;
        return e->field_name;
    }
    return NULL;
}

void irem_struct_db_init(IremStructAnnotationDB* db) {
    if (!db) return;
    db->annotations = NULL;
    db->count = 0;
    db->capacity = 0;
}

void irem_struct_db_free(IremStructAnnotationDB* db) {
    if (!db) return;
    if (db->annotations) {
        free(db->annotations);
        db->annotations = NULL;
    }
    db->count = 0;
    db->capacity = 0;
}

static bool db_push(IremStructAnnotationDB* db, const IremStructAnnotation* ann) {
    if (db->count >= db->capacity) {
        int new_cap = db->capacity == 0 ? 64 : db->capacity * 2;
        IremStructAnnotation* new_buf = (IremStructAnnotation*)realloc(db->annotations, new_cap * sizeof(IremStructAnnotation));
        if (!new_buf) return false;
        db->annotations = new_buf;
        db->capacity = new_cap;
    }
    db->annotations[db->count++] = *ann;
    return true;
}

/* ========================================================================= */
/* Main Resolution Engine (Chained Dataflow within Basic Blocks)             */
/* ========================================================================= */
bool irem_resolve_struct_accesses(
    const IremFlatInstruction* instructions,
    size_t                     count,
    bool                       is_kernel_driver,
    IremStructAnnotationDB*    out_db
) {
    if (!instructions || count == 0 || !out_db) return false;

    /* Register State Tracker for canonical 64-bit registers (RAX..R15) */
    typedef struct {
        IremStructType type;
        char           chain_prefix[96];
        int            depth;
    } RegState;

    RegState reg_state[IREM_REG_MAX];
    memset(reg_state, 0, sizeof(reg_state));

    for (size_t i = 0; i < count; ++i) {
        const IremFlatInstruction* ins = &instructions[i];

        /* Reset register state across control flow boundaries */
        if (ins->is_jump || ins->is_conditional_jump || ins->is_ret) {
            memset(reg_state, 0, sizeof(reg_state));
            continue;
        }

        /* Check for GS-segment memory access: gs:[offset] or gs:[reg + offset] */
        for (uint8_t op_idx = 0; op_idx < ins->op_count; ++op_idx) {
            const IremFlatOperand* op = &ins->ops[op_idx];
            if (op->type == IREM_OP_MEM && op->mem.segment_override == IREM_SEG_GS) {
                int64_t disp = op->mem.disp;
                IremStructType target_type = IREM_STRUCT_NONE;
                bool is_anti_debug = false;
                const char* field = NULL;
                const char* sname = is_kernel_driver ? "KPCR" : "TEB";

                if (is_kernel_driver) {
                    field = irem_struct_resolve_kpcr_offset(disp, &target_type);
                } else {
                    field = irem_struct_resolve_teb_offset(disp, &target_type, &is_anti_debug);
                }

                if (field) {
                    IremStructAnnotation ann;
                    memset(&ann, 0, sizeof(ann));
                    ann.insn_index = i;
                    ann.va = ins->va;
                    ann.struct_type = is_kernel_driver ? IREM_STRUCT_KPCR : IREM_STRUCT_TEB;
                    ann.offset = disp;
                    strncpy_s(ann.struct_name, sizeof(ann.struct_name), sname, sizeof(ann.struct_name) - 1);
                    strncpy_s(ann.field_name, sizeof(ann.field_name), field, sizeof(ann.field_name) - 1);
                    ann.depth = 1;
                    ann.is_kernel_mode = is_kernel_driver;
                    ann.is_anti_debug = is_anti_debug;

                    if (is_anti_debug) {
                        snprintf(ann.annotation, sizeof(ann.annotation), "%s->%s [ANTI-DEBUG]", sname, field);
                    } else {
                        snprintf(ann.annotation, sizeof(ann.annotation), "%s->%s", sname, field);
                    }

                    db_push(out_db, &ann);

                    /* If destination register is tracked (e.g. mov reg, gs:[disp]), record target type */
                    if (ins->op_count >= 2 && ins->ops[0].type == IREM_OP_REG && op_idx == 1) {
                        IremReg canon = irem_get_canonical_64(ins->ops[0].reg);
                        if (canon != IREM_REG_NONE && canon < IREM_REG_MAX) {
                            reg_state[canon].type = target_type;
                            snprintf(reg_state[canon].chain_prefix, sizeof(reg_state[canon].chain_prefix), "%s", field);
                            reg_state[canon].depth = 1;
                        }
                    }
                }
                continue;
            }

            /* Chained dereference: [base_reg + offset] where base_reg holds a known struct pointer */
            if (op->type == IREM_OP_MEM && op->mem.segment_override == IREM_SEG_NONE && op->mem.base != IREM_REG_NONE) {
                IremReg canon_base = irem_get_canonical_64(op->mem.base);
                if (canon_base != IREM_REG_NONE && canon_base < IREM_REG_MAX && reg_state[canon_base].type != IREM_STRUCT_NONE) {
                    IremStructType cur_type = reg_state[canon_base].type;
                    int64_t disp = op->mem.disp;
                    IremStructType target_type = IREM_STRUCT_NONE;
                    bool is_anti_debug = false;
                    const char* field = NULL;
                    const char* sname = "";

                    switch (cur_type) {
                    case IREM_STRUCT_PEB:
                        sname = "PEB";
                        field = irem_struct_resolve_peb_offset(disp, &target_type, &is_anti_debug);
                        break;
                    case IREM_STRUCT_PEB_LDR:
                        sname = "PEB_LDR_DATA";
                        field = irem_struct_resolve_ldr_offset(disp, &target_type);
                        break;
                    case IREM_STRUCT_LDR_ENTRY:
                        sname = "LDR_ENTRY";
                        field = irem_struct_resolve_ldr_entry_offset(disp, &target_type);
                        break;
                    case IREM_STRUCT_RTL_PARAMS:
                        sname = "ProcessParameters";
                        field = irem_struct_resolve_rtl_params_offset(disp, &target_type);
                        break;
                    case IREM_STRUCT_KTHREAD:
                        sname = "KTHREAD";
                        field = irem_struct_resolve_kthread_offset(disp, &target_type);
                        break;
                    case IREM_STRUCT_EPROCESS:
                        sname = "EPROCESS";
                        field = irem_struct_resolve_eprocess_offset(disp, &target_type);
                        break;
                    default:
                        break;
                    }

                    if (field) {
                        IremStructAnnotation ann;
                        memset(&ann, 0, sizeof(ann));
                        ann.insn_index = i;
                        ann.va = ins->va;
                        ann.struct_type = cur_type;
                        ann.offset = disp;
                        strncpy_s(ann.struct_name, sizeof(ann.struct_name), sname, sizeof(ann.struct_name) - 1);
                        strncpy_s(ann.field_name, sizeof(ann.field_name), field, sizeof(ann.field_name) - 1);
                        ann.depth = reg_state[canon_base].depth + 1;
                        ann.is_kernel_mode = is_kernel_driver;
                        ann.is_anti_debug = is_anti_debug;

                        if (is_anti_debug) {
                            snprintf(ann.annotation, sizeof(ann.annotation), "%s->%s [ANTI-DEBUG]", sname, field);
                        } else {
                            snprintf(ann.annotation, sizeof(ann.annotation), "%s->%s", sname, field);
                        }

                        db_push(out_db, &ann);

                        /* Propagate forward if destination is a register */
                        if (ins->op_count >= 2 && ins->ops[0].type == IREM_OP_REG && op_idx == 1) {
                            IremReg dst_canon = irem_get_canonical_64(ins->ops[0].reg);
                            if (dst_canon != IREM_REG_NONE && dst_canon < IREM_REG_MAX) {
                                reg_state[dst_canon].type = target_type;
                                snprintf(reg_state[dst_canon].chain_prefix, sizeof(reg_state[dst_canon].chain_prefix), "%s", field);
                                reg_state[dst_canon].depth = ann.depth;
                            }
                        }
                    }
                }
            }
        }

        /* If an instruction clobbers destination register without reading struct, clear it */
        if (ins->op_count >= 1 && ins->ops[0].type == IREM_OP_REG) {
            bool has_struct_read = false;
            for (uint8_t op_idx = 1; op_idx < ins->op_count; ++op_idx) {
                const IremFlatOperand* op = &ins->ops[op_idx];
                if (op->type == IREM_OP_MEM && (op->mem.segment_override == IREM_SEG_GS ||
                    (op->mem.base != IREM_REG_NONE && reg_state[irem_get_canonical_64(op->mem.base)].type != IREM_STRUCT_NONE))) {
                    has_struct_read = true;
                    break;
                }
            }
            if (!has_struct_read && strcmp(ins->mnemonic, "mov") == 0) {
                IremReg dst_canon = irem_get_canonical_64(ins->ops[0].reg);
                if (dst_canon != IREM_REG_NONE && dst_canon < IREM_REG_MAX) {
                    /* If it's a register copy `mov rbx, rax` where rax has struct */
                    if (ins->op_count >= 2 && ins->ops[1].type == IREM_OP_REG) {
                        IremReg src_canon = irem_get_canonical_64(ins->ops[1].reg);
                        if (src_canon != IREM_REG_NONE && src_canon < IREM_REG_MAX && reg_state[src_canon].type != IREM_STRUCT_NONE) {
                            reg_state[dst_canon] = reg_state[src_canon];
                        } else {
                            reg_state[dst_canon].type = IREM_STRUCT_NONE;
                        }
                    } else {
                        reg_state[dst_canon].type = IREM_STRUCT_NONE;
                    }
                }
            } else if (!has_struct_read && (strcmp(ins->mnemonic, "xor") == 0 || strcmp(ins->mnemonic, "add") == 0 ||
                       strcmp(ins->mnemonic, "sub") == 0 || strcmp(ins->mnemonic, "lea") == 0)) {
                IremReg dst_canon = irem_get_canonical_64(ins->ops[0].reg);
                if (dst_canon != IREM_REG_NONE && dst_canon < IREM_REG_MAX) {
                    reg_state[dst_canon].type = IREM_STRUCT_NONE;
                }
            }
        }

        /* Calls invalidate caller-saved scratch registers (RAX, RCX, RDX, R8, R9, R10, R11) */
        if (ins->is_call) {
            reg_state[IREM_REG_RAX].type = IREM_STRUCT_NONE;
            reg_state[IREM_REG_RCX].type = IREM_STRUCT_NONE;
            reg_state[IREM_REG_RDX].type = IREM_STRUCT_NONE;
            reg_state[IREM_REG_R8].type  = IREM_STRUCT_NONE;
            reg_state[IREM_REG_R9].type  = IREM_STRUCT_NONE;
            reg_state[IREM_REG_R10].type = IREM_STRUCT_NONE;
            reg_state[IREM_REG_R11].type = IREM_STRUCT_NONE;
        }
    }

    return true;
}
