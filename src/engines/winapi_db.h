#ifndef IREM_WINAPI_DB_H
#define IREM_WINAPI_DB_H

#include "irem_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char* name;
    uint64_t    value;
} IremApiEnumValue;

typedef struct {
    const char*             param_name;
    int                     param_slot; /* 0=RCX, 1=RDX, 2=R8, 3=R9 */
    bool                    is_bitmask;
    int                     value_count;
    const IremApiEnumValue* values;
} IremApiParamHint;

typedef struct {
    const char*             api_name;
    const char*             dll_name;
    int                     param_count;
    const IremApiParamHint* params;
    const char*             category;
    int                     risk_level; /* 0=Normal, 1=Notable, 2=Suspicious, 3=Critical */
} IremApiDef;

typedef struct {
    char        resolved_str[256];
    const char* param_name;
    const char* category;
    int         risk_level;
} IremResolvedFlag;

/* Lookup API definition by name (case-insensitive) */
const IremApiDef* irem_winapi_find(const char* api_name);

/* Resolve a parameter value into flag names or enum string */
bool irem_winapi_resolve_param(
    const char* api_name,
    int param_slot,
    uint64_t param_val,
    IremResolvedFlag* out_resolved
);

#ifdef __cplusplus
}
#endif

#endif /* IREM_WINAPI_DB_H */

