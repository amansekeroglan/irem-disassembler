#include "winapi_db.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* Case-insensitive string comparison helper */
static int irem_stricmp(const char* a, const char* b) {
    if (!a || !b) return (a == b) ? 0 : (a ? 1 : -1);
    while (*a && *b) {
        int diff = tolower((unsigned char)*a) - tolower((unsigned char)*b);
        if (diff != 0) return diff;
        a++;
        b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

static const IremApiEnumValue g_page_protect_values[] = {
    { "PAGE_NOACCESS",          0x01 },
    { "PAGE_READONLY",          0x02 },
    { "PAGE_READWRITE",         0x04 },
    { "PAGE_WRITECOPY",         0x08 },
    { "PAGE_EXECUTE",           0x10 },
    { "PAGE_EXECUTE_READ",      0x20 },
    { "PAGE_EXECUTE_READWRITE", 0x40 },
    { "PAGE_EXECUTE_WRITECOPY", 0x80 },
    { "PAGE_GUARD",             0x100 },
    { "PAGE_NOCACHE",           0x200 },
    { "PAGE_WRITECOMBINE",      0x400 }
};

static const IremApiEnumValue g_mem_alloc_values[] = {
    { "MEM_COMMIT",      0x00001000 },
    { "MEM_RESERVE",     0x00002000 },
    { "MEM_DECOMMIT",    0x00004000 },
    { "MEM_RELEASE",     0x00008000 },
    { "MEM_FREE",        0x00010000 },
    { "MEM_PRIVATE",     0x00020000 },
    { "MEM_MAPPED",      0x00040000 },
    { "MEM_RESET",       0x00080000 },
    { "MEM_TOP_DOWN",    0x00100000 },
    { "MEM_LARGE_PAGES", 0x20000000 }
};

static const IremApiEnumValue g_process_access_values[] = {
    { "PROCESS_TERMINATE",         0x0001 },
    { "PROCESS_CREATE_THREAD",     0x0002 },
    { "PROCESS_SET_SESSIONID",     0x0004 },
    { "PROCESS_VM_OPERATION",      0x0008 },
    { "PROCESS_VM_READ",           0x0010 },
    { "PROCESS_VM_WRITE",          0x0020 },
    { "PROCESS_DUP_HANDLE",        0x0040 },
    { "PROCESS_CREATE_PROCESS",    0x0080 },
    { "PROCESS_SET_QUOTA",         0x0100 },
    { "PROCESS_SET_INFORMATION",   0x0200 },
    { "PROCESS_QUERY_INFORMATION", 0x0400 },
    { "PROCESS_SUSPEND_RESUME",    0x0800 },
    { "PROCESS_ALL_ACCESS",        0x001F0FFF }
};

static const IremApiEnumValue g_file_access_values[] = {
    { "GENERIC_READ",    0x80000000ULL },
    { "GENERIC_WRITE",   0x40000000ULL },
    { "GENERIC_EXECUTE", 0x20000000ULL },
    { "GENERIC_ALL",     0x10000000ULL },
    { "FILE_READ_DATA",  0x0001 },
    { "FILE_WRITE_DATA", 0x0002 },
    { "FILE_APPEND_DATA",0x0004 },
    { "DELETE",          0x00010000ULL }
};

static const IremApiEnumValue g_file_share_values[] = {
    { "FILE_SHARE_READ",   0x00000001 },
    { "FILE_SHARE_WRITE",  0x00000002 },
    { "FILE_SHARE_DELETE", 0x00000004 }
};

static const IremApiEnumValue g_creation_disposition_values[] = {
    { "CREATE_NEW",        1 },
    { "CREATE_ALWAYS",     2 },
    { "OPEN_EXISTING",     3 },
    { "OPEN_ALWAYS",       4 },
    { "TRUNCATE_EXISTING", 5 }
};

static const IremApiEnumValue g_reg_root_values[] = {
    { "HKEY_CLASSES_ROOT",     0x80000000ULL },
    { "HKEY_CURRENT_USER",     0x80000001ULL },
    { "HKEY_LOCAL_MACHINE",    0x80000002ULL },
    { "HKEY_USERS",            0x80000003ULL },
    { "HKEY_CURRENT_CONFIG",   0x80000005ULL }
};

static const IremApiEnumValue g_hook_type_values[] = {
    { "WH_MSGFILTER",       (uint64_t)(int64_t)-1 },
    { "WH_JOURNALRECORD",    0 },
    { "WH_JOURNALPLAYBACK",  1 },
    { "WH_KEYBOARD",         2 },
    { "WH_GETMESSAGE",       3 },
    { "WH_CALLWNDPROC",      4 },
    { "WH_CBT",              5 },
    { "WH_SYSMSGFILTER",     6 },
    { "WH_MOUSE",            7 },
    { "WH_DEBUG",            9 },
    { "WH_SHELL",           10 },
    { "WH_KEYBOARD_LL",     13 },
    { "WH_MOUSE_LL",        14 }
};

/* API Definitions */

static const IremApiParamHint g_virtualalloc_params[] = {
    { "flAllocationType", 2, true,  10, g_mem_alloc_values },
    { "flProtect",        3, false, 11, g_page_protect_values }
};

static const IremApiParamHint g_virtualprotect_params[] = {
    { "flNewProtect",     2, false, 11, g_page_protect_values }
};

static const IremApiParamHint g_virtualfree_params[] = {
    { "dwFreeType",       2, true,  10, g_mem_alloc_values }
};

static const IremApiParamHint g_openprocess_params[] = {
    { "dwDesiredAccess",  0, true,  13, g_process_access_values }
};

static const IremApiParamHint g_createfile_params[] = {
    { "dwDesiredAccess",       1, true,   8, g_file_access_values },
    { "dwShareMode",           2, true,   3, g_file_share_values },
    { "dwCreationDisposition", 4, false,  5, g_creation_disposition_values }
};

static const IremApiParamHint g_regopen_params[] = {
    { "hKey",             0, false,  5, g_reg_root_values }
};

static const IremApiParamHint g_sethook_params[] = {
    { "idHook",           0, false, 13, g_hook_type_values }
};

static const IremApiDef g_api_catalog[] = {
    { "VirtualAlloc",       "KERNEL32.dll", 2, g_virtualalloc_params,  "Memory",   1 },
    { "VirtualAllocEx",     "KERNEL32.dll", 2, g_virtualalloc_params,  "Memory",   2 },
    { "VirtualProtect",     "KERNEL32.dll", 1, g_virtualprotect_params,"Memory",   1 },
    { "VirtualProtectEx",   "KERNEL32.dll", 1, g_virtualprotect_params,"Memory",   2 },
    { "VirtualFree",        "KERNEL32.dll", 1, g_virtualfree_params,   "Memory",   0 },
    { "OpenProcess",        "KERNEL32.dll", 1, g_openprocess_params,   "Process",  1 },
    { "CreateFileW",        "KERNEL32.dll", 3, g_createfile_params,    "File",     0 },
    { "CreateFileA",        "KERNEL32.dll", 3, g_createfile_params,    "File",     0 },
    { "RegOpenKeyExW",      "ADVAPI32.dll", 1, g_regopen_params,       "Registry", 0 },
    { "RegOpenKeyExA",      "ADVAPI32.dll", 1, g_regopen_params,       "Registry", 0 },
    { "SetWindowsHookExW",  "USER32.dll",   1, g_sethook_params,       "Hook",     3 },
    { "SetWindowsHookExA",  "USER32.dll",   1, g_sethook_params,       "Hook",     3 },
    { "WriteProcessMemory", "KERNEL32.dll", 0, NULL,                   "Memory",   2 },
    { "ReadProcessMemory",  "KERNEL32.dll", 0, NULL,                   "Memory",   1 },
    { "CreateRemoteThread", "KERNEL32.dll", 0, NULL,                   "Thread",   3 },
    { "NtCreateThreadEx",   "NTDLL.dll",    0, NULL,                   "Thread",   3 },
    { "IsDebuggerPresent",  "KERNEL32.dll", 0, NULL,                   "Debug",    1 },
    { "CheckRemoteDebuggerPresent","KERNEL32.dll",0, NULL,             "Debug",    1 }
};

static const size_t g_api_catalog_count = sizeof(g_api_catalog) / sizeof(g_api_catalog[0]);

const IremApiDef* irem_winapi_find(const char* api_name) {
    if (!api_name || !*api_name) return NULL;

    for (size_t i = 0; i < g_api_catalog_count; ++i) {
        if (irem_stricmp(g_api_catalog[i].api_name, api_name) == 0) {
            return &g_api_catalog[i];
        }
    }
    return NULL;
}

bool irem_winapi_resolve_param(
    const char* api_name,
    int param_slot,
    uint64_t param_val,
    IremResolvedFlag* out_resolved
) {
    if (!api_name || !out_resolved) return false;

    memset(out_resolved, 0, sizeof(IremResolvedFlag));
    const IremApiDef* api = irem_winapi_find(api_name);
    if (!api) return false;

    out_resolved->category = api->category;
    out_resolved->risk_level = api->risk_level;

    /* Find matching parameter hint */
    const IremApiParamHint* hint = NULL;
    for (int p = 0; p < api->param_count; ++p) {
        if (api->params[p].param_slot == param_slot) {
            hint = &api->params[p];
            break;
        }
    }

    if (!hint) return false;
    out_resolved->param_name = hint->param_name;

    if (!hint->is_bitmask) {
        /* Exact enum match */
        for (int v = 0; v < hint->value_count; ++v) {
            if (hint->values[v].value == param_val) {
                strncpy_s(out_resolved->resolved_str, sizeof(out_resolved->resolved_str),
                          hint->values[v].name, sizeof(out_resolved->resolved_str) - 1);

                /* Special risk escalation: PAGE_EXECUTE_READWRITE is High Risk */
                if (param_val == 0x40 && strcmp(hint->values[v].name, "PAGE_EXECUTE_READWRITE") == 0) {
                    out_resolved->risk_level = 3;
                }
                return true;
            }
        }
    } else {
        /* Bitmask flags matching (OR combination) */
        char buffer[256] = { 0 };
        size_t buf_len = 0;
        uint64_t remaining = param_val;

        for (int v = 0; v < hint->value_count; ++v) {
            uint64_t flag_val = hint->values[v].value;
            if ((param_val & flag_val) == flag_val && flag_val != 0) {
                if (buf_len > 0 && buf_len + 3 < sizeof(buffer)) {
                    strcat_s(buffer, sizeof(buffer), " | ");
                    buf_len += 3;
                }
                strcat_s(buffer, sizeof(buffer), hint->values[v].name);
                buf_len = strlen(buffer);
                remaining &= ~flag_val;
            }
        }

        if (buf_len > 0) {
            strncpy_s(out_resolved->resolved_str, sizeof(out_resolved->resolved_str), buffer, sizeof(out_resolved->resolved_str) - 1);
            return true;
        }
    }

    return false;
}
