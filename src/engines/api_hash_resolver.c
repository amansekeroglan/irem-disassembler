#include "api_hash_resolver.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>


uint32_t irem_calc_ror13(const char* str) {
    if (!str) return 0;
    uint32_t h = 0;
    while (*str) {
        h = (h >> 13) | (h << 19);
        h += (uint8_t)(*str);
        str++;
    }
    return h;
}

uint32_t irem_calc_ror13_dll(const char* dll_name, const char* api_name) {
    if (!dll_name || !api_name) return 0;
    /* Metasploit / Cobalt Strike style: ROR13 uppercase unicode or ascii dll + ROR13 api */
    uint32_t h_dll = 0;
    const char* d = dll_name;
    while (*d) {
        h_dll = (h_dll >> 13) | (h_dll << 19);
        char c = (char)toupper((unsigned char)*d);
        h_dll += (uint8_t)c;
        d++;
    }
    uint32_t h_api = irem_calc_ror13(api_name);
    return h_dll + h_api;
}

uint32_t irem_calc_djb2(const char* str) {
    if (!str) return 0;
    uint32_t h = 5381;
    while (*str) {
        h = ((h << 5) + h) + (uint8_t)(*str);
        str++;
    }
    return h;
}

uint32_t irem_calc_fnv1a(const char* str) {
    if (!str) return 0;
    uint32_t h = 2166136261u;
    while (*str) {
        h ^= (uint8_t)(*str);
        h *= 16777619u;
        str++;
    }
    return h;
}

static uint32_t crc32_tab[256];
static bool crc32_tab_inited = false;

static void init_crc32_tab(void) {
    if (crc32_tab_inited) return;
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int j = 0; j < 8; ++j) {
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        crc32_tab[i] = c;
    }
    crc32_tab_inited = true;
}

uint32_t irem_calc_crc32(const char* str) {
    if (!str) return 0;
    init_crc32_tab();
    uint32_t c = 0xFFFFFFFFu;
    while (*str) {
        c = crc32_tab[(c ^ (uint8_t)(*str)) & 0xFF] ^ (c >> 8);
        str++;
    }
    return c ^ 0xFFFFFFFFu;
}

uint32_t irem_calc_additive(const char* str) {
    if (!str) return 0;
    uint32_t h = 0;
    while (*str) {
        h += (uint8_t)(*str);
        str++;
    }
    return h;
}


typedef struct {
    const char* dll_name;
    const char* api_name;
    int         risk_level; /* 0=Benign, 1=Info, 2=Suspicious, 3=Critical */
} KnownApiDef;

static const KnownApiDef KNOWN_APIS[] = {
    /* Memory allocation & protection (Injection / Shellcode) */
    { "kernel32.dll", "VirtualAlloc",               2 },
    { "kernel32.dll", "VirtualAllocEx",             3 },
    { "kernel32.dll", "VirtualProtect",             2 },
    { "kernel32.dll", "VirtualProtectEx",           3 },
    { "kernel32.dll", "VirtualFree",                1 },
    { "kernel32.dll", "VirtualFreeEx",              2 },
    { "kernel32.dll", "HeapCreate",                 1 },
    { "kernel32.dll", "HeapAlloc",                  1 },
    { "kernel32.dll", "GlobalAlloc",                1 },
    { "kernel32.dll", "LocalAlloc",                 1 },

    /* Process & Thread Execution (Code Execution) */
    { "kernel32.dll", "CreateProcessA",             2 },
    { "kernel32.dll", "CreateProcessW",             2 },
    { "kernel32.dll", "CreateRemoteThread",         3 },
    { "kernel32.dll", "CreateRemoteThreadEx",       3 },
    { "kernel32.dll", "CreateThread",               1 },
    { "kernel32.dll", "OpenProcess",                2 },
    { "kernel32.dll", "OpenThread",                 2 },
    { "kernel32.dll", "TerminateProcess",           2 },
    { "kernel32.dll", "ExitProcess",                0 },
    { "kernel32.dll", "QueueUserAPC",               3 },
    { "kernel32.dll", "SetThreadContext",           3 },
    { "kernel32.dll", "GetThreadContext",           2 },
    { "kernel32.dll", "ResumeThread",               2 },
    { "kernel32.dll", "SuspendThread",              2 },
    { "kernel32.dll", "WriteProcessMemory",         3 },
    { "kernel32.dll", "ReadProcessMemory",          2 },

    /* Dynamic Loading */
    { "kernel32.dll", "LoadLibraryA",               2 },
    { "kernel32.dll", "LoadLibraryW",               2 },
    { "kernel32.dll", "LoadLibraryExA",             2 },
    { "kernel32.dll", "LoadLibraryExW",             2 },
    { "kernel32.dll", "GetProcAddress",             2 },
    { "kernel32.dll", "GetModuleHandleA",           1 },
    { "kernel32.dll", "GetModuleHandleW",           1 },
    { "kernel32.dll", "GetModuleHandleExA",         1 },
    { "kernel32.dll", "GetModuleHandleExW",         1 },
    { "kernel32.dll", "FreeLibrary",                1 },

    /* Anti-Debugging & Evasion */
    { "kernel32.dll", "IsDebuggerPresent",          2 },
    { "kernel32.dll", "CheckRemoteDebuggerPresent", 2 },
    { "kernel32.dll", "SetUnhandledExceptionFilter",2 },
    { "kernel32.dll", "OutputDebugStringA",         1 },
    { "kernel32.dll", "OutputDebugStringW",         1 },
    { "kernel32.dll", "Sleep",                      0 },
    { "kernel32.dll", "SleepEx",                    1 },
    { "kernel32.dll", "WaitForSingleObject",        0 },
    { "kernel32.dll", "WaitForSingleObjectEx",      1 },

    /* File & System I/O */
    { "kernel32.dll", "CreateFileA",                1 },
    { "kernel32.dll", "CreateFileW",                1 },
    { "kernel32.dll", "ReadFile",                   0 },
    { "kernel32.dll", "WriteFile",                  1 },
    { "kernel32.dll", "CloseHandle",                0 },
    { "kernel32.dll", "GetTempPathA",               1 },
    { "kernel32.dll", "GetTempPathW",               1 },
    { "kernel32.dll", "GetWindowsDirectoryA",       1 },
    { "kernel32.dll", "GetWindowsDirectoryW",       1 },
    { "kernel32.dll", "GetSystemDirectoryA",        1 },
    { "kernel32.dll", "GetSystemDirectoryW",        1 },

    /* NT Native APIs (ntdll.dll) */
    { "ntdll.dll",    "NtAllocateVirtualMemory",    3 },
    { "ntdll.dll",    "NtProtectVirtualMemory",     3 },
    { "ntdll.dll",    "NtWriteVirtualMemory",       3 },
    { "ntdll.dll",    "NtReadVirtualMemory",        2 },
    { "ntdll.dll",    "NtFreeVirtualMemory",        1 },
    { "ntdll.dll",    "NtCreateThreadEx",           3 },
    { "ntdll.dll",    "NtQueueApcThread",           3 },
    { "ntdll.dll",    "NtQueueApcThreadEx",         3 },
    { "ntdll.dll",    "NtMapViewOfSection",         3 },
    { "ntdll.dll",    "NtUnmapViewOfSection",       2 },
    { "ntdll.dll",    "NtOpenProcess",              2 },
    { "ntdll.dll",    "NtOpenThread",               2 },
    { "ntdll.dll",    "NtSuspendThread",            2 },
    { "ntdll.dll",    "NtResumeThread",             2 },
    { "ntdll.dll",    "NtGetContextThread",         2 },
    { "ntdll.dll",    "NtSetContextThread",         3 },
    { "ntdll.dll",    "NtQueryInformationProcess",  2 },
    { "ntdll.dll",    "NtSetInformationThread",     2 },
    { "ntdll.dll",    "NtQuerySystemInformation",   2 },
    { "ntdll.dll",    "NtClose",                    0 },
    { "ntdll.dll",    "LdrLoadDll",                 2 },
    { "ntdll.dll",    "LdrGetProcedureAddress",     2 },
    { "ntdll.dll",    "RtlCreateUserThread",        3 },
    { "ntdll.dll",    "RtlAdjustPrivilege",         3 },
    { "ntdll.dll",    "RtlMoveMemory",              0 },
    { "ntdll.dll",    "RtlZeroMemory",              0 },

    /* Networking (Payload stagers / Shellcode callbacks) */
    { "ws2_32.dll",   "WSAStartup",                 1 },
    { "ws2_32.dll",   "WSACleanup",                 0 },
    { "ws2_32.dll",   "socket",                     2 },
    { "ws2_32.dll",   "connect",                    2 },
    { "ws2_32.dll",   "send",                       1 },
    { "ws2_32.dll",   "recv",                       1 },
    { "ws2_32.dll",   "bind",                       2 },
    { "ws2_32.dll",   "listen",                     2 },
    { "ws2_32.dll",   "accept",                     2 },
    { "ws2_32.dll",   "closesocket",                0 },
    { "ws2_32.dll",   "gethostbyname",              1 },
    { "ws2_32.dll",   "getaddrinfo",                1 },
    { "ws2_32.dll",   "WSASend",                    1 },
    { "ws2_32.dll",   "WSARecv",                    1 },

    /* HTTP / Web (Droppers & C2) */
    { "wininet.dll",  "InternetOpenA",              2 },
    { "wininet.dll",  "InternetOpenW",              2 },
    { "wininet.dll",  "InternetConnectA",           2 },
    { "wininet.dll",  "InternetConnectW",           2 },
    { "wininet.dll",  "HttpOpenRequestA",           2 },
    { "wininet.dll",  "HttpOpenRequestW",           2 },
    { "wininet.dll",  "HttpSendRequestA",           2 },
    { "wininet.dll",  "HttpSendRequestW",           2 },
    { "wininet.dll",  "InternetReadFile",           2 },
    { "wininet.dll",  "InternetCloseHandle",        0 },

    /* Security & Token Manipulation */
    { "advapi32.dll", "OpenProcessToken",           2 },
    { "advapi32.dll", "LookupPrivilegeValueA",      2 },
    { "advapi32.dll", "LookupPrivilegeValueW",      2 },
    { "advapi32.dll", "AdjustTokenPrivileges",      3 },
    { "advapi32.dll", "RegOpenKeyExA",              1 },
    { "advapi32.dll", "RegOpenKeyExW",              1 },
    { "advapi32.dll", "RegSetValueExA",             2 },
    { "advapi32.dll", "RegSetValueExW",             2 },
    { "advapi32.dll", "CreateServiceA",             3 },
    { "advapi32.dll", "CreateServiceW",             3 },
    { "advapi32.dll", "StartServiceA",              2 },
    { "advapi32.dll", "StartServiceW",              2 },

    /* User Interaction & Hooking */
    { "user32.dll",   "MessageBoxA",                0 },
    { "user32.dll",   "MessageBoxW",                0 },
    { "user32.dll",   "FindWindowA",                1 },
    { "user32.dll",   "FindWindowW",                1 },
    { "user32.dll",   "SetWindowsHookExA",          3 },
    { "user32.dll",   "SetWindowsHookExW",          3 },
    { "user32.dll",   "GetAsyncKeyState",            2 },
    { "user32.dll",   "GetKeyState",                1 },
    { "user32.dll",   "BlockInput",                 3 },

    { NULL, NULL, 0 }
};

/* Lookup Table & Binary Search Engine */

typedef struct {
    uint32_t     hash_val;
    IremHashAlgo algo;
    const char*  dll_name;
    const char*  api_name;
    int          risk_level;
} HashLookupEntry;

static HashLookupEntry* g_hash_table = NULL;
static size_t g_hash_count = 0;
static bool g_hash_inited = false;

static int compare_entries(const void* a, const void* b) {
    uint32_t ha = ((const HashLookupEntry*)a)->hash_val;
    uint32_t hb = ((const HashLookupEntry*)b)->hash_val;
    if (ha < hb) return -1;
    if (ha > hb) return 1;
    return 0;
}

void irem_hash_init_tables(void) {
    if (g_hash_inited) return;

    size_t api_count = 0;
    while (KNOWN_APIS[api_count].api_name != NULL) {
        api_count++;
    }

    /* We register 5 algorithms per API: ROR13, ROR13_DLL, DJB2, FNV1A, CRC32 */
    size_t max_entries = api_count * 5;
    g_hash_table = (HashLookupEntry*)malloc(max_entries * sizeof(HashLookupEntry));
    if (!g_hash_table) return;

    g_hash_count = 0;

    for (size_t i = 0; i < api_count; ++i) {
        const KnownApiDef* def = &KNOWN_APIS[i];

        // 1. ROR13
        uint32_t h_ror13 = irem_calc_ror13(def->api_name);
        if (h_ror13 > 0xFFFF) {
            HashLookupEntry e = { h_ror13, IREM_HASH_ALGO_ROR13, def->dll_name, def->api_name, def->risk_level };
            g_hash_table[g_hash_count++] = e;
        }

        // 2. ROR13 with DLL
        uint32_t h_ror13_dll = irem_calc_ror13_dll(def->dll_name, def->api_name);
        if (h_ror13_dll > 0xFFFF) {
            HashLookupEntry e = { h_ror13_dll, IREM_HASH_ALGO_ROR13_DLL, def->dll_name, def->api_name, def->risk_level };
            g_hash_table[g_hash_count++] = e;
        }

        // 3. DJB2
        uint32_t h_djb2 = irem_calc_djb2(def->api_name);
        if (h_djb2 > 0xFFFF) {
            HashLookupEntry e = { h_djb2, IREM_HASH_ALGO_DJB2, def->dll_name, def->api_name, def->risk_level };
            g_hash_table[g_hash_count++] = e;
        }

        // 4. FNV-1a
        uint32_t h_fnv = irem_calc_fnv1a(def->api_name);
        if (h_fnv > 0xFFFF) {
            HashLookupEntry e = { h_fnv, IREM_HASH_ALGO_FNV1A, def->dll_name, def->api_name, def->risk_level };
            g_hash_table[g_hash_count++] = e;
        }

        // 5. CRC32
        uint32_t h_crc = irem_calc_crc32(def->api_name);
        if (h_crc > 0xFFFF) {
            HashLookupEntry e = { h_crc, IREM_HASH_ALGO_CRC32, def->dll_name, def->api_name, def->risk_level };
            g_hash_table[g_hash_count++] = e;
        }
    }

    /* Sort table for fast O(log N) binary search */
    qsort(g_hash_table, g_hash_count, sizeof(HashLookupEntry), compare_entries);
    g_hash_inited = true;
}

const char* irem_hash_lookup(uint32_t hash_val, const char** out_dll, IremHashAlgo* out_algo, int* out_risk) {
    if (!g_hash_inited) {
        irem_hash_init_tables();
    }
    if (!g_hash_table || g_hash_count == 0) return NULL;

    HashLookupEntry key;
    key.hash_val = hash_val;

    const HashLookupEntry* match = (const HashLookupEntry*)bsearch(
        &key,
        g_hash_table,
        g_hash_count,
        sizeof(HashLookupEntry),
        compare_entries
    );

    if (match) {
        if (out_dll) *out_dll = match->dll_name;
        if (out_algo) *out_algo = match->algo;
        if (out_risk) *out_risk = match->risk_level;
        return match->api_name;
    }
    return NULL;
}

void irem_hash_db_init(IremHashMatchDB* db) {
    if (!db) return;
    db->matches = NULL;
    db->count = 0;
    db->capacity = 0;
}

void irem_hash_db_free(IremHashMatchDB* db) {
    if (!db) return;
    if (db->matches) {
        free(db->matches);
        db->matches = NULL;
    }
    db->count = 0;
    db->capacity = 0;
}

static bool match_db_push(IremHashMatchDB* db, const IremHashMatch* match) {
    if (db->count >= db->capacity) {
        int new_cap = db->capacity == 0 ? 32 : db->capacity * 2;
        IremHashMatch* new_buf = (IremHashMatch*)realloc(db->matches, new_cap * sizeof(IremHashMatch));
        if (!new_buf) return false;
        db->matches = new_buf;
        db->capacity = new_cap;
    }
    db->matches[db->count++] = *match;
    return true;
}

static const char* algo_to_string(IremHashAlgo algo) {
    switch (algo) {
    case IREM_HASH_ALGO_ROR13: return "ROR13";
    case IREM_HASH_ALGO_ROR13_DLL: return "ROR13+DLL";
    case IREM_HASH_ALGO_DJB2: return "DJB2";
    case IREM_HASH_ALGO_FNV1A: return "FNV-1a";
    case IREM_HASH_ALGO_CRC32: return "CRC32";
    case IREM_HASH_ALGO_ADDITIVE: return "ADD";
    default: return "HASH";
    }
}


bool irem_hash_scan_instructions(
    const IremFlatInstruction* instructions,
    size_t                     count,
    IremHashMatchDB*           out_matches
) {
    if (!instructions || count == 0 || !out_matches) return false;

    if (!g_hash_inited) {
        irem_hash_init_tables();
    }

    for (size_t i = 0; i < count; ++i) {
        const IremFlatInstruction* ins = &instructions[i];

        /* Check immediate operands */
        for (uint8_t op_idx = 0; op_idx < ins->op_count; ++op_idx) {
            const IremFlatOperand* op = &ins->ops[op_idx];
            if (op->type == IREM_OP_IMM) {
                uint32_t val = (uint32_t)(op->imm & 0xFFFFFFFF);
                /* Filter out trivial numbers (pointers, small ints, stack offsets) */
                if (val < 0x10000 || val == 0xFFFFFFFF || val == 0xCCCCCCCC) continue;

                const char* dll_name = NULL;
                IremHashAlgo algo = IREM_HASH_ALGO_NONE;
                int risk = 0;
                const char* api = irem_hash_lookup(val, &dll_name, &algo, &risk);

                if (api) {
                    IremHashMatch m;
                    memset(&m, 0, sizeof(m));
                    m.insn_index = i;
                    m.va = ins->va;
                    m.hash_value = val;
                    m.algo = algo;
                    m.risk_level = risk;
                    strncpy_s(m.api_name, sizeof(m.api_name), api, sizeof(m.api_name) - 1);
                    strncpy_s(m.dll_name, sizeof(m.dll_name), dll_name ? dll_name : "", sizeof(m.dll_name) - 1);

                    const char* risk_str = (risk >= 3) ? " [CRITICAL]" : ((risk >= 2) ? " [SUSPICIOUS]" : "");
                    snprintf(m.annotation, sizeof(m.annotation), "[API Hash: %s -> %s!%s]%s",
                             algo_to_string(algo), m.dll_name, m.api_name, risk_str);

                    match_db_push(out_matches, &m);
                }
            }
        }
    }

    return true;
}