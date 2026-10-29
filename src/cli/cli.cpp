#include "cli.hpp"
#include "../pe/pe_parser.hpp"
#include "../disasm/instruction.hpp"
#include "../disasm/x86_decoder.hpp"
#include "../patch/patch_manager.hpp"
#include "../analysis/function_manager.hpp"
#include "../analysis/xref_manager.hpp"
#include "../engines/engines_bridge.hpp"

#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <algorithm>
#include <filesystem>
#include <format>

namespace agy::cli {

static bool attach_console() {
    DWORD file_type = GetFileType(GetStdHandle(STD_OUTPUT_HANDLE));
    bool is_redirected = (file_type == FILE_TYPE_DISK || file_type == FILE_TYPE_PIPE);

    if (!is_redirected) {
        if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
            AllocConsole();
        }
        FILE* fp = nullptr;
        freopen_s(&fp, "CONOUT$", "w", stdout);
        freopen_s(&fp, "CONOUT$", "w", stderr);
        freopen_s(&fp, "CONIN$", "r", stdin);
    } else {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE && hOut != NULL) {
            int fd = _open_osfhandle((intptr_t)hOut, _O_TEXT);
            if (fd >= 0) {
                FILE* fp = _fdopen(fd, "w");
                if (fp) {
                    *stdout = *fp;
                    setvbuf(stdout, NULL, _IONBF, 0);
                }
            }
        }
        HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
        if (hErr != INVALID_HANDLE_VALUE && hErr != NULL) {
            int fd = _open_osfhandle((intptr_t)hErr, _O_TEXT);
            if (fd >= 0) {
                FILE* fp = _fdopen(fd, "w");
                if (fp) {
                    *stderr = *fp;
                    setvbuf(stderr, NULL, _IONBF, 0);
                }
            }
        }
    }

    std::ios::sync_with_stdio(true);
    return true;
}

static std::string to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), str.data(), size_needed, nullptr, nullptr);
    return str;
}

static uint64_t parse_u64(const std::wstring& str) {
    std::string s = to_utf8(str);
    try {
        return std::stoull(s, nullptr, 0);
    } catch (...) {
        return 0;
    }
}

static uint32_t parse_u32(const std::wstring& str) {
    return static_cast<uint32_t>(parse_u64(str));
}

static const char* get_algo_name(IremHashAlgo algo) {
    switch (algo) {
    case IREM_HASH_ALGO_ROR13:     return "ROR13";
    case IREM_HASH_ALGO_ROR13_DLL: return "ROR13_DLL (Metasploit)";
    case IREM_HASH_ALGO_DJB2:      return "DJB2";
    case IREM_HASH_ALGO_FNV1A:     return "FNV-1a";
    case IREM_HASH_ALGO_CRC32:     return "CRC32";
    case IREM_HASH_ALGO_ADDITIVE:  return "Additive";
    default:                       return "Unknown";
    }
}

bool is_cli_verb(const wchar_t* arg) {
    if (!arg) return false;
    std::wstring s = arg;
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);

    return s == L"help" || s == L"--help" || s == L"-h" || s == L"/?" ||
           s == L"analyze" || s == L"sections" || s == L"imports" ||
           s == L"exports" || s == L"functions" || s == L"strings" ||
           s == L"disasm" || s == L"xrefs" || s == L"sig" ||
           s == L"hash" || s == L"patch" || s == L"cfg" || s == L"entropy";
}

// Command handlers

static int cmd_help(int, wchar_t**) {
    std::cout << "\n"
              << "Irem - x86_64 Disassembler & Patching Engine\n"
              << "Author: mina | Windows x86_64 | 10 Analysis Engines\n\n"
              << "Usage: Irem.exe <command> [arguments...]\n\n"
              << "Available Commands:\n"
              << "  help                                Show this command reference\n"
              << "  analyze   <binary>                  Comprehensive PE header & engine report\n"
              << "  sections  <binary>                  PE section table with Shannon entropy\n"
              << "  imports   <binary>                  Import Address Table (IAT) dump\n"
              << "  exports   <binary>                  Export Address Table (EAT) symbols\n"
              << "  functions <binary>                  Discovered functions with sizes & xrefs\n"
              << "  strings   <binary>                  Extract ASCII and UTF-16 literals & xrefs\n"
              << "  disasm    <binary> [va] [count]     Disassemble N instructions (default: entry, 40)\n"
              << "  xrefs     <binary> <va>             Display all callers to the target address\n"
              << "  sig       <binary> <va> [count]     Generate unique AOB signature at address\n"
              << "  hash      <hex_value>               Resolve API hash (ROR13, DJB2, FNV-1a, CRC32)\n"
              << "  patch     <bin> <va> <hex> -o <out> Apply hex patch and export patched PE\n"
              << "  cfg       <binary> <va>             Control flow graph basic blocks & edges\n"
              << "  entropy   <binary>                  Section entropy visualization & packing test\n\n"
              << "Examples:\n"
              << "  Irem.exe analyze target.exe\n"
              << "  Irem.exe disasm target.exe 0x140001000 30\n"
              << "  Irem.exe hash 0x91AFCA54\n"
              << "  Irem.exe patch game.exe 0x140002150 \"90 90 90\" -o game_fixed.exe\n\n";
    return 0;
}

static int cmd_analyze(int argc, wchar_t** argv) {
    if (argc < 3) {
        std::cerr << "[-] Error: Missing binary path. Usage: Irem.exe analyze <binary>\n";
        return 1;
    }
    std::filesystem::path target = argv[2];
    auto pe_res = pe::PEFile::load_from_file(target);
    if (!pe_res) {
        std::cerr << "[-] PE Load Error: " << pe_res.error().message << "\n";
        return 1;
    }
    const auto& pe = *pe_res;

    std::cout << "\n[+] Binary: " << target.filename().string() << "\n";
    std::cout << "    Subsystem:       " << pe.get_subsystem_name()
              << (pe.is_driver() ? " [KERNEL DRIVER]" : "")
              << (pe.is_uefi() ? " [UEFI BINARY]" : "") << "\n";
    std::cout << "    ImageBase:       0x" << std::hex << pe.get_image_base() << "\n";
    std::cout << "    Entry Point VA:  0x" << std::hex << pe.get_entry_point_va() << "\n";
    const auto& sec = pe.get_security_flags();
    std::cout << "    Mitigations:     ASLR=" << (sec.aslr ? "ON" : "OFF")
              << " | DEP=" << (sec.dep_nx ? "ON" : "OFF")
              << " | CFG=" << (sec.cfg ? "ON" : "OFF")
              << " | HighEntropyVA=" << (sec.high_entropy_va ? "ON" : "OFF") << "\n";

    std::cout << "\n[+] Sections (" << pe.get_sections().size() << "):\n";
    for (const auto& s : pe.get_sections()) {
        std::cout << "    " << std::left << std::setw(10) << s.name
                  << " VA: 0x" << std::hex << std::setw(10) << (pe.get_image_base() + s.virtual_address)
                  << " Size: 0x" << std::hex << std::setw(8) << s.virtual_size
                  << " Entropy: " << std::dec << std::fixed << std::setprecision(2) << s.entropy
                  << (s.is_executable ? " [EXEC]" : "")
                  << (s.is_writable ? " [WRITE]" : "") << "\n";
    }

    std::cout << "\n[+] Imports: " << std::dec << pe.get_imports().size() << " APIs\n";
    std::cout << "[+] Exports: " << std::dec << pe.get_exports().size() << " Symbols\n";

    const auto* code_sec = pe.get_code_section();
    if (code_sec) {
        auto sec_bytes = pe.get_section_bytes(*code_sec);
        disasm::X86Decoder decoder;
        auto instructions = decoder.decode_buffer(
            sec_bytes,
            pe.get_image_base() + code_sec->virtual_address,
            code_sec->virtual_address,
            code_sec->raw_offset,
            &pe
        );
        analysis::FunctionManager fn_mgr;
        fn_mgr.discover_functions(pe, code_sec->name, instructions);

        auto session = engines::run_analysis(pe, code_sec->name, instructions, fn_mgr);

        std::cout << "\n[+] Analysis Engines Summary:\n";
        std::cout << "    * Instructions Disassembled: " << std::dec << instructions.size() << "\n";
        std::cout << "    * Functions Discovered:      " << std::dec << fn_mgr.get_functions().size() << "\n";
        std::cout << "    * Stack Frames (.pdata):     " << std::dec << session->stack_frames.size() << "\n";
        std::cout << "    * String Literals Extracted: " << std::dec << session->string_db.string_count << "\n";
        std::cout << "    * Call Sites Analyzed:       " << std::dec << session->call_analyses.size() << "\n";
        std::cout << "    * Jump Tables Resolved:      " << std::dec << session->jump_tables.size() << "\n";
        std::cout << "    * Function CFGs Built:       " << std::dec << session->function_cfgs.size() << "\n";
        std::cout << "    * Struct Accesses (TEB/PEB): " << std::dec << session->struct_db.count << "\n";
        std::cout << "    * API Hash Matches:          " << std::dec << session->hash_db.count << "\n";
    }
    std::cout << "\n";
    return 0;
}

static int cmd_sections(int argc, wchar_t** argv) {
    if (argc < 3) {
        std::cerr << "[-] Error: Missing binary path. Usage: Irem.exe sections <binary>\n";
        return 1;
    }
    auto pe_res = pe::PEFile::load_from_file(argv[2]);
    if (!pe_res) {
        std::cerr << "[-] Failed to load PE.\n";
        return 1;
    }
    const auto& pe = *pe_res;

    std::cout << "\n=== PE SECTION TABLE ===\n";
    std::cout << std::left << std::setw(10) << "Name"
              << std::setw(18) << "Virtual Address"
              << std::setw(12) << "Virt Size"
              << std::setw(12) << "Raw Size"
              << std::setw(10) << "Entropy"
              << "Flags\n";
    std::cout << "------------------------------------------------------------------------\n";

    for (const auto& s : pe.get_sections()) {
        std::cout << std::left << std::setw(10) << s.name
                  << "0x" << std::hex << std::setw(16) << (pe.get_image_base() + s.virtual_address)
                  << "0x" << std::hex << std::setw(10) << s.virtual_size
                  << "0x" << std::hex << std::setw(10) << s.raw_size
                  << std::dec << std::fixed << std::setprecision(2) << std::setw(10) << s.entropy;
        if (s.is_executable) std::cout << "EXEC ";
        if (s.is_readable)   std::cout << "READ ";
        if (s.is_writable)   std::cout << "WRITE ";
        std::cout << "\n";
    }
    std::cout << "\n";
    return 0;
}

static int cmd_imports(int argc, wchar_t** argv) {
    if (argc < 3) {
        std::cerr << "[-] Missing binary. Usage: Irem.exe imports <binary>\n";
        return 1;
    }
    auto pe_res = pe::PEFile::load_from_file(argv[2]);
    if (!pe_res) {
        std::cerr << "[-] Failed to load PE.\n";
        return 1;
    }
    const auto& pe = *pe_res;
    const auto& imps = pe.get_imports();
    std::cout << "\n=== IMPORT ADDRESS TABLE (" << std::dec << imps.size() << " APIs) ===\n";

    std::string current_dll;
    for (const auto& imp : imps) {
        if (imp.dll_name != current_dll) {
            current_dll = imp.dll_name;
            std::cout << "\n[" << current_dll << "]\n";
        }
        std::cout << "  0x" << std::hex << std::setw(12) << imp.iat_va << " : " << imp.symbol_name;
        if (imp.is_by_ordinal) std::cout << " (Ordinal " << std::dec << imp.ordinal << ")";
        std::cout << "\n";
    }
    std::cout << "\n";
    return 0;
}

static int cmd_exports(int argc, wchar_t** argv) {
    if (argc < 3) {
        std::cerr << "[-] Missing binary. Usage: Irem.exe exports <binary>\n";
        return 1;
    }
    auto pe_res = pe::PEFile::load_from_file(argv[2]);
    if (!pe_res) {
        std::cerr << "[-] Failed to load PE.\n";
        return 1;
    }
    const auto& pe = *pe_res;
    const auto& exps = pe.get_exports();
    std::cout << "\n=== EXPORT ADDRESS TABLE (" << std::dec << exps.size() << " Exports) ===\n";

    for (const auto& exp : exps) {
        std::cout << "  Ord: " << std::dec << std::setw(5) << exp.ordinal
                  << "  RVA: 0x" << std::hex << std::setw(8) << exp.rva
                  << "  VA: 0x" << std::hex << std::setw(12) << exp.va
                  << "  " << exp.name << "\n";
    }
    std::cout << "\n";
    return 0;
}

static int cmd_functions(int argc, wchar_t** argv) {
    if (argc < 3) {
        std::cerr << "[-] Missing binary. Usage: Irem.exe functions <binary>\n";
        return 1;
    }
    auto pe_res = pe::PEFile::load_from_file(argv[2]);
    if (!pe_res) {
        std::cerr << "[-] Failed to load PE.\n";
        return 1;
    }
    const auto& pe = *pe_res;
    const auto* code_sec = pe.get_code_section();
    if (!code_sec) {
        std::cerr << "[-] No executable code section found.\n";
        return 1;
    }

    auto sec_bytes = pe.get_section_bytes(*code_sec);
    disasm::X86Decoder decoder;
    auto instructions = decoder.decode_buffer(
        sec_bytes,
        pe.get_image_base() + code_sec->virtual_address,
        code_sec->virtual_address,
        code_sec->raw_offset,
        &pe
    );

    analysis::FunctionManager fn_mgr;
    fn_mgr.discover_functions(pe, code_sec->name, instructions);

    analysis::XrefManager xref_mgr;
    xref_mgr.build_xrefs(instructions, fn_mgr);

    const auto& fns = fn_mgr.get_functions();
    std::cout << "\n=== DISCOVERED FUNCTIONS (" << std::dec << fns.size() << ") ===\n";
    std::cout << std::left << std::setw(18) << "Start VA"
              << std::setw(10) << "Size"
              << std::setw(8)  << "XREFs"
              << "Name\n";
    std::cout << "------------------------------------------------------------------------\n";

    for (const auto& fn : fns) {
        size_t xcnt = xref_mgr.get_xref_count(fn.start_va);
        std::cout << "0x" << std::hex << std::setw(16) << fn.start_va
                  << "0x" << std::hex << std::setw(8) << fn.length
                  << std::dec << std::setw(8) << xcnt
                  << fn.name;
        if (fn.is_entry_point) std::cout << " [ENTRY]";
        if (fn.is_export) std::cout << " [EXPORT]";
        std::cout << "\n";
    }
    std::cout << "\n";
    return 0;
}

static int cmd_strings(int argc, wchar_t** argv) {
    if (argc < 3) {
        std::cerr << "[-] Missing binary. Usage: Irem.exe strings <binary>\n";
        return 1;
    }
    auto pe_res = pe::PEFile::load_from_file(argv[2]);
    if (!pe_res) {
        std::cerr << "[-] Failed to load PE.\n";
        return 1;
    }
    const auto& pe = *pe_res;
    const auto* code_sec = pe.get_code_section();
    if (!code_sec) return 1;

    auto sec_bytes = pe.get_section_bytes(*code_sec);
    disasm::X86Decoder decoder;
    auto instructions = decoder.decode_buffer(
        sec_bytes,
        pe.get_image_base() + code_sec->virtual_address,
        code_sec->virtual_address,
        code_sec->raw_offset,
        &pe
    );

    analysis::FunctionManager fn_mgr;
    fn_mgr.discover_functions(pe, code_sec->name, instructions);

    auto session = engines::run_analysis(pe, code_sec->name, instructions, fn_mgr);

    std::cout << "\n=== STRING LITERALS (" << std::dec << session->string_db.string_count << ") ===\n";
    for (int i = 0; i < session->string_db.string_count; ++i) {
        const auto& item = session->string_db.strings[i];
        std::cout << "0x" << std::hex << std::setw(12) << item.va
                  << " [" << (item.encoding == IREM_STR_UTF16LE ? "UTF16" : "ASCII") << "]"
                  << " (" << item.section_name << ") : "
                  << "\"" << item.preview << "\"\n";
    }
    std::cout << "\n";
    return 0;
}

static int cmd_disasm(int argc, wchar_t** argv) {
    if (argc < 3) {
        std::cerr << "[-] Missing binary. Usage: Irem.exe disasm <binary> [va] [count]\n";
        return 1;
    }
    auto pe_res = pe::PEFile::load_from_file(argv[2]);
    if (!pe_res) {
        std::cerr << "[-] Failed to load PE.\n";
        return 1;
    }
    const auto& pe = *pe_res;
    const auto* code_sec = pe.get_code_section();
    if (!code_sec) return 1;

    auto sec_bytes = pe.get_section_bytes(*code_sec);
    disasm::X86Decoder decoder;
    auto instructions = decoder.decode_buffer(
        sec_bytes,
        pe.get_image_base() + code_sec->virtual_address,
        code_sec->virtual_address,
        code_sec->raw_offset,
        &pe
    );

    analysis::FunctionManager fn_mgr;
    fn_mgr.discover_functions(pe, code_sec->name, instructions);
    auto session = engines::run_analysis(pe, code_sec->name, instructions, fn_mgr);
    engines::apply_analysis_annotations(instructions, *session, pe);

    uint64_t target_va = (argc >= 4) ? parse_u64(argv[3]) : pe.get_entry_point_va();
    size_t count = (argc >= 5) ? static_cast<size_t>(parse_u64(argv[4])) : 40;

    size_t start_idx = 0;
    bool found = false;
    for (size_t i = 0; i < instructions.size(); ++i) {
        if (instructions[i].va >= target_va) {
            start_idx = i;
            found = true;
            break;
        }
    }
    if (!found) start_idx = 0;

    std::cout << "\n=== DISASSEMBLY @ 0x" << std::hex << target_va << " (" << std::dec << count << " instructions) ===\n";
    for (size_t i = start_idx; i < instructions.size() && i < start_idx + count; ++i) {
        const auto& ins = instructions[i];
        std::string raw = ins.format_raw_bytes();
        std::string ops = ins.format_operands();

        std::cout << "0x" << std::hex << std::setw(12) << ins.va << "  "
                  << std::left << std::setw(20) << raw << " "
                  << std::setw(8) << ins.mnemonic << " "
                  << std::setw(28) << ops;
        if (!ins.comment.empty()) {
            std::cout << " ; " << ins.comment;
        }
        std::cout << "\n";
    }
    std::cout << "\n";
    return 0;
}

static int cmd_xrefs(int argc, wchar_t** argv) {
    if (argc < 4) {
        std::cerr << "[-] Missing arguments. Usage: Irem.exe xrefs <binary> <va>\n";
        return 1;
    }
    auto pe_res = pe::PEFile::load_from_file(argv[2]);
    if (!pe_res) return 1;
    const auto& pe = *pe_res;
    const auto* code_sec = pe.get_code_section();
    if (!code_sec) return 1;

    uint64_t target_va = parse_u64(argv[3]);
    auto sec_bytes = pe.get_section_bytes(*code_sec);
    disasm::X86Decoder decoder;
    auto instructions = decoder.decode_buffer(
        sec_bytes,
        pe.get_image_base() + code_sec->virtual_address,
        code_sec->virtual_address,
        code_sec->raw_offset,
        &pe
    );

    analysis::FunctionManager fn_mgr;
    fn_mgr.discover_functions(pe, code_sec->name, instructions);

    analysis::XrefManager xref_mgr;
    xref_mgr.build_xrefs(instructions, fn_mgr);

    const auto* callers = xref_mgr.get_xrefs_to(target_va);
    std::cout << "\n=== CROSS-REFERENCES TO 0x" << std::hex << target_va;
    if (!callers || callers->empty()) {
        std::cout << " (0 Callers) ===\n[-] No cross-references found.\n\n";
        return 0;
    }
    std::cout << " (" << std::dec << callers->size() << " Callers) ===\n";

    for (const auto& xr : *callers) {
        std::cout << "  0x" << std::hex << xr.source_va
                  << " [" << xr.type_name() << "]"
                  << (!xr.source_func_name.empty() ? (" in " + xr.source_func_name) : "")
                  << " : " << xr.instruction_text << "\n";
    }
    std::cout << "\n";
    return 0;
}

static int cmd_sig(int argc, wchar_t** argv) {
    if (argc < 4) {
        std::cerr << "[-] Missing arguments. Usage: Irem.exe sig <binary> <va> [instruction_count]\n";
        return 1;
    }
    auto pe_res = pe::PEFile::load_from_file(argv[2]);
    if (!pe_res) return 1;
    const auto& pe = *pe_res;
    const auto* code_sec = pe.get_code_section();
    if (!code_sec) return 1;

    uint64_t target_va = parse_u64(argv[3]);
    size_t insn_count = (argc >= 5) ? static_cast<size_t>(parse_u64(argv[4])) : 5;
    if (insn_count == 0) insn_count = 5;

    auto sec_bytes = pe.get_section_bytes(*code_sec);
    disasm::X86Decoder decoder;
    auto instructions = decoder.decode_buffer(
        sec_bytes,
        pe.get_image_base() + code_sec->virtual_address,
        code_sec->virtual_address,
        code_sec->raw_offset,
        &pe
    );

    size_t start_idx = 0;
    bool found = false;
    for (size_t i = 0; i < instructions.size(); ++i) {
        if (instructions[i].va == target_va) {
            start_idx = i;
            found = true;
            break;
        }
    }
    if (!found) {
        std::cerr << "[-] VA 0x" << std::hex << target_va << " not found in disassembly.\n";
        return 1;
    }

    auto flat = engines::flatten_instructions(instructions);
    size_t end_idx = (std::min)(start_idx + insn_count - 1, flat.size() - 1);

    IremSignature sig{};
    if (!irem_sigmaker_generate(flat.data(), flat.size(), start_idx, end_idx, &sig)) {
        std::cerr << "[-] Failed to generate signature.\n";
        return 1;
    }

    IremScanMatch matches[16];
    int match_count = irem_aob_scan(
        pe.get_raw_bytes().data(),
        pe.get_raw_bytes().size(),
        pe.get_image_base(),
        code_sec->raw_offset,
        code_sec->raw_size,
        code_sec->virtual_address,
        sig.bytes,
        sig.byte_count,
        matches,
        16
    );

    std::cout << "\n=== GENERATED AOB SIGNATURE @ 0x" << std::hex << target_va << " ===\n";
    std::cout << "  IDA Pattern:   " << sig.ida_pattern << "\n";
    std::cout << "  CE Pattern:    " << sig.ce_pattern << "\n";
    std::cout << "  C Mask:        " << sig.c_mask << "\n";
    std::cout << "  Total Bytes:   " << std::dec << sig.byte_count << " bytes\n";
    std::cout << "  Matches:       " << std::dec << match_count << (match_count == 1 ? " [UNIQUE SIGNATURE!]" : " [NON-UNIQUE]") << "\n\n";
    return 0;
}

static int cmd_hash(int argc, wchar_t** argv) {
    if (argc < 3) {
        std::cerr << "[-] Missing hash value. Usage: Irem.exe hash <hex_value>\n";
        return 1;
    }
    uint32_t hash_val = parse_u32(argv[2]);
    const char* dll = nullptr;
    IremHashAlgo algo = IREM_HASH_ALGO_NONE;
    int risk = 0;

    const char* api = irem_hash_lookup(hash_val, &dll, &algo, &risk);

    std::cout << "\n=== API HASH RESOLVER ===\n";
    std::cout << "  Input Hash:  0x" << std::hex << std::uppercase << hash_val << "\n";

    if (api) {
        std::cout << "  Status:      RESOLVED\n";
        std::cout << "  API Name:    " << (dll ? dll : "") << "!" << api << "\n";
        std::cout << "  Algorithm:   " << get_algo_name(algo) << "\n";
        std::cout << "  Risk Level:  ";
        if (risk == 3) std::cout << "CRITICAL (3)\n";
        else if (risk == 2) std::cout << "SUSPICIOUS / DANGEROUS (2)\n";
        else if (risk == 1) std::cout << "ALERT (1)\n";
        else std::cout << "BENIGN (0)\n";
    } else {
        std::cout << "  Status:      UNRESOLVED\n";
        std::cout << "  Notice:      Hash does not match known high-value APIs in internal database.\n";
    }
    std::cout << "\n";
    return 0;
}

static int cmd_patch(int argc, wchar_t** argv) {
    if (argc < 6) {
        std::cerr << "[-] Usage: Irem.exe patch <binary> <va> <\"hex bytes\"> -o <output>\n";
        return 1;
    }
    std::filesystem::path target = argv[2];
    uint64_t target_va = parse_u64(argv[3]);
    std::string hex_str = to_utf8(argv[4]);

    std::filesystem::path output_path;
    for (int i = 5; i < argc - 1; ++i) {
        if (std::wstring(argv[i]) == L"-o") {
            output_path = argv[i + 1];
            break;
        }
    }
    if (output_path.empty()) {
        std::cerr << "[-] Error: Output path required with -o <output_file>\n";
        return 1;
    }

    auto pe_res = pe::PEFile::load_from_file(target);
    if (!pe_res) {
        std::cerr << "[-] Failed to load PE binary.\n";
        return 1;
    }
    auto& pe = *pe_res;

    // Parse hex bytes
    std::vector<uint8_t> patch_bytes;
    std::string clean;
    for (char c : hex_str) {
        if (isxdigit((unsigned char)c)) clean.push_back(c);
    }
    for (size_t i = 0; i + 1 < clean.size(); i += 2) {
        std::string byte_str = clean.substr(i, 2);
        uint8_t b = static_cast<uint8_t>(std::strtoul(byte_str.c_str(), nullptr, 16));
        patch_bytes.push_back(b);
    }

    if (patch_bytes.empty()) {
        std::cerr << "[-] No valid hex bytes parsed from input.\n";
        return 1;
    }

    // Calculate RVA and File Offset from VA
    uint32_t rva = static_cast<uint32_t>(target_va - pe.get_image_base());
    uint32_t file_offset = pe.rva_to_file_offset(rva);

    patch::PatchManager pm;
    if (!pm.apply_custom_bytes(pe, file_offset, rva, target_va, patch_bytes, "CLI Patch")) {
        std::cerr << "[-] Failed to apply patch at VA 0x" << std::hex << target_va << "\n";
        return 1;
    }

    if (!pe.save_to_file(output_path)) {
        std::cerr << "[-] Failed to save patched binary to: " << output_path.string() << "\n";
        return 1;
    }

    std::cout << "[+] Patch Applied Successfully!\n";
    std::cout << "    Target VA:     0x" << std::hex << target_va << "\n";
    std::cout << "    Bytes Written: " << std::dec << patch_bytes.size() << " bytes\n";
    std::cout << "    Exported File: " << output_path.string() << "\n\n";
    return 0;
}

static int cmd_cfg(int argc, wchar_t** argv) {
    if (argc < 4) {
        std::cerr << "[-] Missing arguments. Usage: Irem.exe cfg <binary> <function_va>\n";
        return 1;
    }
    auto pe_res = pe::PEFile::load_from_file(argv[2]);
    if (!pe_res) return 1;
    const auto& pe = *pe_res;
    const auto* code_sec = pe.get_code_section();
    if (!code_sec) return 1;

    uint64_t target_va = parse_u64(argv[3]);
    auto sec_bytes = pe.get_section_bytes(*code_sec);
    disasm::X86Decoder decoder;
    auto instructions = decoder.decode_buffer(
        sec_bytes,
        pe.get_image_base() + code_sec->virtual_address,
        code_sec->virtual_address,
        code_sec->raw_offset,
        &pe
    );

    analysis::FunctionManager fn_mgr;
    fn_mgr.discover_functions(pe, code_sec->name, instructions);

    const auto* fn = fn_mgr.find_function_by_va(target_va);
    if (!fn) fn = fn_mgr.find_enclosing_function(target_va);
    if (!fn) {
        std::cerr << "[-] No function found containing 0x" << std::hex << target_va << "\n";
        return 1;
    }

    auto session = engines::run_analysis(pe, code_sec->name, instructions, fn_mgr);
    auto it = session->function_cfgs.find(fn->start_va);
    if (it == session->function_cfgs.end()) {
        std::cerr << "[-] CFG could not be constructed for function: " << fn->name << "\n";
        return 1;
    }
    const auto& cfg = it->second;

    std::cout << "\n=== CONTROL FLOW GRAPH: " << fn->name << " (0x" << std::hex << fn->start_va << ") ===\n";
    std::cout << "  Total Blocks: " << std::dec << cfg.block_count << " | Total Edges: " << cfg.edge_count << "\n\n";

    for (int i = 0; i < cfg.block_count; ++i) {
        const auto& bb = cfg.blocks[i];
        std::cout << "  [Block #" << bb.block_id << "] 0x" << std::hex << bb.start_va << " .. 0x" << bb.end_va
                  << " (" << std::dec << bb.instruction_count << " insns)";
        if (bb.is_entry) std::cout << " [ENTRY]";
        if (bb.is_exit)  std::cout << " [EXIT]";
        if (bb.is_loop_header) std::cout << " [LOOP HEADER]";
        std::cout << "\n";

        if (bb.succ_count > 0) {
            std::cout << "    -> Successors: ";
            for (int s = 0; s < bb.succ_count; ++s) {
                std::cout << "#" << std::dec << bb.succ_ids[s] << " ";
            }
            std::cout << "\n";
        }
    }

    std::cout << "\n  Edges:\n";
    for (int e = 0; e < cfg.edge_count; ++e) {
        const auto& edge = cfg.edges[e];
        const char* type_str = "FALLTHROUGH";
        if (edge.type == IREM_EDGE_JUMP_TRUE) type_str = "COND_TRUE";
        else if (edge.type == IREM_EDGE_JUMP_FALSE) type_str = "COND_FALSE";
        else if (edge.type == IREM_EDGE_JUMP_UNCOND) type_str = "UNCOND";
        else if (edge.type == IREM_EDGE_CALL) type_str = "CALL";

        std::cout << "    #" << edge.src_block_id << " -> #" << edge.dst_block_id
                  << " (" << type_str << ")"
                  << (edge.is_back_edge ? " [LOOP BACK-EDGE]" : "") << "\n";
    }
    std::cout << "\n";
    return 0;
}

static int cmd_entropy(int argc, wchar_t** argv) {
    if (argc < 3) {
        std::cerr << "[-] Missing binary. Usage: Irem.exe entropy <binary>\n";
        return 1;
    }
    auto pe_res = pe::PEFile::load_from_file(argv[2]);
    if (!pe_res) return 1;
    const auto& pe = *pe_res;

    std::cout << "\n=== SHANNON ENTROPY & PACKER ANALYSIS ===\n";
    for (const auto& s : pe.get_sections()) {
        int bar_filled = static_cast<int>((s.entropy / 8.0) * 20.0);
        bar_filled = std::clamp(bar_filled, 0, 20);
        std::string bar(bar_filled, '#');
        bar.append(20 - bar_filled, '.');

        std::cout << "  " << std::left << std::setw(10) << s.name
                  << " [" << bar << "] "
                  << std::fixed << std::setprecision(2) << s.entropy << " / 8.00";

        if (s.entropy >= 7.20) {
            std::cout << " [CRITICAL: PACKED / ENCRYPTED]";
        } else if (s.entropy >= 6.80) {
            std::cout << " [HIGH ENTROPY / COMPRESSED]";
        }
        std::cout << "\n";
    }
    std::cout << "\n";
    return 0;
}

// CLI dispatcher

int execute(int argc, wchar_t** argv) {
    if (argc < 2) return 0;

    attach_console();

    std::wstring verb = argv[1];
    std::transform(verb.begin(), verb.end(), verb.begin(), ::towlower);

    int ret = 1;
    if (verb == L"help" || verb == L"--help" || verb == L"-h" || verb == L"/?") {
        ret = cmd_help(argc, argv);
    } else if (verb == L"analyze") {
        ret = cmd_analyze(argc, argv);
    } else if (verb == L"sections") {
        ret = cmd_sections(argc, argv);
    } else if (verb == L"imports") {
        ret = cmd_imports(argc, argv);
    } else if (verb == L"exports") {
        ret = cmd_exports(argc, argv);
    } else if (verb == L"functions") {
        ret = cmd_functions(argc, argv);
    } else if (verb == L"strings") {
        ret = cmd_strings(argc, argv);
    } else if (verb == L"disasm") {
        ret = cmd_disasm(argc, argv);
    } else if (verb == L"xrefs") {
        ret = cmd_xrefs(argc, argv);
    } else if (verb == L"sig") {
        ret = cmd_sig(argc, argv);
    } else if (verb == L"hash") {
        ret = cmd_hash(argc, argv);
    } else if (verb == L"patch") {
        ret = cmd_patch(argc, argv);
    } else if (verb == L"cfg") {
        ret = cmd_cfg(argc, argv);
    } else if (verb == L"entropy") {
        ret = cmd_entropy(argc, argv);
    } else {
        std::cerr << "[-] Unknown command: " << to_utf8(verb) << ". Type 'Irem.exe help' for usage.\n";
        ret = 1;
    }

    std::cout << std::flush;
    std::cerr << std::flush;
    fflush(stdout);
    fflush(stderr);
    return ret;
}

} // namespace agy::cli
