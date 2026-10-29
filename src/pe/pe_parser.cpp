#include "pe_parser.hpp"
#include <fstream>
#include <cmath>
#include <array>
#include <format>
#include <algorithm>

namespace agy::pe {

double calculate_shannon_entropy(std::span<const uint8_t> data) {
    if (data.empty()) return 0.0;
    std::array<size_t, 256> counts{};
    for (uint8_t b : data) {
        counts[b]++;
    }

    double entropy = 0.0;
    double total = static_cast<double>(data.size());
    for (size_t count : counts) {
        if (count == 0) continue;
        double p = static_cast<double>(count) / total;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

std::expected<PEFile, PEParseError> PEFile::load_from_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return std::unexpected(PEParseError{ std::format("Failed to open file: {}", path.string()) });
    }

    const auto file_size = file.tellg();
    if (file_size < sizeof(IMAGE_DOS_HEADER)) {
        return std::unexpected(PEParseError{ "File size is too small to be a valid PE file." });
    }

    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(static_cast<size_t>(file_size));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), file_size)) {
        return std::unexpected(PEParseError{ "An error occurred while reading file content." });
    }

    return load_from_memory(std::move(buffer), path.string());
}

std::expected<PEFile, PEParseError> PEFile::load_from_memory(std::vector<uint8_t> buffer, const std::string& source_name) {
    PEFile pe;
    pe.file_path_ = source_name;
    pe.raw_bytes_ = std::move(buffer);

    PEParseError err;
    if (!pe.parse_internal(err)) {
        return std::unexpected(err);
    }

    return pe;
}

bool PEFile::parse_internal(PEParseError& err) {
    if (raw_bytes_.size() < sizeof(IMAGE_DOS_HEADER)) {
        err.message = "Invalid file: smaller than DOS Header size.";
        return false;
    }

    const auto* dos_hdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw_bytes_.data());
    if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) {
        err.message = std::format("Invalid DOS Signature: Expected 0x5A4D (MZ), Got 0x{:04X}", dos_hdr->e_magic);
        return false;
    }

    if (dos_hdr->e_lfanew < 0 || static_cast<size_t>(dos_hdr->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > raw_bytes_.size()) {
        err.message = "Invalid e_lfanew: NT Headers point outside file bounds.";
        return false;
    }

    const auto* nt_hdrs = reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw_bytes_.data() + dos_hdr->e_lfanew);
    if (nt_hdrs->Signature != IMAGE_NT_SIGNATURE) {
        err.message = std::format("Invalid PE Signature: Expected 0x00004550 (PE), Got 0x{:08X}", nt_hdrs->Signature);
        return false;
    }

    // Architecture check
    if (nt_hdrs->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        err.message = std::format("Only x86_64 (AMD64) architecture is supported. Detected machine type: 0x{:04X}", nt_hdrs->FileHeader.Machine);
        return false;
    }

    if (nt_hdrs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        err.message = "Invalid Optional Header Magic: PE32+ (64-bit) expected.";
        return false;
    }

    // Extract headers
    image_base_          = nt_hdrs->OptionalHeader.ImageBase;
    entry_point_rva_     = nt_hdrs->OptionalHeader.AddressOfEntryPoint;
    section_alignment_   = nt_hdrs->OptionalHeader.SectionAlignment;
    file_alignment_      = nt_hdrs->OptionalHeader.FileAlignment;
    size_of_image_       = nt_hdrs->OptionalHeader.SizeOfImage;
    subsystem_           = nt_hdrs->OptionalHeader.Subsystem;

    // Security flags
    WORD dll_char = nt_hdrs->OptionalHeader.DllCharacteristics;
    security_flags_.aslr            = (dll_char & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    security_flags_.dep_nx          = (dll_char & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
    security_flags_.cfg             = (dll_char & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
    security_flags_.high_entropy_va = (dll_char & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0;
    security_flags_.seh             = (dll_char & IMAGE_DLLCHARACTERISTICS_NO_SEH) == 0;

    // Parse Sections
    const size_t num_sections = nt_hdrs->FileHeader.NumberOfSections;
    const auto* sec_hdrs = IMAGE_FIRST_SECTION(nt_hdrs);

    // Validate section header array memory boundary
    const uint8_t* sec_start = reinterpret_cast<const uint8_t*>(sec_hdrs);
    if (sec_start + (num_sections * sizeof(IMAGE_SECTION_HEADER)) > raw_bytes_.data() + raw_bytes_.size()) {
        err.message = "Section Header table extends beyond file boundaries.";
        return false;
    }

    sections_.clear();
    sections_.reserve(num_sections);

    for (size_t i = 0; i < num_sections; ++i) {
        const auto& sh = sec_hdrs[i];

        SectionInfo sec;
        char name_buf[9] = {};
        std::memcpy(name_buf, sh.Name, 8);
        sec.name = name_buf;

        sec.virtual_size     = sh.Misc.VirtualSize;
        sec.virtual_address  = sh.VirtualAddress;
        sec.raw_size         = sh.SizeOfRawData;
        sec.raw_offset       = sh.PointerToRawData;
        sec.characteristics  = sh.Characteristics;

        sec.is_executable = (sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        sec.is_readable   = (sh.Characteristics & IMAGE_SCN_MEM_READ) != 0;
        sec.is_writable   = (sh.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        sections_.push_back(std::move(sec));
    }

    calculate_section_entropies();
    parse_imports();
    parse_exports();
    parse_exception_directory(nt_hdrs);
    parse_debug_directory(nt_hdrs);

    return true;
}

std::string PEFile::get_subsystem_name() const {
    switch (subsystem_) {
    case IMAGE_SUBSYSTEM_NATIVE:                  return "Native Driver";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:             return "Windows GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:             return "Windows Console";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:         return "EFI Application";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return "EFI Boot Service Driver";
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:      return "EFI Runtime Driver";
    case IMAGE_SUBSYSTEM_EFI_ROM:                 return "EFI ROM";
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: return "Windows Boot Application";
    default: return std::format("Unknown ({})", subsystem_);
    }
}

bool PEFile::is_driver() const {
    return subsystem_ == IMAGE_SUBSYSTEM_NATIVE;
}

bool PEFile::is_uefi() const {
    return subsystem_ == IMAGE_SUBSYSTEM_EFI_APPLICATION ||
           subsystem_ == IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER ||
           subsystem_ == IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER ||
           subsystem_ == IMAGE_SUBSYSTEM_EFI_ROM;
}

void PEFile::calculate_section_entropies() {
    for (auto& sec : sections_) {
        if (sec.raw_offset + sec.raw_size <= raw_bytes_.size() && sec.raw_size > 0) {
            std::span<const uint8_t> sec_data(raw_bytes_.data() + sec.raw_offset, sec.raw_size);
            sec.entropy = calculate_shannon_entropy(sec_data);
        } else {
            sec.entropy = 0.0;
        }
    }
}

uint32_t PEFile::rva_to_file_offset(uint32_t rva) const {
    for (const auto& sec : sections_) {
        uint32_t sec_limit = (std::max)(sec.virtual_size, sec.raw_size);
        if (rva >= sec.virtual_address && rva < sec.virtual_address + sec_limit) {
            uint32_t delta = rva - sec.virtual_address;
            if (delta < sec.raw_size && (sec.raw_offset + delta) < raw_bytes_.size()) {
                return sec.raw_offset + delta;
            }
        }
    }
    // Check if within PE headers
    if (rva < raw_bytes_.size()) {
        return rva;
    }
    return 0xFFFFFFFF; // Not mapped / invalid
}

uint32_t PEFile::file_offset_to_rva(uint32_t offset) const {
    for (const auto& sec : sections_) {
        if (offset >= sec.raw_offset && offset < sec.raw_offset + sec.raw_size) {
            return sec.virtual_address + (offset - sec.raw_offset);
        }
    }
    return offset;
}

const SectionInfo* PEFile::find_section_by_rva(uint32_t rva) const {
    for (const auto& sec : sections_) {
        uint32_t sec_limit = (std::max)(sec.virtual_size, sec.raw_size);
        if (rva >= sec.virtual_address && rva < sec.virtual_address + sec_limit) {
            return &sec;
        }
    }
    return nullptr;
}

const SectionInfo* PEFile::find_section_by_name(std::string_view name) const {
    for (const auto& sec : sections_) {
        if (sec.name == name) {
            return &sec;
        }
    }
    return nullptr;
}

const SectionInfo* PEFile::get_code_section() const {
    // Prefer entry point section, otherwise first executable section
    if (const auto* ep_sec = find_section_by_rva(entry_point_rva_)) {
        return ep_sec;
    }
    for (const auto& sec : sections_) {
        if (sec.is_executable) {
            return &sec;
        }
    }
    return sections_.empty() ? nullptr : &sections_[0];
}

std::span<const uint8_t> PEFile::get_section_bytes(const SectionInfo& section) const {
    if (section.raw_offset + section.raw_size <= raw_bytes_.size()) {
        return std::span<const uint8_t>(raw_bytes_.data() + section.raw_offset, section.raw_size);
    }
    return {};
}

std::span<const uint8_t> PEFile::get_bytes_at_rva(uint32_t rva, size_t max_len) const {
    uint32_t offset = rva_to_file_offset(rva);
    if (offset != 0xFFFFFFFF && offset < raw_bytes_.size()) {
        size_t available = (std::min)(max_len, raw_bytes_.size() - offset);
        return std::span<const uint8_t>(raw_bytes_.data() + offset, available);
    }
    return {};
}

void PEFile::parse_imports() {
    imports_.clear();
    iat_va_to_import_index_.clear();

    const auto* dos_hdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw_bytes_.data());
    const auto* nt_hdrs = reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw_bytes_.data() + dos_hdr->e_lfanew);

    const auto& import_dir = nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.VirtualAddress == 0 || import_dir.Size == 0) {
        return;
    }

    uint32_t import_offset = rva_to_file_offset(import_dir.VirtualAddress);
    if (import_offset == 0xFFFFFFFF || import_offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) > raw_bytes_.size()) {
        return;
    }

    const auto* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(raw_bytes_.data() + import_offset);

    while (desc->Name != 0 && desc->FirstThunk != 0) {
        // Bounds check descriptor
        if (reinterpret_cast<const uint8_t*>(desc + 1) > raw_bytes_.data() + raw_bytes_.size()) {
            break;
        }

        uint32_t name_offset = rva_to_file_offset(desc->Name);
        std::string dll_name = "UNKNOWN.DLL";
        if (name_offset != 0xFFFFFFFF && name_offset < raw_bytes_.size()) {
            dll_name = reinterpret_cast<const char*>(raw_bytes_.data() + name_offset);
        }

        uint32_t lookup_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        uint32_t lookup_offset = rva_to_file_offset(lookup_rva);
        uint32_t iat_rva = desc->FirstThunk;

        if (lookup_offset != 0xFFFFFFFF) {
            const auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA64*>(raw_bytes_.data() + lookup_offset);

            while (reinterpret_cast<const uint8_t*>(thunk + 1) <= raw_bytes_.data() + raw_bytes_.size() && thunk->u1.AddressOfData != 0) {
                ImportSymbol sym;
                sym.dll_name = dll_name;
                sym.iat_rva = iat_rva;
                sym.iat_va = image_base_ + iat_rva;

                if (IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal)) {
                    sym.is_by_ordinal = true;
                    sym.ordinal = static_cast<uint16_t>(IMAGE_ORDINAL64(thunk->u1.Ordinal));
                    sym.symbol_name = std::format("#{}", sym.ordinal);
                } else {
                    sym.is_by_ordinal = false;
                    uint32_t data_offset = rva_to_file_offset(static_cast<uint32_t>(thunk->u1.AddressOfData));
                    if (data_offset != 0xFFFFFFFF && data_offset + sizeof(IMAGE_IMPORT_BY_NAME) <= raw_bytes_.size()) {
                        const auto* ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(raw_bytes_.data() + data_offset);
                        sym.ordinal = ibn->Hint;
                        sym.symbol_name = reinterpret_cast<const char*>(ibn->Name);
                    } else {
                        sym.symbol_name = "???";
                    }
                }

                iat_va_to_import_index_[sym.iat_va] = imports_.size();
                imports_.push_back(std::move(sym));

                thunk++;
                iat_rva += sizeof(IMAGE_THUNK_DATA64);
            }
        }

        desc++;
    }
}

void PEFile::parse_exports() {
    exports_.clear();
    rva_to_export_index_.clear();

    const auto* dos_hdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw_bytes_.data());
    const auto* nt_hdrs = reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw_bytes_.data() + dos_hdr->e_lfanew);

    const auto& export_dir = nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_dir.VirtualAddress == 0 || export_dir.Size == 0) {
        return;
    }

    uint32_t export_offset = rva_to_file_offset(export_dir.VirtualAddress);
    if (export_offset == 0xFFFFFFFF || export_offset + sizeof(IMAGE_EXPORT_DIRECTORY) > raw_bytes_.size()) {
        return;
    }

    const auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(raw_bytes_.data() + export_offset);

    uint32_t funcs_offset = rva_to_file_offset(exp->AddressOfFunctions);
    uint32_t names_offset = rva_to_file_offset(exp->AddressOfNames);
    uint32_t ords_offset  = rva_to_file_offset(exp->AddressOfNameOrdinals);

    if (funcs_offset == 0xFFFFFFFF) return;

    const auto* func_rvas = reinterpret_cast<const uint32_t*>(raw_bytes_.data() + funcs_offset);
    const auto* name_rvas = (names_offset != 0xFFFFFFFF) ? reinterpret_cast<const uint32_t*>(raw_bytes_.data() + names_offset) : nullptr;
    const auto* ords      = (ords_offset != 0xFFFFFFFF)  ? reinterpret_cast<const uint16_t*>(raw_bytes_.data() + ords_offset)  : nullptr;

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        if (!name_rvas || !ords) break;

        uint32_t name_rva = name_rvas[i];
        uint32_t name_file_offset = rva_to_file_offset(name_rva);
        if (name_file_offset == 0xFFFFFFFF || name_file_offset >= raw_bytes_.size()) continue;

        const char* func_name = reinterpret_cast<const char*>(raw_bytes_.data() + name_file_offset);
        uint16_t ordinal_index = ords[i];

        if (ordinal_index < exp->NumberOfFunctions) {
            uint32_t func_rva = func_rvas[ordinal_index];

            ExportSymbol sym;
            sym.name = func_name;
            sym.ordinal = exp->Base + ordinal_index;
            sym.rva = func_rva;
            sym.va = image_base_ + func_rva;

            rva_to_export_index_[func_rva] = exports_.size();
            exports_.push_back(std::move(sym));
        }
    }
}

#pragma pack(push, 1)
struct CV_INFO_PDB70 {
    DWORD CvSignature; // 'RSDS'
    GUID  Signature;   // GUID
    DWORD Age;         // Age
    char  PdbFileName[1]; // Null-terminated string
};
#pragma pack(pop)

void PEFile::parse_exception_directory(const IMAGE_NT_HEADERS64* nt_hdrs) {
    runtime_functions_.clear();
    const auto& dir = nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return;

    uint32_t offset = rva_to_file_offset(dir.VirtualAddress);
    if (offset == 0 || offset + dir.Size > raw_bytes_.size()) return;

    const size_t count = dir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    const auto* entries = reinterpret_cast<const IMAGE_RUNTIME_FUNCTION_ENTRY*>(raw_bytes_.data() + offset);

    runtime_functions_.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        const auto& entry = entries[i];
        if (entry.BeginAddress == 0 || entry.EndAddress <= entry.BeginAddress) continue;

        RuntimeFunctionEntry rf;
        rf.begin_rva = entry.BeginAddress;
        rf.end_rva = entry.EndAddress;
        rf.unwind_info_rva = entry.UnwindInfoAddress;
        runtime_functions_.push_back(rf);
    }
}

void PEFile::parse_debug_directory(const IMAGE_NT_HEADERS64* nt_hdrs) {
    debug_codeview_info_.reset();
    const auto& dir = nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return;

    uint32_t offset = rva_to_file_offset(dir.VirtualAddress);
    if (offset == 0 || offset + dir.Size > raw_bytes_.size()) return;

    const size_t count = dir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    const auto* debug_dirs = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(raw_bytes_.data() + offset);

    for (size_t i = 0; i < count; ++i) {
        const auto& dbg = debug_dirs[i];
        if (dbg.Type == IMAGE_DEBUG_TYPE_CODEVIEW && dbg.SizeOfData >= sizeof(DWORD)) {
            uint32_t data_offset = dbg.PointerToRawData;
            if (data_offset == 0) {
                data_offset = rva_to_file_offset(dbg.AddressOfRawData);
            }
            if (data_offset == 0 || data_offset + dbg.SizeOfData > raw_bytes_.size()) continue;

            const uint8_t* cv_ptr = raw_bytes_.data() + data_offset;
            DWORD cv_sig = *reinterpret_cast<const DWORD*>(cv_ptr);
            // 0x53445352 is 'RSDS' in little endian
            if (cv_sig == 0x53445352 && dbg.SizeOfData >= sizeof(CV_INFO_PDB70)) {
                const auto* cv70 = reinterpret_cast<const CV_INFO_PDB70*>(cv_ptr);
                CodeViewDebugInfo info;
                info.guid = cv70->Signature;
                info.age = cv70->Age;

                size_t max_name_len = dbg.SizeOfData - offsetof(CV_INFO_PDB70, PdbFileName);
                std::string raw_path;
                for (size_t n = 0; n < max_name_len && cv70->PdbFileName[n] != '\0'; ++n) {
                    raw_path.push_back(cv70->PdbFileName[n]);
                }
                info.pdb_filename = raw_path;

                // Format GUID + Age string for Microsoft Symbol Server
                info.guid_age_string = std::format(
                    "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:X}",
                    info.guid.Data1, info.guid.Data2, info.guid.Data3,
                    info.guid.Data4[0], info.guid.Data4[1], info.guid.Data4[2], info.guid.Data4[3],
                    info.guid.Data4[4], info.guid.Data4[5], info.guid.Data4[6], info.guid.Data4[7],
                    info.age
                );

                debug_codeview_info_ = std::move(info);
                break;
            }
        }
    }
}

const ImportSymbol* PEFile::find_import_by_va(uint64_t va) const {
    auto it = iat_va_to_import_index_.find(va);
    if (it != iat_va_to_import_index_.end()) {
        return &imports_[it->second];
    }
    return nullptr;
}

const ImportSymbol* PEFile::find_import_by_rva(uint32_t rva) const {
    return find_import_by_va(image_base_ + rva);
}

const ExportSymbol* PEFile::find_export_by_rva(uint32_t rva) const {
    auto it = rva_to_export_index_.find(rva);
    if (it != rva_to_export_index_.end()) {
        return &exports_[it->second];
    }
    return nullptr;
}

bool PEFile::patch_byte(uint32_t file_offset, uint8_t new_val) {
    if (file_offset < raw_bytes_.size()) {
        raw_bytes_[file_offset] = new_val;
        return true;
    }
    return false;
}

bool PEFile::patch_bytes(uint32_t file_offset, std::span<const uint8_t> bytes) {
    if (file_offset + bytes.size() <= raw_bytes_.size()) {
        std::copy(bytes.begin(), bytes.end(), raw_bytes_.begin() + file_offset);
        return true;
    }
    return false;
}

bool PEFile::save_to_file(const std::filesystem::path& output_path) const {
    std::ofstream out(output_path, std::ios::binary);
    if (!out.is_open()) return false;
    out.write(reinterpret_cast<const char*>(raw_bytes_.data()), raw_bytes_.size());
    return out.good();
}

} // namespace agy::pe

