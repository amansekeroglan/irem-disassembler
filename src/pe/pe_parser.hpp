#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <span>
#include <expected>
#include <filesystem>

namespace agy::pe {

struct SectionInfo {
    std::string name;
    uint32_t virtual_size{ 0 };
    uint32_t virtual_address{ 0 }; // RVA
    uint32_t raw_size{ 0 };
    uint32_t raw_offset{ 0 };      // File Offset
    uint32_t characteristics{ 0 };
    double entropy{ 0.0 };         // 0.0 to 8.0
    bool is_executable{ false };
    bool is_readable{ false };
    bool is_writable{ false };
};

struct ImportSymbol {
    std::string dll_name;
    std::string symbol_name;
    uint16_t ordinal{ 0 };
    bool is_by_ordinal{ false };
    uint32_t iat_rva{ 0 };          // Thunk RVA where loader places function pointer
    uint64_t iat_va{ 0 };           // ImageBase + iat_rva
};

struct ExportSymbol {
    std::string name;
    uint32_t ordinal{ 0 };
    uint32_t rva{ 0 };
    uint64_t va{ 0 };
};

struct SecurityFlags {
    bool aslr{ false };             // DYNAMIC_BASE
    bool dep_nx{ false };           // NX_COMPAT
    bool cfg{ false };              // GUARD_CF (Control Flow Guard)
    bool high_entropy_va{ false };  // HIGH_ENTROPY_VA (64-bit ASLR)
    bool seh{ false };              // NO_SEH (false means SEH enabled)
};

struct RuntimeFunctionEntry {
    uint32_t begin_rva{ 0 };
    uint32_t end_rva{ 0 };
    uint32_t unwind_info_rva{ 0 };
};

struct CodeViewDebugInfo {
    std::string pdb_filename;
    GUID guid{};
    uint32_t age{ 0 };
    std::string guid_age_string; // Format: GUID (hex uppercase) + Age (hex uppercase)
};

struct PEParseError {
    std::string message;
};

class PEFile {
public:
    static std::expected<PEFile, PEParseError> load_from_file(const std::filesystem::path& path);
    static std::expected<PEFile, PEParseError> load_from_memory(std::vector<uint8_t> buffer, const std::string& source_name = "");

    // Path & Raw buffer
    const std::filesystem::path& get_path() const { return file_path_; }
    const std::vector<uint8_t>& get_raw_bytes() const { return raw_bytes_; }
    std::vector<uint8_t>& get_raw_bytes_mut() { return raw_bytes_; } // For patching

    // Headers & Metadata
    uint64_t get_image_base() const { return image_base_; }
    uint32_t get_entry_point_rva() const { return entry_point_rva_; }
    uint64_t get_entry_point_va() const { return image_base_ + entry_point_rva_; }
    uint32_t get_section_alignment() const { return section_alignment_; }
    uint32_t get_file_alignment() const { return file_alignment_; }
    uint32_t get_size_of_image() const { return size_of_image_; }
    uint16_t get_subsystem() const { return subsystem_; }
    std::string get_subsystem_name() const;
    bool is_driver() const;
    bool is_uefi() const;
    const SecurityFlags& get_security_flags() const { return security_flags_; }

    // Sections
    const std::vector<SectionInfo>& get_sections() const { return sections_; }
    const SectionInfo* find_section_by_rva(uint32_t rva) const;
    const SectionInfo* find_section_by_name(std::string_view name) const;
    const SectionInfo* get_code_section() const;

    // Address Conversions
    uint32_t rva_to_file_offset(uint32_t rva) const;
    uint32_t file_offset_to_rva(uint32_t offset) const;
    uint64_t rva_to_va(uint32_t rva) const { return image_base_ + rva; }
    uint32_t va_to_rva(uint64_t va) const { return static_cast<uint32_t>(va - image_base_); }

    // Safe span access
    std::span<const uint8_t> get_section_bytes(const SectionInfo& section) const;
    std::span<const uint8_t> get_bytes_at_rva(uint32_t rva, size_t max_len) const;

    // Imports & Exports
    const std::vector<ImportSymbol>& get_imports() const { return imports_; }
    const std::vector<ExportSymbol>& get_exports() const { return exports_; }
    const ImportSymbol* find_import_by_va(uint64_t va) const;
    const ImportSymbol* find_import_by_rva(uint32_t rva) const;
    const ExportSymbol* find_export_by_rva(uint32_t rva) const;

    // x64 Exception Directory (.pdata) & Debug / PDB Info
    const std::vector<RuntimeFunctionEntry>& get_runtime_functions() const { return runtime_functions_; }
    const std::optional<CodeViewDebugInfo>& get_debug_codeview_info() const { return debug_codeview_info_; }

    // Patching support
    bool patch_byte(uint32_t file_offset, uint8_t new_val);
    bool patch_bytes(uint32_t file_offset, std::span<const uint8_t> bytes);
    bool save_to_file(const std::filesystem::path& output_path) const;

private:
    PEFile() = default;
    bool parse_internal(PEParseError& err);
    void calculate_section_entropies();
    void parse_imports();
    void parse_exports();
    void parse_exception_directory(const IMAGE_NT_HEADERS64* nt_hdrs);
    void parse_debug_directory(const IMAGE_NT_HEADERS64* nt_hdrs);

private:
    std::filesystem::path file_path_;
    std::vector<uint8_t> raw_bytes_;

    uint64_t image_base_{ 0 };
    uint32_t entry_point_rva_{ 0 };
    uint32_t section_alignment_{ 0 };
    uint32_t file_alignment_{ 0 };
    uint32_t size_of_image_{ 0 };
    uint16_t subsystem_{ 0 };
    SecurityFlags security_flags_{};

    std::vector<SectionInfo> sections_;
    std::vector<ImportSymbol> imports_;
    std::vector<ExportSymbol> exports_;
    std::vector<RuntimeFunctionEntry> runtime_functions_;
    std::optional<CodeViewDebugInfo> debug_codeview_info_;

    // Fast lookups
    std::unordered_map<uint64_t, size_t> iat_va_to_import_index_;
    std::unordered_map<uint32_t, size_t> rva_to_export_index_;
};

// Shannon Entropy utility
double calculate_shannon_entropy(std::span<const uint8_t> data);

} // namespace agy::pe

