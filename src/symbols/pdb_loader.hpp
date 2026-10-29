#pragma once

#include <windows.h>
#include <dbghelp.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <optional>
#include <filesystem>
#include "../pe/pe_parser.hpp"

namespace agy::symbols {

struct SymbolInfo {
    uint64_t va{ 0 };
    uint32_t rva{ 0 };
    std::string name;
    uint32_t size{ 0 };
};

class PdbLoader {
public:
    PdbLoader();
    ~PdbLoader();

    // Initializes DbgHelp subsystem
    bool initialize();
    void cleanup();

    // Loads local PDB file for the given binary
    bool load_pdb_file(
        const std::filesystem::path& pdb_path,
        uint64_t image_base,
        uint32_t image_size
    );

    // Attempts to auto-discover matching PDB in same directory as binary
    bool auto_load_matching_pdb(
        const std::filesystem::path& binary_path,
        uint64_t image_base,
        uint32_t image_size
    );

    // Downloads PDB from Microsoft Symbol Server and loads it
    bool download_and_load_from_symbol_server(
        const pe::PEFile& pe,
        const std::filesystem::path& download_dir,
        std::string& out_status
    );

    // Fast symbol query
    const std::string* find_symbol_name(uint64_t va) const;
    const std::unordered_map<uint64_t, std::string>& get_all_symbols() const { return symbols_; }

    bool is_loaded() const { return is_loaded_; }
    size_t get_symbol_count() const { return symbols_.size(); }
    const std::string& get_loaded_pdb_name() const { return loaded_pdb_name_; }

    void unload();

private:
    void enumerate_symbols(uint64_t base_address);

private:
    HANDLE process_handle_{ nullptr };
    bool initialized_{ false };
    bool is_loaded_{ false };
    uint64_t loaded_base_{ 0 };
    std::string loaded_pdb_name_;

    // va -> symbol name
    std::unordered_map<uint64_t, std::string> symbols_;
};

} // namespace agy::symbols

