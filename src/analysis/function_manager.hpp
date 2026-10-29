#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <span>
#include <optional>
#include "../pe/pe_parser.hpp"
#include "../disasm/instruction.hpp"

namespace agy::analysis {

struct FunctionInfo {
    uint64_t start_va{ 0 };
    uint32_t start_rva{ 0 };
    uint32_t length{ 0 };
    std::string name;
    bool is_from_pdata{ false };
    bool is_export{ false };
    bool is_entry_point{ false };
    bool has_custom_name{ false };
    size_t xref_count{ 0 };
};

class FunctionManager {
public:
    FunctionManager() = default;

    // Discovers functions in the active section and binary
    void discover_functions(
        const pe::PEFile& pe,
        const std::string& active_section_name,
        const std::vector<disasm::Instruction>& instructions
    );

    // Apply symbol names from PDB or external resolver
    void apply_symbol_name(uint64_t va, const std::string& name);

    // Fast lookups
    const FunctionInfo* find_function_by_va(uint64_t va) const;
    const FunctionInfo* find_enclosing_function(uint64_t va) const;
    bool is_function_start(uint64_t va) const;

    const std::vector<FunctionInfo>& get_functions() const { return functions_; }
    std::vector<FunctionInfo>& get_functions_mut() { return functions_; }

    void clear() {
        functions_.clear();
        va_to_function_index_.clear();
    }

private:
    std::vector<FunctionInfo> functions_;
    std::unordered_map<uint64_t, size_t> va_to_function_index_;
};

} // namespace agy::analysis

