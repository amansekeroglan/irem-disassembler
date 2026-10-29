#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <span>
#include "../disasm/instruction.hpp"
#include "function_manager.hpp"

namespace agy::analysis {

enum class XrefType {
    Call,
    JumpConditional,
    JumpUnconditional,
    DataReadWrite
};

struct XrefEntry {
    uint64_t source_va{ 0 };
    uint32_t source_rva{ 0 };
    uint64_t target_va{ 0 };
    XrefType type{ XrefType::Call };
    std::string source_func_name;
    std::string instruction_text;
    std::string type_name() const {
        switch (type) {
        case XrefType::Call: return "Call";
        case XrefType::JumpConditional: return "Jump (Cond)";
        case XrefType::JumpUnconditional: return "Jump (Uncond)";
        case XrefType::DataReadWrite: return "Data Ref";
        default: return "Ref";
        }
    }
};

class XrefManager {
public:
    XrefManager() = default;

    // Builds the full cross-reference database from decoded instructions
    void build_xrefs(
        const std::vector<disasm::Instruction>& instructions,
        FunctionManager& function_manager
    );

    // Queries references to a specific VA
    const std::vector<XrefEntry>* get_xrefs_to(uint64_t target_va) const;
    size_t get_xref_count(uint64_t target_va) const;

    void clear() {
        xrefs_to_target_.clear();
    }

private:
    // target_va -> list of callers/referrers
    std::unordered_map<uint64_t, std::vector<XrefEntry>> xrefs_to_target_;
};

} // namespace agy::analysis

