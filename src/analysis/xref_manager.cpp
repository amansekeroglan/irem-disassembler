#include "xref_manager.hpp"
#include <format>

namespace agy::analysis {

void XrefManager::build_xrefs(
    const std::vector<disasm::Instruction>& instructions,
    FunctionManager& function_manager
) {
    clear();

    for (const auto& ins : instructions) {
        if (ins.branch_target_va == 0) continue;

        XrefType type = XrefType::Call;
        if (ins.is_call) {
            type = XrefType::Call;
        } else if (ins.is_jump) {
            type = XrefType::JumpUnconditional;
        } else if (ins.is_conditional_jump) {
            type = XrefType::JumpConditional;
        } else {
            continue;
        }

        XrefEntry entry;
        entry.source_va = ins.va;
        entry.source_rva = ins.rva;
        entry.target_va = ins.branch_target_va;
        entry.type = type;
        entry.instruction_text = std::format("{} {}", ins.mnemonic, ins.format_operands());

        const auto* enclosing_fn = function_manager.find_enclosing_function(ins.va);
        if (enclosing_fn) {
            uint64_t offset = ins.va - enclosing_fn->start_va;
            entry.source_func_name = std::format("{}+0x{:X}", enclosing_fn->name, offset);
        } else {
            entry.source_func_name = std::format("0x{:X}", ins.va);
        }

        xrefs_to_target_[ins.branch_target_va].push_back(std::move(entry));
    }

    // Update xref_count in FunctionManager
    for (auto& fn : function_manager.get_functions_mut()) {
        fn.xref_count = get_xref_count(fn.start_va);
    }
}

const std::vector<XrefEntry>* XrefManager::get_xrefs_to(uint64_t target_va) const {
    auto it = xrefs_to_target_.find(target_va);
    if (it != xrefs_to_target_.end()) {
        return &it->second;
    }
    return nullptr;
}

size_t XrefManager::get_xref_count(uint64_t target_va) const {
    auto it = xrefs_to_target_.find(target_va);
    if (it != xrefs_to_target_.end()) {
        return it->second.size();
    }
    return 0;
}

} // namespace agy::analysis
