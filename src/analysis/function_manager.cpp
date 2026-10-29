#include "function_manager.hpp"
#include <algorithm>
#include <format>
#include <set>

namespace agy::analysis {

void FunctionManager::discover_functions(
    const pe::PEFile& pe,
    const std::string& active_section_name,
    const std::vector<disasm::Instruction>& instructions
) {
    clear();

    const auto* active_sec = pe.find_section_by_name(active_section_name);
    if (!active_sec) return;

    uint32_t sec_start_rva = active_sec->virtual_address;
    uint32_t sec_end_rva = sec_start_rva + active_sec->virtual_size;
    uint64_t image_base = pe.get_image_base();

    // Map of discovered start RVAs to FunctionInfo
    std::unordered_map<uint32_t, FunctionInfo> candidate_map;

    auto add_or_update = [&](uint32_t rva, uint32_t len, bool from_pdata, const std::string& default_name) {
        if (rva < sec_start_rva || rva >= sec_end_rva) return;

        auto it = candidate_map.find(rva);
        if (it == candidate_map.end()) {
            FunctionInfo fn;
            fn.start_rva = rva;
            fn.start_va = image_base + rva;
            fn.length = len;
            fn.is_from_pdata = from_pdata;
            fn.name = default_name.empty() ? std::format("sub_{:X}", fn.start_va) : default_name;
            candidate_map[rva] = std::move(fn);
        } else {
            if (from_pdata) {
                it->second.is_from_pdata = true;
                if (len > 0) it->second.length = len;
            }
            if (!default_name.empty() && !it->second.has_custom_name) {
                it->second.name = default_name;
            }
        }
    };

    // 1. Process Windows x64 .pdata (RUNTIME_FUNCTION)
    for (const auto& rf : pe.get_runtime_functions()) {
        if (rf.begin_rva >= sec_start_rva && rf.begin_rva < sec_end_rva) {
            uint32_t len = (rf.end_rva > rf.begin_rva) ? (rf.end_rva - rf.begin_rva) : 0;
            add_or_update(rf.begin_rva, len, true, "");
        }
    }

    // 2. Process Entry Point
    uint32_t ep_rva = pe.get_entry_point_rva();
    if (ep_rva >= sec_start_rva && ep_rva < sec_end_rva) {
        add_or_update(ep_rva, 0, false, "EntryPoint");
        candidate_map[ep_rva].is_entry_point = true;
        candidate_map[ep_rva].has_custom_name = true;
    }

    // 3. Process Exports
    for (const auto& exp : pe.get_exports()) {
        if (exp.rva >= sec_start_rva && exp.rva < sec_end_rva) {
            add_or_update(exp.rva, 0, false, exp.name);
            candidate_map[exp.rva].is_export = true;
            candidate_map[exp.rva].has_custom_name = true;
        }
    }

    // 4. Scan instructions for CALL targets and prologue heuristics
    for (size_t i = 0; i < instructions.size(); ++i) {
        const auto& ins = instructions[i];

        // CALL targets
        if (ins.is_call && ins.branch_target_va != 0) {
            uint64_t target_va = ins.branch_target_va;
            uint32_t target_rva = pe.va_to_rva(target_va);
            if (target_rva >= sec_start_rva && target_rva < sec_end_rva) {
                add_or_update(target_rva, 0, false, "");
            }
        }

        // Prologue heuristics:
        // Pattern 1: push rbp; mov rbp, rsp (55 48 89 E5)
        // Pattern 2: sub rsp, XX (48 83 EC xx or 48 81 EC xx xx xx xx)
        std::string op_str = ins.format_operands();
        bool is_prologue = false;
        if (ins.mnemonic == "push" && op_str == "rbp") {
            is_prologue = true;
        } else if (ins.mnemonic == "sub" && op_str.starts_with("rsp,")) {
            // Check if preceded by ret/int3/nop
            if (i > 0) {
                const auto& prev = instructions[i - 1];
                if (prev.mnemonic == "ret" || prev.mnemonic == "int3" || prev.mnemonic == "nop") {
                    is_prologue = true;
                }
            }
        }

        if (is_prologue) {
            add_or_update(ins.rva, 0, false, "");
        }
    }

    // Flatten and sort by RVA
    functions_.reserve(candidate_map.size());
    for (auto& [rva, fn] : candidate_map) {
        functions_.push_back(std::move(fn));
    }

    std::sort(functions_.begin(), functions_.end(), [](const FunctionInfo& a, const FunctionInfo& b) {
        return a.start_rva < b.start_rva;
    });

    // Compute approximate lengths for functions without explicit .pdata bounds
    for (size_t i = 0; i < functions_.size(); ++i) {
        if (functions_[i].length == 0) {
            if (i + 1 < functions_.size()) {
                functions_[i].length = functions_[i + 1].start_rva - functions_[i].start_rva;
            } else {
                functions_[i].length = sec_end_rva - functions_[i].start_rva;
            }
        }
    }

    // Build fast lookup index
    for (size_t i = 0; i < functions_.size(); ++i) {
        va_to_function_index_[functions_[i].start_va] = i;
    }
}

void FunctionManager::apply_symbol_name(uint64_t va, const std::string& name) {
    auto it = va_to_function_index_.find(va);
    if (it != va_to_function_index_.end()) {
        functions_[it->second].name = name;
        functions_[it->second].has_custom_name = true;
    }
}

const FunctionInfo* FunctionManager::find_function_by_va(uint64_t va) const {
    auto it = va_to_function_index_.find(va);
    if (it != va_to_function_index_.end()) {
        return &functions_[it->second];
    }
    return nullptr;
}

const FunctionInfo* FunctionManager::find_enclosing_function(uint64_t va) const {
    if (functions_.empty()) return nullptr;

    // Binary search upper_bound
    auto it = std::upper_bound(functions_.begin(), functions_.end(), va,
        [](uint64_t target_va, const FunctionInfo& fn) {
            return target_va < fn.start_va;
        }
    );

    if (it == functions_.begin()) return nullptr;

    const auto& candidate = *(--it);
    if (va >= candidate.start_va && va < candidate.start_va + candidate.length) {
        return &candidate;
    }

    return nullptr;
}

bool FunctionManager::is_function_start(uint64_t va) const {
    return va_to_function_index_.contains(va);
}

} // namespace agy::analysis
