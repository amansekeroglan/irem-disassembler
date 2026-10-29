#pragma once

#include "irem_engines.h"
#include "../disasm/instruction.hpp"
#include "../pe/pe_parser.hpp"
#include "../analysis/function_manager.hpp"

#include <vector>
#include <string>
#include <unordered_map>
#include <memory>

namespace agy::engines {

/* Converts C++ Instruction vector to C flat instruction vector */
std::vector<IremFlatInstruction> flatten_instructions(
    const std::vector<disasm::Instruction>& instructions
);

/* Converts PEFile sections to C section descriptor vector */
std::vector<IremSectionDesc> flatten_sections(const pe::PEFile& pe);

/* Full Analysis Session Container */
struct AnalysisSession {
    IremStringDatabase string_db;
    std::vector<IremJumpTable> jump_tables;
    std::vector<IremCallSiteAnalysis> call_analyses;
    std::unordered_map<uint64_t, IremStackFrame> stack_frames;
    std::unordered_map<uint64_t, IremCFG> function_cfgs;
    IremStructAnnotationDB struct_db;
    IremHashMatchDB hash_db;

    AnalysisSession() {
        irem_strings_init(&string_db);
        irem_struct_db_init(&struct_db);
        irem_hash_db_init(&hash_db);
    }

    ~AnalysisSession() {
        irem_strings_free(&string_db);
        irem_struct_db_free(&struct_db);
        irem_hash_db_free(&hash_db);
        for (auto& [va, cfg] : function_cfgs) {
            irem_cfg_free(&cfg);
        }
    }

    /* Move-only semantics */
    AnalysisSession(const AnalysisSession&) = delete;
    AnalysisSession& operator=(const AnalysisSession&) = delete;
    AnalysisSession(AnalysisSession&&) noexcept = default;
    AnalysisSession& operator=(AnalysisSession&&) noexcept = default;
};

/* Executes all analysis engines on the current binary and decoded instructions */
std::unique_ptr<AnalysisSession> run_analysis(
    const pe::PEFile& pe,
    const std::string& active_section_name,
    const std::vector<disasm::Instruction>& instructions,
    const analysis::FunctionManager& function_manager
);

/* Annotates instruction comments with string references and WinAPI flags */
void apply_analysis_annotations(
    std::vector<disasm::Instruction>& instructions,
    const AnalysisSession& session,
    const pe::PEFile& pe
);

} // namespace agy::engines

