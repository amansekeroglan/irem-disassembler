#include "engines_bridge.hpp"
#include <algorithm>
#include <format>
#include <cstring>

namespace agy::engines {

std::vector<IremFlatInstruction> flatten_instructions(
    const std::vector<disasm::Instruction>& instructions
) {
    std::vector<IremFlatInstruction> flat;
    flat.reserve(instructions.size());

    for (const auto& ins : instructions) {
        IremFlatInstruction fi;
        memset(&fi, 0, sizeof(fi));

        fi.va = ins.va;
        fi.rva = ins.rva;
        fi.file_offset = ins.file_offset;
        fi.length = ins.length;

        size_t raw_len = (std::min)((size_t)ins.length, (size_t)15);
        if (!ins.raw_bytes.empty()) {
            memcpy(fi.raw_bytes, ins.raw_bytes.data(), (std::min)(ins.raw_bytes.size(), raw_len));
        }

        strncpy_s(fi.mnemonic, sizeof(fi.mnemonic), ins.mnemonic.c_str(), sizeof(fi.mnemonic) - 1);

        fi.is_jump = ins.is_jump;
        fi.is_conditional_jump = ins.is_conditional_jump;
        fi.is_call = ins.is_call;
        fi.is_ret = ins.is_ret;
        fi.branch_target_va = ins.branch_target_va;

        fi.op_count = (uint8_t)(std::min)(ins.operands.size(), (size_t)4);
        for (uint8_t op_i = 0; op_i < fi.op_count; ++op_i) {
            const auto& src_op = ins.operands[op_i];
            auto& dst_op = fi.ops[op_i];

            switch (src_op.type) {
            case disasm::OperandType::Register:
                dst_op.type = IREM_OP_REG;
                dst_op.reg = static_cast<IremReg>(src_op.reg);
                break;
            case disasm::OperandType::Immediate:
                dst_op.type = IREM_OP_IMM;
                dst_op.imm = src_op.imm;
                dst_op.imm_signed = src_op.imm_signed;
                break;
            case disasm::OperandType::Memory:
                dst_op.type = IREM_OP_MEM;
                dst_op.mem.base = static_cast<IremReg>(src_op.mem.base);
                dst_op.mem.index = static_cast<IremReg>(src_op.mem.index);
                dst_op.mem.scale = src_op.mem.scale;
                dst_op.mem.disp = src_op.mem.disp;
                dst_op.mem.size_bytes = src_op.mem.size_bytes;
                dst_op.mem.is_rip_relative = src_op.mem.is_rip_relative;
                dst_op.mem.resolved_target_va = src_op.mem.resolved_target_va;
                switch (src_op.mem.segment_override) {
                case disasm::Reg::GS: dst_op.mem.segment_override = IREM_SEG_GS; break;
                case disasm::Reg::FS: dst_op.mem.segment_override = IREM_SEG_FS; break;
                case disasm::Reg::CS: dst_op.mem.segment_override = IREM_SEG_CS; break;
                case disasm::Reg::DS: dst_op.mem.segment_override = IREM_SEG_DS; break;
                case disasm::Reg::SS: dst_op.mem.segment_override = IREM_SEG_SS; break;
                case disasm::Reg::ES: dst_op.mem.segment_override = IREM_SEG_ES; break;
                default: dst_op.mem.segment_override = IREM_SEG_NONE; break;
                }
                break;
            default:
                dst_op.type = IREM_OP_NONE;
                break;
            }
        }

        flat.push_back(fi);
    }

    return flat;
}

std::vector<IremSectionDesc> flatten_sections(const pe::PEFile& pe) {
    std::vector<IremSectionDesc> sec_descs;
    const auto& sections = pe.get_sections();
    sec_descs.reserve(sections.size());

    for (const auto& sec : sections) {
        IremSectionDesc sd;
        memset(&sd, 0, sizeof(sd));
        strncpy_s(sd.name, sizeof(sd.name), sec.name.c_str(), sizeof(sd.name) - 1);
        sd.virtual_size = sec.virtual_size;
        sd.virtual_address = sec.virtual_address;
        sd.raw_size = sec.raw_size;
        sd.raw_offset = sec.raw_offset;
        sd.characteristics = sec.characteristics;
        sd.is_executable = sec.is_executable;
        sd.is_readable = sec.is_readable;
        sd.is_writable = sec.is_writable;
        sec_descs.push_back(sd);
    }

    return sec_descs;
}

std::unique_ptr<AnalysisSession> run_analysis(
    const pe::PEFile& pe,
    const std::string& active_section_name,
    const std::vector<disasm::Instruction>& instructions,
    const analysis::FunctionManager& function_manager
) {
    (void)active_section_name;
    auto session = std::make_unique<AnalysisSession>();

    auto flat_instructions = flatten_instructions(instructions);
    auto flat_sections = flatten_sections(pe);

    const auto& raw_bytes = pe.get_raw_bytes();
    if (raw_bytes.empty()) return session;

    /* 1. String Scanner Engine */
    irem_strings_scan_binary(
        &session->string_db,
        raw_bytes.data(),
        raw_bytes.size(),
        pe.get_image_base(),
        flat_sections.data(),
        flat_sections.size(),
        4
    );

    if (!flat_instructions.empty()) {
        irem_strings_build_xrefs(&session->string_db, flat_instructions.data(), flat_instructions.size());
    }

    /* 2. Fastcall Analyzer Engine */
    if (!flat_instructions.empty()) {
        session->call_analyses.resize(flat_instructions.size());
        int total_calls = irem_fastcall_analyze_all_calls(
            flat_instructions.data(),
            flat_instructions.size(),
            session->call_analyses.data(),
            session->call_analyses.size()
        );
        session->call_analyses.resize(total_calls);
    }

    /* 3. Jump Table Resolver Engine */
    if (!flat_instructions.empty()) {
        std::vector<IremJumpTable> raw_tables(128);
        int total_tables = irem_jumptable_scan_all(
            flat_instructions.data(),
            flat_instructions.size(),
            raw_bytes.data(),
            raw_bytes.size(),
            pe.get_image_base(),
            flat_sections.data(),
            flat_sections.size(),
            raw_tables.data(),
            raw_tables.size()
        );
        raw_tables.resize(total_tables);
        session->jump_tables = std::move(raw_tables);
    }

    /* 4. UNWIND_INFO Parser Engine */
    for (const auto& rf : pe.get_runtime_functions()) {
        IremStackFrame frame;
        if (irem_unwind_parse_function(
            raw_bytes.data(),
            raw_bytes.size(),
            pe.get_image_base(),
            rf.begin_rva,
            rf.end_rva,
            rf.unwind_info_rva,
            flat_sections.data(),
            flat_sections.size(),
            &frame
        )) {
            session->stack_frames[frame.func_va] = frame;
        }
    }

    /* 5. Basic Block & CFG Builder Engine */
    if (!flat_instructions.empty()) {
        for (const auto& fn : function_manager.get_functions()) {
            if (fn.length == 0) continue;

            /* Binary search for start_idx using std::lower_bound (O(log N)) */
            auto it_start = std::lower_bound(
                flat_instructions.begin(), flat_instructions.end(), fn.start_va,
                [](const IremFlatInstruction& ins, uint64_t target_va) {
                    return ins.va < target_va;
                }
            );

            if (it_start != flat_instructions.end() && it_start->va < fn.start_va + fn.length) {
                auto it_end = std::lower_bound(
                    it_start, flat_instructions.end(), fn.start_va + fn.length,
                    [](const IremFlatInstruction& ins, uint64_t target_va) {
                        return ins.va < target_va;
                    }
                );

                size_t start_idx = std::distance(flat_instructions.begin(), it_start);
                size_t count = std::distance(it_start, it_end);

                if (count > 0) {
                    IremCFG cfg;
                    irem_cfg_init(&cfg);
                    if (irem_cfg_build(&cfg, fn.start_va, fn.length, &flat_instructions[start_idx], count)) {
                        session->function_cfgs[fn.start_va] = cfg;
                    }
                }
            }
        }
    }

    /* 6. TEB / PEB & Kernel Struct Resolver Engine */
    if (!flat_instructions.empty()) {
        irem_resolve_struct_accesses(
            flat_instructions.data(),
            flat_instructions.size(),
            pe.is_driver(),
            &session->struct_db
        );
    }

    /* 7. API Hash / ROR13 Resolver Engine */
    if (!flat_instructions.empty()) {
        irem_hash_scan_instructions(
            flat_instructions.data(),
            flat_instructions.size(),
            &session->hash_db
        );
    }

    return session;
}

void apply_analysis_annotations(
    std::vector<disasm::Instruction>& instructions,
    const AnalysisSession& session,
    const pe::PEFile& pe
) {
    /* 1. Map Call analyses for fast lookup by call_site_va */
    std::unordered_map<uint64_t, const IremCallSiteAnalysis*> call_map;
    for (const auto& ca : session.call_analyses) {
        call_map[ca.call_site_va] = &ca;
    }

    /* 2. Map Jump tables for fast lookup by switch_jmp_va */
    std::unordered_map<uint64_t, const IremJumpTable*> jmp_table_map;
    for (const auto& jt : session.jump_tables) {
        jmp_table_map[jt.switch_jmp_va] = &jt;
    }

    /* 3. Map TEB / PEB struct annotations by va */
    std::unordered_map<uint64_t, const IremStructAnnotation*> struct_map;
    for (int s = 0; s < session.struct_db.count; ++s) {
        struct_map[session.struct_db.annotations[s].va] = &session.struct_db.annotations[s];
    }

    /* 4. Map API Hash matches by va */
    std::unordered_map<uint64_t, const IremHashMatch*> hash_map;
    for (int h = 0; h < session.hash_db.count; ++h) {
        hash_map[session.hash_db.matches[h].va] = &session.hash_db.matches[h];
    }

    for (auto& ins : instructions) {
        std::string extra_comment;

        /* String references annotation */
        const IremStringXref* str_xref = irem_strings_find_xref_by_code_va(&session.string_db, ins.va);
        if (str_xref && str_xref->string_index < session.string_db.string_count) {
            const auto& str_entry = session.string_db.strings[str_xref->string_index];
            std::string prefix = (str_entry.encoding == IREM_STR_UTF16LE) ? "L\"" : "\"";
            extra_comment = std::format("{}{}\"", prefix, str_entry.preview);
        }

        /* Jump Table annotation */
        auto jt_it = jmp_table_map.find(ins.va);
        if (jt_it != jmp_table_map.end()) {
            const auto* jt = jt_it->second;
            std::string jt_str = std::format("[switch-case: {} cases, table @ 0x{:X}]", jt->case_count, jt->table_va);
            extra_comment = extra_comment.empty() ? jt_str : (extra_comment + " " + jt_str);
        }

        /* WinAPI parameter flag resolution */
        if (ins.is_call) {
            const auto* imp = pe.find_import_by_va(ins.branch_target_va);
            if (!imp) {
                imp = pe.find_import_by_rva(pe.va_to_rva(ins.branch_target_va));
            }

            if (imp) {
                auto ca_it = call_map.find(ins.va);
                if (ca_it != call_map.end()) {
                    const auto* ca = ca_it->second;
                    for (int s = 0; s < ca->param_count; ++s) {
                        const auto& param = ca->params[s];
                        if (param.is_set && param.src_type == IREM_PARAM_SRC_IMM) {
                            IremResolvedFlag resolved;
                            if (irem_winapi_resolve_param(imp->symbol_name.c_str(), s, param.imm_val, &resolved)) {
                                std::string flag_tag = std::format("{}: {}", resolved.param_name, resolved.resolved_str);
                                if (resolved.risk_level >= 3) {
                                    flag_tag += " [CRITICAL]";
                                } else if (resolved.risk_level >= 2) {
                                    flag_tag += " [RISK]";
                                }
                                extra_comment = extra_comment.empty() ? flag_tag : (extra_comment + " | " + flag_tag);
                            }
                        }
                    }
                }
            }
        }

        /* TEB / PEB / KPCR struct access annotation */
        auto st_it = struct_map.find(ins.va);
        if (st_it != struct_map.end()) {
            std::string st_str = st_it->second->annotation;
            extra_comment = extra_comment.empty() ? st_str : (extra_comment + " | " + st_str);
        }

        /* API Hash match annotation */
        auto hash_it = hash_map.find(ins.va);
        if (hash_it != hash_map.end()) {
            std::string h_str = hash_it->second->annotation;
            extra_comment = extra_comment.empty() ? h_str : (extra_comment + " | " + h_str);
        }

        /* Append to instruction comment if not empty */
        if (!extra_comment.empty()) {
            if (ins.comment.empty()) {
                ins.comment = extra_comment;
            } else {
                ins.comment += " | " + extra_comment;
            }
        }
    }
}

} // namespace agy::engines
