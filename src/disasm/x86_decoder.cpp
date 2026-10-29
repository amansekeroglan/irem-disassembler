#include "x86_decoder.hpp"
#include <algorithm>
#include <format>

namespace agy::disasm {

Reg X86Decoder::get_register(uint8_t index, uint8_t size_bytes, bool has_rex) {
    index &= 0x0F; // 0 to 15

    if (size_bytes == 8) {
        static constexpr Reg regs64[] = {
            Reg::RAX, Reg::RCX, Reg::RDX, Reg::RBX, Reg::RSP, Reg::RBP, Reg::RSI, Reg::RDI,
            Reg::R8,  Reg::R9,  Reg::R10, Reg::R11, Reg::R12, Reg::R13, Reg::R14, Reg::R15
        };
        return regs64[index];
    }
    if (size_bytes == 4) {
        static constexpr Reg regs32[] = {
            Reg::EAX, Reg::ECX, Reg::EDX, Reg::EBX, Reg::ESP, Reg::EBP, Reg::ESI, Reg::EDI,
            Reg::R8D, Reg::R9D, Reg::R10D, Reg::R11D, Reg::R12D, Reg::R13D, Reg::R14D, Reg::R15D
        };
        return regs32[index];
    }
    if (size_bytes == 2) {
        static constexpr Reg regs16[] = {
            Reg::AX,  Reg::CX,  Reg::DX,  Reg::BX,  Reg::SP,  Reg::BP,  Reg::SI,  Reg::DI,
            Reg::R8W, Reg::R9W, Reg::R10W, Reg::R11W, Reg::R12W, Reg::R13W, Reg::R14W, Reg::R15W
        };
        return regs16[index];
    }
    if (size_bytes == 1) {
        if (has_rex) {
            static constexpr Reg regs8_rex[] = {
                Reg::AL,  Reg::CL,  Reg::DL,  Reg::BL,  Reg::SPL, Reg::BPL, Reg::SIL, Reg::DIL,
                Reg::R8B, Reg::R9B, Reg::R10B, Reg::R11B, Reg::R12B, Reg::R13B, Reg::R14B, Reg::R15B
            };
            return regs8_rex[index];
        } else {
            static constexpr Reg regs8_norex[] = {
                Reg::AL, Reg::CL, Reg::DL, Reg::BL, Reg::AH, Reg::CH, Reg::DH, Reg::BH,
                Reg::None, Reg::None, Reg::None, Reg::None, Reg::None, Reg::None, Reg::None, Reg::None
            };
            return regs8_norex[index & 0x07];
        }
    }
    return Reg::None;
}

Instruction X86Decoder::decode_instruction(
    std::span<const uint8_t> buffer,
    uint64_t va,
    uint32_t rva,
    uint32_t file_offset,
    const pe::PEFile* pe
) {
    Instruction ins;
    ins.va = va;
    ins.rva = rva;
    ins.file_offset = file_offset;

    if (buffer.empty()) {
        ins.length = 0;
        return ins;
    }

    size_t cursor = 0;
    auto read_u8 = [&]() -> uint8_t {
        return (cursor < buffer.size()) ? buffer[cursor++] : 0;
    };
    auto has_bytes = [&](size_t count) -> bool {
        return cursor + count <= buffer.size();
    };

    // 1. Prefixes
    bool op_size_override = false; // 0x66
    bool addr_size_override = false; // 0x67
    bool rep_prefix = false; // 0xF3
    bool repne_prefix = false; // 0xF2
    bool lock_prefix = false; // 0xF0
    Reg seg_override = Reg::None; // 0x65 (GS), 0x64 (FS), etc.

    bool has_rex = false;
    uint8_t rex_val = 0;
    bool rex_w = false, rex_r = false, rex_x = false, rex_b = false;

    while (has_bytes(1)) {
        uint8_t p = buffer[cursor];
        if (p == 0x66) { op_size_override = true; cursor++; }
        else if (p == 0x67) { addr_size_override = true; cursor++; }
        else if (p == 0xF3) { rep_prefix = true; cursor++; }
        else if (p == 0xF2) { repne_prefix = true; cursor++; }
        else if (p == 0xF0) { lock_prefix = true; cursor++; }
        else if (p == 0x65) { seg_override = Reg::GS; cursor++; }
        else if (p == 0x64) { seg_override = Reg::FS; cursor++; }
        else if (p == 0x2E) { seg_override = Reg::CS; cursor++; }
        else if (p == 0x36) { seg_override = Reg::SS; cursor++; }
        else if (p == 0x3E) { seg_override = Reg::DS; cursor++; }
        else if (p == 0x26) { seg_override = Reg::ES; cursor++; }
        else if ((p & 0xF0) == 0x40) { // REX prefix
            has_rex = true;
            rex_val = p;
            rex_w = (p & 0x08) != 0;
            rex_r = (p & 0x04) != 0;
            rex_x = (p & 0x02) != 0;
            rex_b = (p & 0x01) != 0;
            cursor++;
            break; // REX must be immediately before opcode
        }
        else {
            break;
        }
    }

    if (!has_bytes(1)) {
        // Fallback db
        ins.length = static_cast<uint8_t>((std::max)(cursor, size_t(1)));
        ins.mnemonic = "db";
        ins.operands.push_back(Operand{ OperandType::Immediate, Reg::None, buffer[0] });
        ins.raw_bytes.assign(buffer.begin(), buffer.begin() + ins.length);
        return ins;
    }

    // Default operand sizes
    uint8_t op_size = rex_w ? 8 : (op_size_override ? 2 : 4);

    // 2. Opcode
    uint8_t op = read_u8();
    bool is_two_byte = false;
    if (op == 0x0F) {
        if (!has_bytes(1)) {
            ins.length = static_cast<uint8_t>(cursor);
            ins.mnemonic = "db";
            ins.operands.push_back(Operand{ OperandType::Immediate, Reg::None, 0x0F });
            ins.raw_bytes.assign(buffer.begin(), buffer.begin() + ins.length);
            return ins;
        }
        is_two_byte = true;
        op = read_u8();
    }

    // ModR/M & SIB helper
    auto decode_modrm_mem = [&](uint8_t modrm_byte, uint8_t mem_size, Operand& out_op, size_t extra_imm_len = 0) -> bool {
        uint8_t mod = (modrm_byte >> 6) & 0x03;
        uint8_t rm  = modrm_byte & 0x07;

        if (mod == 3) { // Register
            out_op.type = OperandType::Register;
            out_op.reg = get_register(rm | (rex_b ? 8 : 0), mem_size, has_rex);
            return true;
        }

        out_op.type = OperandType::Memory;
        out_op.mem.size_bytes = mem_size;
        out_op.mem.segment_override = seg_override;

        if (mod == 0 && rm == 5) { // RIP-relative in 64-bit mode!
            if (!has_bytes(4)) return false;
            int32_t disp = static_cast<int32_t>(read_u8() | (read_u8() << 8) | (read_u8() << 16) | (read_u8() << 24));
            out_op.mem.is_rip_relative = true;
            out_op.mem.disp = disp;
            // RIP resolves to: next_instruction_va = va + current_cursor + extra_imm_len
            uint64_t next_va = va + cursor + extra_imm_len;
            out_op.mem.resolved_target_va = next_va + disp;
            return true;
        }

        if (rm == 4) { // SIB follows
            if (!has_bytes(1)) return false;
            uint8_t sib = read_u8();
            uint8_t scale = 1 << ((sib >> 6) & 0x03);
            uint8_t index = ((sib >> 3) & 0x07) | (rex_x ? 8 : 0);
            uint8_t base  = (sib & 0x07) | (rex_b ? 8 : 0);

            out_op.mem.scale = scale;
            if (index != 4) { // 4 means no index (RSP/R12)
                out_op.mem.index = get_register(index, 8, true);
            }

            if ((sib & 0x07) == 5 && mod == 0) {
                if (!has_bytes(4)) return false;
                out_op.mem.disp = static_cast<int32_t>(read_u8() | (read_u8() << 8) | (read_u8() << 16) | (read_u8() << 24));
            } else {
                out_op.mem.base = get_register(base, 8, true);
            }
        } else {
            out_op.mem.base = get_register(rm | (rex_b ? 8 : 0), 8, has_rex);
        }

        if (mod == 1) { // disp8
            if (!has_bytes(1)) return false;
            out_op.mem.disp = static_cast<int8_t>(read_u8());
        } else if (mod == 2) { // disp32
            if (!has_bytes(4)) return false;
            out_op.mem.disp = static_cast<int32_t>(read_u8() | (read_u8() << 8) | (read_u8() << 16) | (read_u8() << 24));
        }

        return true;
    };

    bool decoded = false;

    // --- TWO-BYTE OPCODES (0x0F ...) ---
    if (is_two_byte) {
        if (op == 0x05) { // SYSCALL
            ins.mnemonic = "syscall";
            decoded = true;
        }
        else if (op == 0x1F) { // Multi-byte NOP
            if (has_bytes(1)) {
                uint8_t modrm = read_u8();
                Operand op_dummy;
                decode_modrm_mem(modrm, op_size, op_dummy);
            }
            ins.mnemonic = "nop";
            decoded = true;
        }
        else if (op >= 0x80 && op <= 0x8F) { // Near conditional jumps (rel32)
            static const char* jcc_names[] = {
                "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
                "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"
            };
            if (has_bytes(4)) {
                int32_t rel = static_cast<int32_t>(read_u8() | (read_u8() << 8) | (read_u8() << 16) | (read_u8() << 24));
                ins.mnemonic = jcc_names[op - 0x80];
                ins.is_jump = true;
                ins.is_conditional_jump = true;
                ins.branch_target_va = va + cursor + rel;
                ins.operands.push_back(Operand{ OperandType::Immediate, Reg::None, ins.branch_target_va });
                decoded = true;
            }
        }
        else if (op == 0xAF) { // IMUL r, r/m
            if (has_bytes(1)) {
                uint8_t modrm = read_u8();
                Operand r_op{ OperandType::Register, get_register(((modrm >> 3) & 7) | (rex_r ? 8 : 0), op_size, has_rex) };
                Operand rm_op;
                if (decode_modrm_mem(modrm, op_size, rm_op)) {
                    ins.mnemonic = "imul";
                    ins.operands = { r_op, rm_op };
                    decoded = true;
                }
            }
        }
        else if (op == 0xB6 || op == 0xB7) { // MOVZX
            uint8_t src_size = (op == 0xB6) ? 1 : 2;
            if (has_bytes(1)) {
                uint8_t modrm = read_u8();
                Operand dst{ OperandType::Register, get_register(((modrm >> 3) & 7) | (rex_r ? 8 : 0), op_size, has_rex) };
                Operand src;
                if (decode_modrm_mem(modrm, src_size, src)) {
                    ins.mnemonic = "movzx";
                    ins.operands = { dst, src };
                    decoded = true;
                }
            }
        }
        else if (op == 0xBE || op == 0xBF) { // MOVSX
            uint8_t src_size = (op == 0xBE) ? 1 : 2;
            if (has_bytes(1)) {
                uint8_t modrm = read_u8();
                Operand dst{ OperandType::Register, get_register(((modrm >> 3) & 7) | (rex_r ? 8 : 0), op_size, has_rex) };
                Operand src;
                if (decode_modrm_mem(modrm, src_size, src)) {
                    ins.mnemonic = "movsx";
                    ins.operands = { dst, src };
                    decoded = true;
                }
            }
        }
    }
    // --- ONE-BYTE OPCODES ---
    else {
        // NOP
        if (op == 0x90) {
            ins.mnemonic = "nop";
            decoded = true;
        }
        // INT 3
        else if (op == 0xCC) {
            ins.mnemonic = "int3";
            decoded = true;
        }
        // RET (near)
        else if (op == 0xC3) {
            ins.mnemonic = "ret";
            ins.is_ret = true;
            decoded = true;
        }
        // RET imm16
        else if (op == 0xC2) {
            if (has_bytes(2)) {
                uint16_t imm = static_cast<uint16_t>(read_u8() | (read_u8() << 8));
                ins.mnemonic = "ret";
                ins.is_ret = true;
                ins.operands.push_back(Operand{ OperandType::Immediate, Reg::None, imm });
                decoded = true;
            }
        }
        // PUSH reg64 (0x50 - 0x57)
        else if (op >= 0x50 && op <= 0x57) {
            ins.mnemonic = "push";
            ins.operands.push_back(Operand{ OperandType::Register, get_register((op & 7) | (rex_b ? 8 : 0), 8, has_rex) });
            decoded = true;
        }
        // POP reg64 (0x58 - 0x5F)
        else if (op >= 0x58 && op <= 0x5F) {
            ins.mnemonic = "pop";
            ins.operands.push_back(Operand{ OperandType::Register, get_register((op & 7) | (rex_b ? 8 : 0), 8, has_rex) });
            decoded = true;
        }
        // PUSH imm32
        else if (op == 0x68) {
            if (has_bytes(4)) {
                uint32_t imm = read_u8() | (read_u8() << 8) | (read_u8() << 16) | (read_u8() << 24);
                ins.mnemonic = "push";
                ins.operands.push_back(Operand{ OperandType::Immediate, Reg::None, imm });
                decoded = true;
            }
        }
        // PUSH imm8
        else if (op == 0x6A) {
            if (has_bytes(1)) {
                int8_t imm = static_cast<int8_t>(read_u8());
                ins.mnemonic = "push";
                ins.operands.push_back(Operand{ OperandType::Immediate, Reg::None, static_cast<uint64_t>(imm), true });
                decoded = true;
            }
        }
        // LEA r, m (0x8D)
        else if (op == 0x8D) {
            if (has_bytes(1)) {
                uint8_t modrm = read_u8();
                Operand r_op{ OperandType::Register, get_register(((modrm >> 3) & 7) | (rex_r ? 8 : 0), op_size, has_rex) };
                Operand mem_op;
                if (decode_modrm_mem(modrm, op_size, mem_op)) {
                    ins.mnemonic = "lea";
                    ins.operands = { r_op, mem_op };
                    decoded = true;
                }
            }
        }
        // MOV r/m8, r8 (0x88)
        else if (op == 0x88) {
            if (has_bytes(1)) {
                uint8_t modrm = read_u8();
                Operand r_op{ OperandType::Register, get_register(((modrm >> 3) & 7) | (rex_r ? 8 : 0), 1, has_rex) };
                Operand rm_op;
                if (decode_modrm_mem(modrm, 1, rm_op)) {
                    ins.mnemonic = "mov";
                    ins.operands = { rm_op, r_op };
                    decoded = true;
                }
            }
        }
        // MOV r/m, r (0x89)
        else if (op == 0x89) {
            if (has_bytes(1)) {
                uint8_t modrm = read_u8();
                Operand r_op{ OperandType::Register, get_register(((modrm >> 3) & 7) | (rex_r ? 8 : 0), op_size, has_rex) };
                Operand rm_op;
                if (decode_modrm_mem(modrm, op_size, rm_op)) {
                    ins.mnemonic = "mov";
                    ins.operands = { rm_op, r_op };
                    decoded = true;
                }
            }
        }
        // MOV r8, r/m8 (0x8A)
        else if (op == 0x8A) {
            if (has_bytes(1)) {
                uint8_t modrm = read_u8();
                Operand r_op{ OperandType::Register, get_register(((modrm >> 3) & 7) | (rex_r ? 8 : 0), 1, has_rex) };
                Operand rm_op;
                if (decode_modrm_mem(modrm, 1, rm_op)) {
                    ins.mnemonic = "mov";
                    ins.operands = { r_op, rm_op };
                    decoded = true;
                }
            }
        }
        // MOV r, r/m (0x8B)
        else if (op == 0x8B) {
            if (has_bytes(1)) {
                uint8_t modrm = read_u8();
                Operand r_op{ OperandType::Register, get_register(((modrm >> 3) & 7) | (rex_r ? 8 : 0), op_size, has_rex) };
                Operand rm_op;
                if (decode_modrm_mem(modrm, op_size, rm_op)) {
                    ins.mnemonic = "mov";
                    ins.operands = { r_op, rm_op };
                    decoded = true;
                }
            }
        }
        // MOV reg8, imm8 (0xB0 - 0xB7)
        else if (op >= 0xB0 && op <= 0xB7) {
            if (has_bytes(1)) {
                uint8_t imm = read_u8();
                ins.mnemonic = "mov";
                ins.operands.push_back(Operand{ OperandType::Register, get_register((op & 7) | (rex_b ? 8 : 0), 1, has_rex) });
                ins.operands.push_back(Operand{ OperandType::Immediate, Reg::None, imm });
                decoded = true;
            }
        }
        // MOV reg, imm32 / imm64 (0xB8 - 0xBF)
        else if (op >= 0xB8 && op <= 0xBF) {
            if (rex_w) { // 64-bit immediate!
                if (has_bytes(8)) {
                    uint64_t imm = 0;
                    for (int i = 0; i < 8; ++i) imm |= (static_cast<uint64_t>(read_u8()) << (i * 8));
                    ins.mnemonic = "mov";
                    ins.operands.push_back(Operand{ OperandType::Register, get_register((op & 7) | (rex_b ? 8 : 0), 8, true) });
                    ins.operands.push_back(Operand{ OperandType::Immediate, Reg::None, imm });
                    decoded = true;
                }
            } else {
                if (has_bytes(4)) {
                    uint32_t imm = read_u8() | (read_u8() << 8) | (read_u8() << 16) | (read_u8() << 24);
                    ins.mnemonic = "mov";
                    ins.operands.push_back(Operand{ OperandType::Register, get_register((op & 7) | (rex_b ? 8 : 0), op_size, has_rex) });
                    ins.operands.push_back(Operand{ OperandType::Immediate, Reg::None, imm });
                    decoded = true;
                }
            }
        }
        // MOV r/m8, imm8 (0xC6)
        else if (op == 0xC6) {
            if (has_bytes(1)) {
                uint8_t modrm = read_u8();
                Operand rm_op;
                if (decode_modrm_mem(modrm, 1, rm_op, 1) && has_bytes(1)) {
                    uint8_t imm = read_u8();
                    ins.mnemonic = "mov";
                    ins.operands = { rm_op, Operand{ OperandType::Immediate, Reg::None, imm } };
                    decoded = true;
                }
            }
        }
        // MOV r/m, imm32 (0xC7)
        else if (op == 0xC7) {
            if (has_bytes(1)) {
                uint8_t modrm = read_u8();
                Operand rm_op;
                if (decode_modrm_mem(modrm, op_size, rm_op, 4) && has_bytes(4)) {
                    uint32_t imm = read_u8() | (read_u8() << 8) | (read_u8() << 16) | (read_u8() << 24);
                    ins.mnemonic = "mov";
                    ins.operands = { rm_op, Operand{ OperandType::Immediate, Reg::None, imm } };
                    decoded = true;
                }
            }
        }
        // CALL rel32 (0xE8)
        else if (op == 0xE8) {
            if (has_bytes(4)) {
                int32_t rel = static_cast<int32_t>(read_u8() | (read_u8() << 8) | (read_u8() << 16) | (read_u8() << 24));
                ins.mnemonic = "call";
                ins.is_call = true;
                ins.branch_target_va = va + cursor + rel;
                ins.operands.push_back(Operand{ OperandType::Immediate, Reg::None, ins.branch_target_va });
                decoded = true;
            }
        }
        // JMP rel32 (0xE9)
        else if (op == 0xE9) {
            if (has_bytes(4)) {
                int32_t rel = static_cast<int32_t>(read_u8() | (read_u8() << 8) | (read_u8() << 16) | (read_u8() << 24));
                ins.mnemonic = "jmp";
                ins.is_jump = true;
                ins.branch_target_va = va + cursor + rel;
                ins.operands.push_back(Operand{ OperandType::Immediate, Reg::None, ins.branch_target_va });
                decoded = true;
            }
        }
        // JMP rel8 (0xEB)
        else if (op == 0xEB) {
            if (has_bytes(1)) {
                int8_t rel = static_cast<int8_t>(read_u8());
                ins.mnemonic = "jmp";
                ins.is_jump = true;
                ins.branch_target_va = va + cursor + rel;
                ins.operands.push_back(Operand{ OperandType::Immediate, Reg::None, ins.branch_target_va });
                decoded = true;
            }
        }
        // Short conditional jumps (0x70 - 0x7F)
        else if (op >= 0x70 && op <= 0x7F) {
            static const char* jcc_names[] = {
                "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
                "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"
            };
            if (has_bytes(1)) {
                int8_t rel = static_cast<int8_t>(read_u8());
                ins.mnemonic = jcc_names[op - 0x70];
                ins.is_jump = true;
                ins.is_conditional_jump = true;
                ins.branch_target_va = va + cursor + rel;
                ins.operands.push_back(Operand{ OperandType::Immediate, Reg::None, ins.branch_target_va });
                decoded = true;
            }
        }
        // Arithmetic / Logic 2-operand (ADD, OR, AND, SUB, XOR, CMP)
        // 0x00-0x03 ADD, 0x08-0x0B OR, 0x20-0x23 AND, 0x28-0x2B SUB, 0x30-0x33 XOR, 0x38-0x3B CMP, 0x84-0x85 TEST
        else if (op <= 0x3D || op == 0x84 || op == 0x85) {
            static const char* alu_mnemonics[] = { "add", "or", "", "", "and", "sub", "xor", "cmp" };
            uint8_t grp = op >> 3; // 0=add, 1=or, 4=and, 5=sub, 6=xor, 7=cmp
            const char* mnem = (op == 0x84 || op == 0x85) ? "test" : ((grp < 8) ? alu_mnemonics[grp] : "");

            if (mnem[0] != '\0' && has_bytes(1)) {
                uint8_t modrm = read_u8();
                uint8_t sub_op = op & 7;
                bool is_8bit = (sub_op == 0 || sub_op == 2 || op == 0x84);
                bool dir_rm_to_r = (sub_op == 2 || sub_op == 3); // 1 = r is dest, 0 = rm is dest
                uint8_t sz = is_8bit ? 1 : op_size;

                Operand r_op{ OperandType::Register, get_register(((modrm >> 3) & 7) | (rex_r ? 8 : 0), sz, has_rex) };
                Operand rm_op;
                if (decode_modrm_mem(modrm, sz, rm_op)) {
                    ins.mnemonic = mnem;
                    if (dir_rm_to_r) {
                        ins.operands = { r_op, rm_op };
                    } else {
                        ins.operands = { rm_op, r_op };
                    }
                    decoded = true;
                }
            }
        }
        // Group 1 Immediate Arithmetic (0x80, 0x81, 0x83)
        else if (op == 0x80 || op == 0x81 || op == 0x83) {
            if (has_bytes(1)) {
                uint8_t modrm = read_u8();
                uint8_t op_index = (modrm >> 3) & 7;
                static const char* grp1_mnemonics[] = { "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp" };
                const char* mnem = grp1_mnemonics[op_index];

                uint8_t target_size = (op == 0x80) ? 1 : op_size;
                size_t imm_len = (op == 0x81) ? (op_size == 2 ? 2 : 4) : 1;

                Operand rm_op;
                if (decode_modrm_mem(modrm, target_size, rm_op, imm_len) && has_bytes(imm_len)) {
                    uint64_t imm = 0;
                    if (imm_len == 1) {
                        int8_t v = static_cast<int8_t>(read_u8());
                        imm = static_cast<uint64_t>(v);
                    } else if (imm_len == 2) {
                        imm = static_cast<uint16_t>(read_u8() | (read_u8() << 8));
                    } else {
                        imm = read_u8() | (read_u8() << 8) | (read_u8() << 16) | (read_u8() << 24);
                    }

                    ins.mnemonic = mnem;
                    ins.operands = { rm_op, Operand{ OperandType::Immediate, Reg::None, imm, (op == 0x83) } };
                    decoded = true;
                }
            }
        }
        // Group 4 / 5 (0xFF): CALL r/m, JMP r/m, PUSH r/m, INC, DEC
        else if (op == 0xFF) {
            if (has_bytes(1)) {
                uint8_t modrm = read_u8();
                uint8_t sub = (modrm >> 3) & 7;

                Operand rm_op;
                if (decode_modrm_mem(modrm, 8, rm_op)) {
                    if (sub == 0) { ins.mnemonic = "inc"; ins.operands = { rm_op }; decoded = true; }
                    else if (sub == 1) { ins.mnemonic = "dec"; ins.operands = { rm_op }; decoded = true; }
                    else if (sub == 2) {
                        ins.mnemonic = "call";
                        ins.is_call = true;
                        ins.operands = { rm_op };
                        decoded = true;
                    }
                    else if (sub == 4) {
                        ins.mnemonic = "jmp";
                        ins.is_jump = true;
                        ins.operands = { rm_op };
                        decoded = true;
                    }
                    else if (sub == 6) { ins.mnemonic = "push"; ins.operands = { rm_op }; decoded = true; }
                }
            }
        }
    }

    // 3. Fallback to db byte
    if (!decoded) {
        ins.length = 1;
        ins.mnemonic = "db";
        ins.operands.push_back(Operand{ OperandType::Immediate, Reg::None, buffer[0] });
        ins.raw_bytes.push_back(buffer[0]);
        return ins;
    }

    ins.length = static_cast<uint8_t>(cursor);
    ins.raw_bytes.assign(buffer.begin(), buffer.begin() + ins.length);

    // 4. Symbolic Annotations (IAT & Exports)
    if (pe) {
        for (const auto& op_item : ins.operands) {
            if (op_item.type == OperandType::Memory && op_item.mem.is_rip_relative) {
                const auto* imp = pe->find_import_by_va(op_item.mem.resolved_target_va);
                if (imp) {
                    ins.comment = std::format("{}!{}", imp->dll_name, imp->symbol_name);
                }
            }
        }

        if (ins.is_call && ins.branch_target_va != 0) {
            const auto* exp = pe->find_export_by_rva(pe->va_to_rva(ins.branch_target_va));
            if (exp) {
                ins.comment = exp->name;
            } else if (ins.comment.empty()) {
                ins.comment = std::format("sub_{:X}", ins.branch_target_va);
            }
        }
    }

    return ins;
}

std::vector<Instruction> X86Decoder::decode_buffer(
    std::span<const uint8_t> buffer,
    uint64_t start_va,
    uint32_t start_rva,
    uint32_t start_file_offset,
    const pe::PEFile* pe
) {
    std::vector<Instruction> instructions;
    if (buffer.empty()) return instructions;

    size_t offset = 0;
    std::unordered_set<uint64_t> jump_targets;

    // Pass 1: Linear sweep decoding
    while (offset < buffer.size()) {
        std::span<const uint8_t> remaining = buffer.subspan(offset);
        uint64_t current_va = start_va + offset;
        uint32_t current_rva = start_rva + static_cast<uint32_t>(offset);
        uint32_t current_file_offset = start_file_offset + static_cast<uint32_t>(offset);

        Instruction ins = decode_instruction(remaining, current_va, current_rva, current_file_offset, pe);
        if (ins.length == 0) {
            break;
        }

        if (ins.is_jump && ins.branch_target_va != 0) {
            jump_targets.insert(ins.branch_target_va);
        }

        offset += ins.length;
        instructions.push_back(std::move(ins));
    }

    // Pass 2: Mark jump targets for ImDrawList arrows
    for (auto& ins : instructions) {
        if (jump_targets.contains(ins.va)) {
            ins.is_jump_target = true;
        }
    }

    return instructions;
}

} // namespace agy::disasm

