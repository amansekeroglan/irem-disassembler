#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <format>
#include <span>

namespace agy::disasm {

enum class Reg : uint8_t {
    None = 0,
    // 64-bit
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
    R8, R9, R10, R11, R12, R13, R14, R15,
    RIP,

    // 32-bit
    EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
    R8D, R9D, R10D, R11D, R12D, R13D, R14D, R15D,

    // 16-bit
    AX, CX, DX, BX, SP, BP, SI, DI,
    R8W, R9W, R10W, R11W, R12W, R13W, R14W, R15W,

    // 8-bit
    AL, CL, DL, BL, SPL, BPL, SIL, DIL,
    R8B, R9B, R10B, R11B, R12B, R13B, R14B, R15B,
    AH, CH, DH, BH,

    // Segment registers
    ES, CS, SS, DS, FS, GS
};

std::string_view reg_name(Reg r);

enum class OperandType {
    None,
    Register,
    Immediate,
    Memory
};

struct MemoryOperand {
    Reg base{ Reg::None };
    Reg index{ Reg::None };
    uint8_t scale{ 1 };          // 1, 2, 4, 8
    int64_t disp{ 0 };
    uint8_t size_bytes{ 0 };     // 1, 2, 4, 8 (BYTE, WORD, DWORD, QWORD)
    bool is_rip_relative{ false };
    uint64_t resolved_target_va{ 0 };
    Reg segment_override{ Reg::None }; // e.g. Reg::GS, Reg::FS
};

struct Operand {
    OperandType type{ OperandType::None };
    Reg reg{ Reg::None };
    uint64_t imm{ 0 };
    bool imm_signed{ false };
    MemoryOperand mem{};

    std::string to_string() const;
};

struct Instruction {
    uint64_t va{ 0 };                 // Virtual Address
    uint32_t rva{ 0 };                // Relative Virtual Address
    uint32_t file_offset{ 0 };        // Raw File Offset
    uint8_t length{ 0 };              // 1 to 15 bytes
    std::vector<uint8_t> raw_bytes;

    std::string mnemonic;             // e.g. "mov", "call", "jmp", "lea"
    std::vector<Operand> operands;

    // Control flow metadata
    bool is_jump{ false };
    bool is_conditional_jump{ false };
    bool is_call{ false };
    bool is_ret{ false };
    bool is_jump_target{ false };
    uint64_t branch_target_va{ 0 };

    // Annotations & Patching
    std::string comment;              // e.g. "KERNEL32.dll!CreateFileW"
    bool is_patched{ false };

    std::string format_raw_bytes() const;
    std::string format_operands() const;
};

} // namespace agy::disasm

