#include "instruction.hpp"

namespace agy::disasm {

std::string_view reg_name(Reg r) {
    switch (r) {
    // 64-bit
    case Reg::RAX: return "rax"; case Reg::RCX: return "rcx"; case Reg::RDX: return "rdx"; case Reg::RBX: return "rbx";
    case Reg::RSP: return "rsp"; case Reg::RBP: return "rbp"; case Reg::RSI: return "rsi"; case Reg::RDI: return "rdi";
    case Reg::R8:  return "r8";  case Reg::R9:  return "r9";  case Reg::R10: return "r10"; case Reg::R11: return "r11";
    case Reg::R12: return "r12"; case Reg::R13: return "r13"; case Reg::R14: return "r14"; case Reg::R15: return "r15";
    case Reg::RIP: return "rip";

    // 32-bit
    case Reg::EAX: return "eax"; case Reg::ECX: return "ecx"; case Reg::EDX: return "edx"; case Reg::EBX: return "ebx";
    case Reg::ESP: return "esp"; case Reg::EBP: return "ebp"; case Reg::ESI: return "esi"; case Reg::EDI: return "edi";
    case Reg::R8D: return "r8d"; case Reg::R9D: return "r9d"; case Reg::R10D: return "r10d"; case Reg::R11D: return "r11d";
    case Reg::R12D: return "r12d"; case Reg::R13D: return "r13d"; case Reg::R14D: return "r14d"; case Reg::R15D: return "r15d";

    // 16-bit
    case Reg::AX: return "ax"; case Reg::CX: return "cx"; case Reg::DX: return "dx"; case Reg::BX: return "bx";
    case Reg::SP: return "sp"; case Reg::BP: return "bp"; case Reg::SI: return "si"; case Reg::DI: return "di";
    case Reg::R8W: return "r8w"; case Reg::R9W: return "r9w"; case Reg::R10W: return "r10w"; case Reg::R11W: return "r11w";
    case Reg::R12W: return "r12w"; case Reg::R13W: return "r13w"; case Reg::R14W: return "r14w"; case Reg::R15W: return "r15w";

    // 8-bit
    case Reg::AL: return "al"; case Reg::CL: return "cl"; case Reg::DL: return "dl"; case Reg::BL: return "bl";
    case Reg::SPL: return "spl"; case Reg::BPL: return "bpl"; case Reg::SIL: return "sil"; case Reg::DIL: return "dil";
    case Reg::R8B: return "r8b"; case Reg::R9B: return "r9b"; case Reg::R10B: return "r10b"; case Reg::R11B: return "r11b";
    case Reg::R12B: return "r12b"; case Reg::R13B: return "r13b"; case Reg::R14B: return "r14b"; case Reg::R15B: return "r15b";
    case Reg::AH: return "ah"; case Reg::CH: return "ch"; case Reg::DH: return "dh"; case Reg::BH: return "bh";

    // Segment registers
    case Reg::ES: return "es"; case Reg::CS: return "cs"; case Reg::SS: return "ss";
    case Reg::DS: return "ds"; case Reg::FS: return "fs"; case Reg::GS: return "gs";

    default: return "";
    }
}

static const char* size_ptr_name(uint8_t size_bytes) {
    switch (size_bytes) {
    case 1: return "byte ptr ";
    case 2: return "word ptr ";
    case 4: return "dword ptr ";
    case 8: return "qword ptr ";
    default: return "";
    }
}

std::string Operand::to_string() const {
    switch (type) {
    case OperandType::Register:
        return std::string(reg_name(reg));

    case OperandType::Immediate: {
        if (imm_signed && static_cast<int64_t>(imm) < 0 && static_cast<int64_t>(imm) >= -0xFF) {
            return std::format("-0x{:X}", -static_cast<int64_t>(imm));
        }
        if (imm <= 9) {
            return std::format("{}", imm);
        }
        return std::format("0x{:X}", imm);
    }

    case OperandType::Memory: {
        std::string s;
        if (mem.segment_override != Reg::None) {
            s += reg_name(mem.segment_override);
            s += ":";
        }
        s += size_ptr_name(mem.size_bytes);
        s += "[";

        bool has_base = false;
        if (mem.is_rip_relative) {
            s += "rip";
            has_base = true;
        } else if (mem.base != Reg::None) {
            s += reg_name(mem.base);
            has_base = true;
        }

        if (mem.index != Reg::None) {
            if (has_base) s += " + ";
            s += reg_name(mem.index);
            if (mem.scale > 1) {
                s += std::format("*{}", mem.scale);
            }
            has_base = true;
        }

        if (mem.disp != 0 || !has_base) {
            if (has_base) {
                if (mem.disp > 0) {
                    s += std::format(" + 0x{:X}", mem.disp);
                } else {
                    s += std::format(" - 0x{:X}", -mem.disp);
                }
            } else {
                s += std::format("0x{:X}", static_cast<uint64_t>(mem.disp));
            }
        }

        s += "]";
        return s;
    }

    default:
        return "";
    }
}

std::string Instruction::format_raw_bytes() const {
    std::string s;
    for (size_t i = 0; i < raw_bytes.size(); ++i) {
        if (i > 0) s += " ";
        s += std::format("{:02X}", raw_bytes[i]);
    }
    return s;
}

std::string Instruction::format_operands() const {
    std::string s;
    for (size_t i = 0; i < operands.size(); ++i) {
        if (i > 0) s += ", ";
        s += operands[i].to_string();
    }
    return s;
}

} // namespace agy::disasm

