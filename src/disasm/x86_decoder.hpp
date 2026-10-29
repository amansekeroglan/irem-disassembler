#pragma once

#include "instruction.hpp"
#include "../pe/pe_parser.hpp"
#include <span>
#include <vector>
#include <unordered_set>

namespace agy::disasm {

class X86Decoder {
public:
    X86Decoder() = default;

    // Decode a single instruction at buffer[0..]
    Instruction decode_instruction(
        std::span<const uint8_t> buffer,
        uint64_t va,
        uint32_t rva,
        uint32_t file_offset,
        const pe::PEFile* pe = nullptr
    );

    // Decode a full buffer (Linear Sweep + Branch Target analysis + IAT annotations)
    std::vector<Instruction> decode_buffer(
        std::span<const uint8_t> buffer,
        uint64_t start_va,
        uint32_t start_rva,
        uint32_t start_file_offset,
        const pe::PEFile* pe = nullptr
    );

private:
    static Reg get_register(uint8_t index, uint8_t size_bytes, bool has_rex);
};

} // namespace agy::disasm

