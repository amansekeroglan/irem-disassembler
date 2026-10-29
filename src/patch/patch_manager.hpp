#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <span>
#include <unordered_set>
#include "../pe/pe_parser.hpp"

namespace agy::patch {

struct PatchRecord {
    uint32_t file_offset{ 0 };
    uint32_t rva{ 0 };
    uint64_t va{ 0 };
    std::vector<uint8_t> original_bytes;
    std::vector<uint8_t> patched_bytes;
    std::string description;
    std::string time_str;
};

class PatchManager {
public:
    PatchManager() = default;

    bool apply_nop_fill(
        pe::PEFile& pe,
        uint32_t file_offset,
        uint32_t rva,
        uint64_t va,
        size_t length
    );

    bool apply_custom_bytes(
        pe::PEFile& pe,
        uint32_t file_offset,
        uint32_t rva,
        uint64_t va,
        std::span<const uint8_t> new_bytes,
        std::string_view description = "Custom Hex Patch"
    );

    bool revert_patch(size_t index, pe::PEFile& pe);
    void revert_all(pe::PEFile& pe);

    bool is_offset_patched(uint32_t file_offset) const;
    bool is_va_patched(uint64_t va) const;

    const std::vector<PatchRecord>& get_patches() const { return patches_; }
    size_t count() const { return patches_.size(); }

    static std::vector<uint8_t> parse_hex_string(std::string_view hex_str);

private:
    std::vector<PatchRecord> patches_;
    std::unordered_set<uint32_t> patched_offsets_;
    std::unordered_set<uint64_t> patched_vas_;
};

} // namespace agy::patch

