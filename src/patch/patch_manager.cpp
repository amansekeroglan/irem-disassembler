#include "patch_manager.hpp"
#include <chrono>
#include <format>
#include <sstream>

namespace agy::patch {

static std::string current_time_string() {
    auto now = std::chrono::system_clock::now();
    return std::format("{:%H:%M:%S}", now);
}

std::vector<uint8_t> PatchManager::parse_hex_string(std::string_view hex_str) {
    std::vector<uint8_t> bytes;
    std::string clean;
    for (char c : hex_str) {
        if (std::isxdigit(static_cast<unsigned char>(c))) {
            clean += c;
        }
    }

    if (clean.size() % 2 != 0) {
        clean = "0" + clean;
    }

    for (size_t i = 0; i < clean.size(); i += 2) {
        std::string byte_str = clean.substr(i, 2);
        uint8_t val = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        bytes.push_back(val);
    }

    return bytes;
}

bool PatchManager::apply_nop_fill(
    pe::PEFile& pe,
    uint32_t file_offset,
    uint32_t rva,
    uint64_t va,
    size_t length
) {
    if (length == 0) return false;
    std::vector<uint8_t> nops(length, 0x90);
    return apply_custom_bytes(pe, file_offset, rva, va, nops, std::format("NOP fill ({} bytes)", length));
}

bool PatchManager::apply_custom_bytes(
    pe::PEFile& pe,
    uint32_t file_offset,
    uint32_t rva,
    uint64_t va,
    std::span<const uint8_t> new_bytes,
    std::string_view description
) {
    if (new_bytes.empty()) return false;
    const auto& raw = pe.get_raw_bytes();
    if (file_offset + new_bytes.size() > raw.size()) return false;

    // Capture original bytes
    std::vector<uint8_t> original(raw.begin() + file_offset, raw.begin() + file_offset + new_bytes.size());

    // Apply to PE buffer
    if (!pe.patch_bytes(file_offset, new_bytes)) {
        return false;
    }

    PatchRecord rec;
    rec.file_offset = file_offset;
    rec.rva = rva;
    rec.va = va;
    rec.original_bytes = std::move(original);
    rec.patched_bytes.assign(new_bytes.begin(), new_bytes.end());
    rec.description = description;
    rec.time_str = current_time_string();

    for (size_t i = 0; i < new_bytes.size(); ++i) {
        patched_offsets_.insert(file_offset + static_cast<uint32_t>(i));
    }
    patched_vas_.insert(va);

    patches_.push_back(std::move(rec));
    return true;
}

bool PatchManager::revert_patch(size_t index, pe::PEFile& pe) {
    if (index >= patches_.size()) return false;

    const auto& rec = patches_[index];
    pe.patch_bytes(rec.file_offset, rec.original_bytes);

    for (size_t i = 0; i < rec.patched_bytes.size(); ++i) {
        patched_offsets_.erase(rec.file_offset + static_cast<uint32_t>(i));
    }
    patched_vas_.erase(rec.va);

    patches_.erase(patches_.begin() + index);
    return true;
}

void PatchManager::revert_all(pe::PEFile& pe) {
    while (!patches_.empty()) {
        revert_patch(patches_.size() - 1, pe);
    }
}

bool PatchManager::is_offset_patched(uint32_t file_offset) const {
    return patched_offsets_.contains(file_offset);
}

bool PatchManager::is_va_patched(uint64_t va) const {
    return patched_vas_.contains(va);
}

} // namespace agy::patch

