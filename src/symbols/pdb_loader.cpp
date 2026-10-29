#include "pdb_loader.hpp"
#include <urlmon.h>
#include <format>
#include <iostream>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "urlmon.lib")

namespace agy::symbols {

static BOOL CALLBACK EnumSymbolsCallback(
    PSYMBOL_INFOW pSymInfo,
    ULONG SymbolSize,
    PVOID UserContext
) {
    (void)SymbolSize;
    auto* symbol_map = reinterpret_cast<std::unordered_map<uint64_t, std::string>*>(UserContext);
    if (!pSymInfo || !symbol_map) return TRUE;

    // Convert wchar_t name to std::string UTF-8
    int len = WideCharToMultiByte(CP_UTF8, 0, pSymInfo->Name, -1, nullptr, 0, nullptr, nullptr);
    if (len > 1) {
        std::string name(len - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, pSymInfo->Name, -1, name.data(), len, nullptr, nullptr);
        (*symbol_map)[pSymInfo->Address] = std::move(name);
    }

    return TRUE;
}

PdbLoader::PdbLoader() {
    process_handle_ = GetCurrentProcess();
}

PdbLoader::~PdbLoader() {
    cleanup();
}

bool PdbLoader::initialize() {
    if (initialized_) return true;

    ::SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | SYMOPT_OMAP_FIND_NEAREST);
    if (!::SymInitializeW(process_handle_, nullptr, FALSE)) {
        return false;
    }

    initialized_ = true;
    return true;
}

void PdbLoader::cleanup() {
    unload();
    if (initialized_) {
        ::SymCleanup(process_handle_);
        initialized_ = false;
    }
}

void PdbLoader::unload() {
    if (is_loaded_ && loaded_base_ != 0) {
        ::SymUnloadModule64(process_handle_, loaded_base_);
    }
    symbols_.clear();
    is_loaded_ = false;
    loaded_base_ = 0;
    loaded_pdb_name_.clear();
}

bool PdbLoader::load_pdb_file(
    const std::filesystem::path& pdb_path,
    uint64_t image_base,
    uint32_t image_size
) {
    if (!initialize()) return false;
    unload();

    if (!std::filesystem::exists(pdb_path)) return false;

    MODLOAD_DATA mld{};
    mld.ssize = sizeof(mld);
    mld.ssig = DBHHEADER_DEBUGDIRS;

    DWORD64 base = ::SymLoadModuleExW(
        process_handle_,
        nullptr,
        pdb_path.wstring().c_str(),
        nullptr,
        image_base,
        image_size,
        &mld,
        0
    );

    if (base == 0) {
        // Fallback without MODLOAD_DATA
        base = ::SymLoadModuleExW(
            process_handle_,
            nullptr,
            pdb_path.wstring().c_str(),
            nullptr,
            image_base,
            image_size,
            nullptr,
            0
        );
    }

    if (base == 0) {
        return false;
    }

    loaded_base_ = base;
    loaded_pdb_name_ = pdb_path.filename().string();
    is_loaded_ = true;

    enumerate_symbols(base);
    return !symbols_.empty();
}

bool PdbLoader::auto_load_matching_pdb(
    const std::filesystem::path& binary_path,
    uint64_t image_base,
    uint32_t image_size
) {
    std::filesystem::path parent_dir = binary_path.parent_path();
    std::filesystem::path stem_pdb = parent_dir / (binary_path.stem().string() + ".pdb");

    if (std::filesystem::exists(stem_pdb)) {
        return load_pdb_file(stem_pdb, image_base, image_size);
    }

    return false;
}

bool PdbLoader::download_and_load_from_symbol_server(
    const pe::PEFile& pe,
    const std::filesystem::path& download_dir,
    std::string& out_status
) {
    const auto& cv = pe.get_debug_codeview_info();
    if (!cv.has_value() || cv->pdb_filename.empty() || cv->guid_age_string.empty()) {
        out_status = "No CodeView (RSDS) debug info found in PE headers.";
        return false;
    }

    // Extract filename from potential full path
    std::string filename = std::filesystem::path(cv->pdb_filename).filename().string();
    std::string url = std::format("https://msdl.microsoft.com/download/symbols/{}/{}/{}",
        filename, cv->guid_age_string, filename);

    std::filesystem::path target_folder = download_dir / "symbols" / filename / cv->guid_age_string;
    std::filesystem::create_directories(target_folder);
    std::filesystem::path target_file = target_folder / filename;

    // Check if already downloaded
    if (std::filesystem::exists(target_file) && std::filesystem::file_size(target_file) > 1024) {
        out_status = "PDB already cached locally. Loading...";
        return load_pdb_file(target_file, pe.get_image_base(), pe.get_size_of_image());
    }

    out_status = std::format("Downloading {} from Microsoft Symbol Server...", filename);

    // Download using URLDownloadToFileW
    std::wstring wurl(url.begin(), url.end());
    HRESULT hr = ::URLDownloadToFileW(
        nullptr,
        wurl.c_str(),
        target_file.wstring().c_str(),
        0,
        nullptr
    );

    if (FAILED(hr) || !std::filesystem::exists(target_file) || std::filesystem::file_size(target_file) < 1024) {
        out_status = "Symbol not found on Microsoft Symbol Server or download failed.";
        if (std::filesystem::exists(target_file)) {
            std::filesystem::remove(target_file);
        }
        return false;
    }

    out_status = std::format("Successfully downloaded {}. Loading symbols...", filename);
    return load_pdb_file(target_file, pe.get_image_base(), pe.get_size_of_image());
}

void PdbLoader::enumerate_symbols(uint64_t base_address) {
    symbols_.clear();
    ::SymEnumSymbolsW(
        process_handle_,
        base_address,
        nullptr,
        EnumSymbolsCallback,
        &symbols_
    );
}

const std::string* PdbLoader::find_symbol_name(uint64_t va) const {
    auto it = symbols_.find(va);
    if (it != symbols_.end()) {
        return &it->second;
    }
    return nullptr;
}

} // namespace agy::symbols

