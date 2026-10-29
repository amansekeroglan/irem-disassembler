#pragma once

#include <windows.h>
#include <d3d11.h>
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <filesystem>
#include <unordered_map>

#include "../pe/pe_parser.hpp"
#include "../disasm/instruction.hpp"
#include "../disasm/x86_decoder.hpp"
#include "../patch/patch_manager.hpp"
#include "../analysis/function_manager.hpp"
#include "../analysis/xref_manager.hpp"
#include "../symbols/pdb_loader.hpp"
#include "../engines/engines_bridge.hpp"
#include "texture_loader.hpp"

namespace agy {

class Application {
public:
    Application();
    ~Application();

    bool initialize(const wchar_t* title, int width, int height);
    void run();
    void shutdown();

    bool open_binary(const std::filesystem::path& path);
    void open_file_dialog();
    void save_patched_file_dialog();

    HWND get_hwnd() const { return hwnd_; }

private:
    bool create_device_d3d();
    void cleanup_device_d3d();
    void create_render_target();
    void cleanup_render_target();

    void disassemble_active_section();
    void refresh_disassembly_annotations();

    void render_ui();
    void render_menu_bar();
    void render_sections_panel();
    void render_disassembly_panel();
    void render_hex_view_panel();
    void render_patch_panel();
    void render_security_flags_summary();
    void render_edit_bytes_modal();
    void render_help_modal();
    void render_functions_tab();
    void render_strings_tab();
    void render_xref_modal();
    void render_sigmaker_modal();
    void render_cfg_view();
    void open_cfg_view(uint64_t func_va);

    void trigger_nop_patch_selected();
    void jump_to_address(uint64_t va, bool save_to_history = true);
    void navigate_back();

    void open_pdb_dialog();
    void download_microsoft_pdb();

    static std::string get_kernel_api_category(const std::string& api_name);

    static LRESULT WINAPI wnd_proc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

private:
    HWND hwnd_{ nullptr };
    WNDCLASSEXW wc_{};
    bool running_{ false };

    // DirectX 11 pointers
    ID3D11Device* d3d_device_{ nullptr };
    ID3D11DeviceContext* d3d_device_context_{ nullptr };
    IDXGISwapChain* swap_chain_{ nullptr };
    ID3D11RenderTargetView* main_render_target_view_{ nullptr };
    UINT resize_width_{ 0 };
    UINT resize_height_{ 0 };

    // Core Engines
    std::optional<pe::PEFile> pe_file_;
    disasm::X86Decoder decoder_;
    patch::PatchManager patch_manager_;
    analysis::FunctionManager function_manager_;
    analysis::XrefManager xref_manager_;
    symbols::PdbLoader pdb_loader_;
    std::unique_ptr<engines::AnalysisSession> analysis_session_;

    // Disassembled State
    std::vector<disasm::Instruction> instructions_;
    std::unordered_map<uint64_t, size_t> va_to_instruction_index_;
    std::string active_section_name_{ ".text" };

    // Navigation History Stack
    std::vector<uint64_t> navigation_history_;

    // UI & Navigation State
    std::string current_file_path_{ "No binary loaded (Drag & Drop or File -> Open)" };
    std::string status_message_{ "Ready" };
    std::string pdb_status_text_{ "PDB: None" };
    uint64_t selected_address_{ 0 };
    uint32_t selected_rva_{ 0 };
    uint32_t selected_file_offset_{ 0 };
    int selected_instruction_idx_{ -1 };
    bool scroll_to_selected_{ false };

    // Edit Bytes, Help & Xref Modal State
    bool show_edit_bytes_modal_{ false };
    bool show_help_modal_{ false };
    bool show_xref_modal_{ false };
    uint64_t xref_modal_target_va_{ 0 };
    char edit_bytes_input_[128] = {};

    // Functions Tab Filter
    char function_filter_buffer_[128] = {};
    int selected_function_idx_{ -1 };

    // Strings Tab Filter & SigMaker Modal State
    char string_filter_buffer_[128] = {};
    bool show_sigmaker_modal_{ false };
    IremSignature current_signature_{};

    // CFG Graph View State
    bool show_cfg_view_{ false };
    uint64_t cfg_view_func_va_{ 0 };
    IremCFGLayout cfg_layout_{};
    float cfg_pan_x_{ 100.0f };
    float cfg_pan_y_{ 100.0f };
    float cfg_zoom_{ 1.0f };
    int cfg_hovered_block_{ -1 };
    int cfg_selected_block_{ -1 };

    // App Logo Texture
    LoadedTexture logo_texture_{};
};

} // namespace agy
