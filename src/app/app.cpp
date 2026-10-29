#include "app.hpp"
#include "ui_theme.hpp"
#include "resource.h"

#include <imgui.h>
#include <backends/imgui_impl_win32.h>
#include <backends/imgui_impl_dx11.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <commdlg.h>
#include <shobjidl.h>
#include <format>
#include <cmath>
#include <algorithm>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace agy {

Application::Application() = default;

Application::~Application() {
    shutdown();
}

bool Application::initialize(const wchar_t* title, int width, int height) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    HICON hIcon = (HICON)::LoadImageW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_APP_ICON), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE | LR_SHARED);
    HICON hIconSm = (HICON)::LoadImageW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_APP_ICON), IMAGE_ICON, 16, 16, LR_SHARED);

    wc_ = {
        sizeof(wc_),
        CS_CLASSDC,
        wnd_proc,
        0L,
        0L,
        GetModuleHandle(nullptr),
        hIcon,
        nullptr,
        nullptr,
        nullptr,
        L"IremWindowClass",
        hIconSm
    };
    ::RegisterClassExW(&wc_);

    hwnd_ = ::CreateWindowW(
        wc_.lpszClassName,
        title,
        WS_OVERLAPPEDWINDOW,
        100, 100, width, height,
        nullptr, nullptr, wc_.hInstance, this
    );

    if (!hwnd_) {
        return false;
    }

    if (hIcon) {
        ::SendMessageW(hwnd_, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(hIcon));
    }
    if (hIconSm) {
        ::SendMessageW(hwnd_, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(hIconSm));
    }

    // Windows Dark Mode Titlebar
    BOOL darkMode = TRUE;
    ::DwmSetWindowAttribute(hwnd_, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &darkMode, sizeof(darkMode));

    // Enable Drag and Drop
    ::DragAcceptFiles(hwnd_, TRUE);

    if (!create_device_d3d()) {
        cleanup_device_d3d();
        ::UnregisterClassW(wc_.lpszClassName, wc_.hInstance);
        return false;
    }

    // Load official logo texture into DirectX 11 (first from embedded binary resource, fallback to disk)
    if (!TextureLoader::load_from_resource(d3d_device_, IDR_LOGO_JPG, logo_texture_)) {
        if (!TextureLoader::load_from_file(d3d_device_, L"makyairemi.jpg", logo_texture_)) {
            TextureLoader::load_from_file(d3d_device_, L"src/app/makyairemi.jpg", logo_texture_);
        }
    }

    ::ShowWindow(hwnd_, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd_);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
#ifdef ImGuiConfigFlags_DockingEnable
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
#endif

    ui::apply_ida_dark_theme();

    ImGui_ImplWin32_Init(hwnd_);
    ImGui_ImplDX11_Init(d3d_device_, d3d_device_context_);

    running_ = true;
    return true;
}

void Application::disassemble_active_section() {
    instructions_.clear();
    va_to_instruction_index_.clear();
    selected_instruction_idx_ = -1;

    if (!pe_file_) return;

    const pe::SectionInfo* target_sec = nullptr;
    if (!active_section_name_.empty()) {
        target_sec = pe_file_->find_section_by_name(active_section_name_);
    }
    if (!target_sec) {
        target_sec = pe_file_->get_code_section();
    }
    if (!target_sec) return;

    active_section_name_ = target_sec->name;
    auto sec_bytes = pe_file_->get_section_bytes(*target_sec);
    if (sec_bytes.empty()) return;

    uint64_t start_va = pe_file_->rva_to_va(target_sec->virtual_address);
    uint32_t start_rva = target_sec->virtual_address;
    uint32_t start_offset = target_sec->raw_offset;

    // Run our custom x86_64 decoder
    instructions_ = decoder_.decode_buffer(sec_bytes, start_va, start_rva, start_offset, &(*pe_file_));

    // Build fast VA lookup index
    for (size_t i = 0; i < instructions_.size(); ++i) {
        va_to_instruction_index_[instructions_[i].va] = i;
    }

    // Check patch status for each instruction
    for (auto& ins : instructions_) {
        ins.is_patched = patch_manager_.is_va_patched(ins.va) || patch_manager_.is_offset_patched(ins.file_offset);
    }

    // Discover Functions in active section
    function_manager_.discover_functions(*pe_file_, active_section_name_, instructions_);

    // Auto-discover matching PDB if not already loaded
    if (!pdb_loader_.is_loaded() && !current_file_path_.empty()) {
        std::filesystem::path bin_path(current_file_path_);
        if (std::filesystem::exists(bin_path)) {
            pdb_loader_.auto_load_matching_pdb(bin_path, pe_file_->get_image_base(), pe_file_->get_size_of_image());
        }
    }

    // Apply PDB symbol names to functions if loaded
    if (pdb_loader_.is_loaded()) {
        for (const auto& [va, name] : pdb_loader_.get_all_symbols()) {
            function_manager_.apply_symbol_name(va, name);
        }
        pdb_status_text_ = std::format("PDB: {} ({} symbols)", pdb_loader_.get_loaded_pdb_name(), pdb_loader_.get_symbol_count());
    } else {
        pdb_status_text_ = "PDB: None";
    }

    // Build Xref cross-reference graph
    xref_manager_.build_xrefs(instructions_, function_manager_);

    // Run All 7 Pure C Advanced Analysis Engines via Bridge
    analysis_session_ = engines::run_analysis(*pe_file_, active_section_name_, instructions_, function_manager_);
    if (analysis_session_) {
        engines::apply_analysis_annotations(instructions_, *analysis_session_, *pe_file_);
    }

    // Annotate instructions with discovered function names
    for (auto& ins : instructions_) {
        if (ins.is_call && ins.branch_target_va != 0) {
            const auto* fn_ptr = function_manager_.find_function_by_va(ins.branch_target_va);
            if (fn_ptr && ins.comment.find(fn_ptr->name) == std::string::npos) {
                ins.comment = (ins.comment.empty() ? "" : (ins.comment + " | ")) + "<" + fn_ptr->name + ">";
            }
        }
    }

    // Default select Entry Point if in this section
    uint64_t ep_va = pe_file_->get_entry_point_va();
    auto it = va_to_instruction_index_.find(ep_va);
    if (it != va_to_instruction_index_.end()) {
        selected_instruction_idx_ = static_cast<int>(it->second);
        selected_address_ = ep_va;
        selected_rva_ = instructions_[selected_instruction_idx_].rva;
        selected_file_offset_ = instructions_[selected_instruction_idx_].file_offset;
        scroll_to_selected_ = true;
    } else if (!instructions_.empty()) {
        selected_instruction_idx_ = 0;
        selected_address_ = instructions_[0].va;
        selected_rva_ = instructions_[0].rva;
        selected_file_offset_ = instructions_[0].file_offset;
    }
}

void Application::jump_to_address(uint64_t va, bool save_to_history) {
    if (save_to_history && selected_address_ != 0 && selected_address_ != va) {
        navigation_history_.push_back(selected_address_);
    }

    auto it = va_to_instruction_index_.find(va);
    if (it != va_to_instruction_index_.end()) {
        selected_instruction_idx_ = static_cast<int>(it->second);
        selected_address_ = va;
        selected_rva_ = instructions_[selected_instruction_idx_].rva;
        selected_file_offset_ = instructions_[selected_instruction_idx_].file_offset;
        scroll_to_selected_ = true;
    }
}

void Application::navigate_back() {
    if (!navigation_history_.empty()) {
        uint64_t prev_va = navigation_history_.back();
        navigation_history_.pop_back();
        jump_to_address(prev_va, false);
    }
}

void Application::refresh_disassembly_annotations() {
    for (auto& ins : instructions_) {
        ins.is_patched = patch_manager_.is_va_patched(ins.va) || patch_manager_.is_offset_patched(ins.file_offset);
    }
}

bool Application::open_binary(const std::filesystem::path& path) {
    auto res = pe::PEFile::load_from_file(path);
    if (!res) {
        status_message_ = std::format("Error: {}", res.error().message);
        return false;
    }

    navigation_history_.clear();
    function_manager_.clear();
    xref_manager_.clear();
    pdb_loader_.unload();

    pe_file_ = std::move(*res);
    current_file_path_ = path.string();

    const auto* code_sec = pe_file_->get_code_section();
    active_section_name_ = code_sec ? code_sec->name : ".text";

    disassemble_active_section();

    status_message_ = std::format("Loaded: {} ({} instructions, {} functions)",
        path.filename().string(),
        instructions_.size(),
        function_manager_.get_functions().size());

    return true;
}

void Application::open_file_dialog() {
    IFileOpenDialog* pFileOpen = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_ALL, IID_IFileOpenDialog, reinterpret_cast<void**>(&pFileOpen));
    if (SUCCEEDED(hr)) {
        static const COMDLG_FILTERSPEC c_fileTypes[] = {
            { L"All Supported (*.exe;*.dll;*.sys;*.efi)", L"*.exe;*.dll;*.sys;*.efi" },
            { L"Kernel Drivers (*.sys)",                  L"*.sys" },
            { L"UEFI Firmware Binaries (*.efi)",          L"*.efi" },
            { L"Applications (*.exe)",                    L"*.exe" },
            { L"Dynamic Link Libraries (*.dll)",          L"*.dll" },
            { L"All Files (*.*)",                         L"*.*" }
        };
        pFileOpen->SetFileTypes(ARRAYSIZE(c_fileTypes), c_fileTypes);
        pFileOpen->SetFileTypeIndex(1);
        pFileOpen->SetTitle(L"Open Executable, Driver, or UEFI Binary - Ирем");

        FILEOPENDIALOGOPTIONS options = 0;
        if (SUCCEEDED(pFileOpen->GetOptions(&options))) {
            pFileOpen->SetOptions(options | FOS_FORCEFILESYSTEM | FOS_FILEMUSTEXIST | FOS_PATHMUSTEXIST);
        }

        if (SUCCEEDED(pFileOpen->Show(hwnd_))) {
            IShellItem* pItem = nullptr;
            if (SUCCEEDED(pFileOpen->GetResult(&pItem))) {
                PWSTR pszFilePath = nullptr;
                if (SUCCEEDED(pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath))) {
                    open_binary(pszFilePath);
                    CoTaskMemFree(pszFilePath);
                }
                pItem->Release();
            }
        }
        pFileOpen->Release();
        return;
    }

    // Fallback to GetOpenFileNameW if COM IFileDialog fails
    wchar_t filename[MAX_PATH] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFilter =
        L"All Supported (*.exe;*.dll;*.sys;*.efi)\0*.exe;*.dll;*.sys;*.efi\0"
        L"Kernel Drivers (*.sys)\0*.sys\0"
        L"UEFI Firmware (*.efi)\0*.efi\0"
        L"Applications (*.exe)\0*.exe\0"
        L"Libraries (*.dll)\0*.dll\0"
        L"All Files (*.*)\0*.*\0\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (::GetOpenFileNameW(&ofn)) {
        open_binary(filename);
    }
}

void Application::save_patched_file_dialog() {
    if (!pe_file_) return;

    IFileSaveDialog* pFileSave = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_FileSaveDialog, nullptr, CLSCTX_ALL, IID_IFileSaveDialog, reinterpret_cast<void**>(&pFileSave));
    if (SUCCEEDED(hr)) {
        static const COMDLG_FILTERSPEC c_fileTypes[] = {
            { L"All Supported (*.exe;*.dll;*.sys;*.efi)", L"*.exe;*.dll;*.sys;*.efi" },
            { L"Kernel Drivers (*.sys)",                  L"*.sys" },
            { L"UEFI Firmware Binaries (*.efi)",          L"*.efi" },
            { L"Applications (*.exe)",                    L"*.exe" },
            { L"Dynamic Link Libraries (*.dll)",          L"*.dll" },
            { L"All Files (*.*)",                         L"*.*" }
        };
        pFileSave->SetFileTypes(ARRAYSIZE(c_fileTypes), c_fileTypes);
        pFileSave->SetFileTypeIndex(1);
        pFileSave->SetTitle(L"Save Patched Binary As - Ирем");

        std::filesystem::path orig_path(current_file_path_);
        std::wstring default_name = orig_path.stem().wstring() + L"_patched" + orig_path.extension().wstring();
        pFileSave->SetFileName(default_name.c_str());

        FILEOPENDIALOGOPTIONS options = 0;
        if (SUCCEEDED(pFileSave->GetOptions(&options))) {
            pFileSave->SetOptions(options | FOS_FORCEFILESYSTEM | FOS_OVERWRITEPROMPT);
        }

        if (SUCCEEDED(pFileSave->Show(hwnd_))) {
            IShellItem* pItem = nullptr;
            if (SUCCEEDED(pFileSave->GetResult(&pItem))) {
                PWSTR pszFilePath = nullptr;
                if (SUCCEEDED(pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath))) {
                    if (pe_file_->save_to_file(pszFilePath)) {
                        status_message_ = std::format("Patched file saved: {}", std::filesystem::path(pszFilePath).filename().string());
                    } else {
                        status_message_ = "Error: Failed to write file to disk!";
                    }
                    CoTaskMemFree(pszFilePath);
                }
                pItem->Release();
            }
        }
        pFileSave->Release();
        return;
    }

    // Fallback to GetSaveFileNameW
    wchar_t filename[MAX_PATH] = {};
    std::filesystem::path orig_path(current_file_path_);
    std::wstring default_name = orig_path.stem().wstring() + L"_patched" + orig_path.extension().wstring();
    wcsncpy_s(filename, default_name.c_str(), MAX_PATH - 1);

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFilter =
        L"All Supported (*.exe;*.dll;*.sys;*.efi)\0*.exe;*.dll;*.sys;*.efi\0"
        L"Kernel Drivers (*.sys)\0*.sys\0"
        L"UEFI Firmware (*.efi)\0*.efi\0"
        L"Applications (*.exe)\0*.exe\0"
        L"Libraries (*.dll)\0*.dll\0"
        L"All Files (*.*)\0*.*\0\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT;

    if (::GetSaveFileNameW(&ofn)) {
        if (pe_file_->save_to_file(filename)) {
            status_message_ = std::format("Patched file saved: {}", std::filesystem::path(filename).filename().string());
        } else {
            status_message_ = "Error: Failed to write file to disk!";
        }
    }
}

void Application::open_pdb_dialog() {
    if (!pe_file_) return;

    IFileOpenDialog* pFileOpen = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_ALL, IID_IFileOpenDialog, reinterpret_cast<void**>(&pFileOpen));
    if (SUCCEEDED(hr)) {
        static const COMDLG_FILTERSPEC c_fileTypes[] = {
            { L"Program Database (*.pdb)", L"*.pdb" },
            { L"All Files (*.*)",          L"*.*" }
        };
        pFileOpen->SetFileTypes(ARRAYSIZE(c_fileTypes), c_fileTypes);
        pFileOpen->SetTitle(L"Open PDB Symbol File - Ирем");

        if (SUCCEEDED(pFileOpen->Show(hwnd_))) {
            IShellItem* pItem = nullptr;
            if (SUCCEEDED(pFileOpen->GetResult(&pItem))) {
                PWSTR pszFilePath = nullptr;
                if (SUCCEEDED(pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath))) {
                    if (pdb_loader_.load_pdb_file(pszFilePath, pe_file_->get_image_base(), pe_file_->get_size_of_image())) {
                        status_message_ = std::format("Loaded {} symbols from PDB", pdb_loader_.get_symbol_count());
                        pdb_status_text_ = std::format("PDB: {} ({} symbols)", pdb_loader_.get_loaded_pdb_name(), pdb_loader_.get_symbol_count());

                        // Apply to functions
                        for (const auto& [va, name] : pdb_loader_.get_all_symbols()) {
                            function_manager_.apply_symbol_name(va, name);
                        }
                        // Refresh call comments
                        for (auto& ins : instructions_) {
                            if (ins.is_call && ins.branch_target_va != 0) {
                                const auto* fn_ptr = function_manager_.find_function_by_va(ins.branch_target_va);
                                if (fn_ptr) ins.comment = "; " + fn_ptr->name;
                            }
                        }
                    } else {
                        status_message_ = "Error: Failed to load PDB or no symbols found.";
                    }
                    CoTaskMemFree(pszFilePath);
                }
                pItem->Release();
            }
        }
        pFileOpen->Release();
    }
}

void Application::download_microsoft_pdb() {
    if (!pe_file_) return;

    std::filesystem::path current_dir = std::filesystem::current_path();
    std::string download_status;
    if (pdb_loader_.download_and_load_from_symbol_server(*pe_file_, current_dir, download_status)) {
        status_message_ = std::format("PDB Downloaded! Loaded {} symbols", pdb_loader_.get_symbol_count());
        pdb_status_text_ = std::format("PDB: {} ({} symbols)", pdb_loader_.get_loaded_pdb_name(), pdb_loader_.get_symbol_count());

        for (const auto& [va, name] : pdb_loader_.get_all_symbols()) {
            function_manager_.apply_symbol_name(va, name);
        }
        for (auto& ins : instructions_) {
            if (ins.is_call && ins.branch_target_va != 0) {
                const auto* fn_ptr = function_manager_.find_function_by_va(ins.branch_target_va);
                if (fn_ptr) ins.comment = "; " + fn_ptr->name;
            }
        }
    } else {
        status_message_ = download_status;
    }
}

void Application::trigger_nop_patch_selected() {
    if (!pe_file_ || selected_instruction_idx_ < 0 || selected_instruction_idx_ >= static_cast<int>(instructions_.size())) {
        return;
    }

    auto& ins = instructions_[selected_instruction_idx_];
    if (patch_manager_.apply_nop_fill(*pe_file_, ins.file_offset, ins.rva, ins.va, ins.length)) {
        // Re-decode patched region
        auto raw_span = pe_file_->get_bytes_at_rva(ins.rva, ins.length);
        disasm::Instruction new_ins = decoder_.decode_instruction(raw_span, ins.va, ins.rva, ins.file_offset, &(*pe_file_));
        new_ins.is_patched = true;
        new_ins.comment = "PATCHED: NOP fill";
        instructions_[selected_instruction_idx_] = std::move(new_ins);
        status_message_ = std::format("Instruction at 0x{:X} filled with NOPs", ins.va);
    }
}

void Application::run() {
    MSG msg;
    ::ZeroMemory(&msg, sizeof(msg));

    while (running_ && msg.message != WM_QUIT) {
        if (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            continue;
        }

        // Handle resize
        if (resize_width_ != 0 && resize_height_ != 0) {
            cleanup_render_target();
            swap_chain_->ResizeBuffers(0, resize_width_, resize_height_, DXGI_FORMAT_UNKNOWN, 0);
            resize_width_ = resize_height_ = 0;
            create_render_target();
        }

        // Global Keyboard Shortcuts
        if (ImGui::IsKeyPressed(ImGuiKey_F1)) {
            show_help_modal_ = true;
        }
        if (ImGui::IsKeyPressed(ImGuiKey_F2)) {
            trigger_nop_patch_selected();
        }
        if (ImGui::IsKeyPressed(ImGuiKey_X)) {
            if (selected_address_ != 0) {
                show_xref_modal_ = true;
                xref_modal_target_va_ = selected_address_;
            }
        }
        if (ImGui::IsKeyPressed(ImGuiKey_C)) {
            if (selected_address_ != 0 && !ImGui::GetIO().WantTextInput) {
                open_cfg_view(selected_address_);
            }
        }
        if (ImGui::IsKeyPressed(ImGuiKey_Escape)) {
            navigate_back();
        }
        if (ImGui::IsKeyDown(ImGuiMod_Ctrl) && ImGui::IsKeyPressed(ImGuiKey_O)) {
            open_file_dialog();
        }
        if (ImGui::IsKeyDown(ImGuiMod_Ctrl) && ImGui::IsKeyPressed(ImGuiKey_S)) {
            save_patched_file_dialog();
        }

        // Start Dear ImGui frame
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // Render UI
        render_ui();
        render_edit_bytes_modal();
        render_help_modal();
        render_xref_modal();
        render_sigmaker_modal();
        render_cfg_view();

        // Rendering
        ImGui::Render();
        const float clear_color[4] = { 0.08f, 0.09f, 0.11f, 1.00f };
        d3d_device_context_->OMSetRenderTargets(1, &main_render_target_view_, nullptr);
        d3d_device_context_->ClearRenderTargetView(main_render_target_view_, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        swap_chain_->Present(1, 0);
    }
}

void Application::shutdown() {
    if (!running_) return;
    running_ = false;

    irem_cfg_layout_free(&cfg_layout_);
    logo_texture_.release();

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    cleanup_device_d3d();
    if (hwnd_) {
        ::DestroyWindow(hwnd_);
        hwnd_ = nullptr;
    }
    ::UnregisterClassW(wc_.lpszClassName, wc_.hInstance);
}

bool Application::create_device_d3d() {
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd_;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = {
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_0,
    };

    HRESULT res = D3D11CreateDeviceAndSwapChain(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        createDeviceFlags,
        featureLevelArray, 2,
        D3D11_SDK_VERSION,
        &sd,
        &swap_chain_,
        &d3d_device_,
        &featureLevel,
        &d3d_device_context_
    );

    if (res != S_OK) return false;

    create_render_target();
    return true;
}

void Application::cleanup_device_d3d() {
    cleanup_render_target();
    if (swap_chain_) { swap_chain_->Release(); swap_chain_ = nullptr; }
    if (d3d_device_context_) { d3d_device_context_->Release(); d3d_device_context_ = nullptr; }
    if (d3d_device_) { d3d_device_->Release(); d3d_device_ = nullptr; }
}

void Application::create_render_target() {
    ID3D11Texture2D* pBackBuffer = nullptr;
    swap_chain_->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    if (pBackBuffer) {
        d3d_device_->CreateRenderTargetView(pBackBuffer, nullptr, &main_render_target_view_);
        pBackBuffer->Release();
    }
}

void Application::cleanup_render_target() {
    if (main_render_target_view_) {
        main_render_target_view_->Release();
        main_render_target_view_ = nullptr;
    }
}

void Application::render_ui() {
    render_menu_bar();

    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, viewport->WorkPos.y));
    ImGui::SetNextWindowSize(viewport->WorkSize);

    ImGuiWindowFlags host_flags = ImGuiWindowFlags_NoTitleBar |
                                  ImGuiWindowFlags_NoCollapse |
                                  ImGuiWindowFlags_NoResize |
                                  ImGuiWindowFlags_NoMove |
                                  ImGuiWindowFlags_NoBringToFrontOnFocus |
                                  ImGuiWindowFlags_NoNavFocus |
                                  ImGuiWindowFlags_NoBackground;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGui::Begin("MainDockSpaceHost", nullptr, host_flags);
    ImGui::PopStyleVar(3);

    // Panels
    render_sections_panel();
    render_disassembly_panel();
    render_hex_view_panel();
    render_patch_panel();

    ImGui::End();
}

void Application::render_menu_bar() {
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open PE / Driver / EFI Binary (*.exe, *.dll, *.sys, *.efi)...", "Ctrl+O")) {
                open_file_dialog();
            }
            if (ImGui::MenuItem("Save Patched Binary As...", "Ctrl+S", false, pe_file_.has_value())) {
                save_patched_file_dialog();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Exit", "Alt+F4")) {
                running_ = false;
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Navigation")) {
            if (ImGui::MenuItem("Jump to Entry Point", "G", false, pe_file_.has_value())) {
                if (pe_file_) {
                    jump_to_address(pe_file_->get_entry_point_va());
                }
            }
            if (ImGui::MenuItem("View Cross-References (Callers)...", "X", false, selected_address_ != 0)) {
                show_xref_modal_ = true;
                xref_modal_target_va_ = selected_address_;
            }
            if (ImGui::MenuItem("View Control Flow Graph (CFG)...", "C", false, selected_address_ != 0)) {
                open_cfg_view(selected_address_);
            }
            if (ImGui::MenuItem("Navigate Back", "Esc", false, !navigation_history_.empty())) {
                navigate_back();
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Symbols")) {
            if (ImGui::MenuItem("Load Local PDB File...", nullptr, false, pe_file_.has_value())) {
                open_pdb_dialog();
            }
            bool has_cv = pe_file_ && pe_file_->get_debug_codeview_info().has_value();
            if (ImGui::MenuItem("Download from Microsoft Symbol Server...", nullptr, false, has_cv)) {
                download_microsoft_pdb();
            }
            if (ImGui::MenuItem("Unload PDB Symbols", nullptr, false, pdb_loader_.is_loaded())) {
                pdb_loader_.unload();
                pdb_status_text_ = "PDB: None";
                disassemble_active_section();
            }
            ImGui::Separator();
            ImGui::TextDisabled("Status: %s", pdb_status_text_.c_str());
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Patching")) {
            if (ImGui::MenuItem("Fill Selection with NOPs (0x90)", "F2", false, selected_instruction_idx_ >= 0)) {
                trigger_nop_patch_selected();
            }
            if (ImGui::MenuItem("Edit Instruction Bytes...", nullptr, false, selected_instruction_idx_ >= 0)) {
                if (selected_instruction_idx_ >= 0 && selected_instruction_idx_ < static_cast<int>(instructions_.size())) {
                    std::string current_hex = instructions_[selected_instruction_idx_].format_raw_bytes();
                    strncpy_s(edit_bytes_input_, current_hex.c_str(), sizeof(edit_bytes_input_) - 1);
                    show_edit_bytes_modal_ = true;
                }
            }
            if (ImGui::MenuItem("Revert All Patches", nullptr, false, patch_manager_.count() > 0)) {
                if (pe_file_) {
                    patch_manager_.revert_all(*pe_file_);
                    disassemble_active_section();
                    status_message_ = "All patches reverted";
                }
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Help")) {
            if (ImGui::MenuItem("Documentation...", "F1")) {
                show_help_modal_ = true;
            }
            ImGui::EndMenu();
        }

        // Status right aligned
        std::string status = std::format("Status: {} | File: {}", status_message_, current_file_path_);
        float text_width = ImGui::CalcTextSize(status.c_str()).x;
        ImGui::SameLine(ImGui::GetWindowWidth() - text_width - 16.0f);
        ImGui::TextDisabled("%s", status.c_str());

        ImGui::EndMainMenuBar();
    }
}

void Application::render_security_flags_summary() {
    if (!pe_file_) return;
    const auto& sec = pe_file_->get_security_flags();

    // Subsystem Badge
    std::string subsys_name = pe_file_->get_subsystem_name();
    ImVec4 badge_col = ImVec4(0.35f, 0.65f, 0.95f, 1.0f); // Blue default
    if (pe_file_->is_driver())     badge_col = ImVec4(0.95f, 0.55f, 0.15f, 1.0f); // Orange for drivers
    else if (pe_file_->is_uefi()) badge_col = ImVec4(0.85f, 0.25f, 0.85f, 1.0f); // Purple for EFI

    ImGui::TextColored(badge_col, "[%s]", subsys_name.c_str());
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.35f, 0.65f, 0.95f, 1.0f), "PE Security & Mitigations");
    ImGui::Separator();

    auto render_badge = [](const char* name, bool enabled) {
        ImVec4 col = enabled ? ImVec4(0.2f, 0.8f, 0.4f, 1.0f) : ImVec4(0.6f, 0.6f, 0.6f, 0.8f);
        ImGui::TextColored(col, "[%s: %s]", name, enabled ? "ON" : "OFF");
        ImGui::SameLine();
    };

    render_badge("ASLR", sec.aslr);
    render_badge("DEP/NX", sec.dep_nx);
    render_badge("CFG", sec.cfg);
    render_badge("High-Entropy VA", sec.high_entropy_va);
    ImGui::NewLine();
}

void Application::render_sections_panel() {
    ImGui::SetNextWindowSize(ImVec2(360, 420), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("PE Analysis & Sections", nullptr)) {
        if (!pe_file_) {
            if (logo_texture_.is_valid()) {
                float avail_w = ImGui::GetContentRegionAvail().x;
                float logo_h = 190.0f;
                float logo_w = logo_h * (static_cast<float>(logo_texture_.width) / static_cast<float>(logo_texture_.height));
                if (logo_w > avail_w) {
                    logo_w = avail_w;
                    logo_h = logo_w * (static_cast<float>(logo_texture_.height) / static_cast<float>(logo_texture_.width));
                }
                float pad_x = (avail_w - logo_w) * 0.5f;
                if (pad_x > 0.0f) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + pad_x);
                ImGui::Image(reinterpret_cast<ImTextureID>(logo_texture_.srv), ImVec2(logo_w, logo_h));
                ImGui::Spacing();
            }
            ImGui::TextDisabled("No PE binary loaded.");
            ImGui::Spacing();
            if (ImGui::Button("Open PE File...", ImVec2(-1, 30))) {
                open_file_dialog();
            }
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(0.35f, 0.75f, 1.00f, 1.0f), "Quick Reference");
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::BulletText("Drag & drop .exe, .dll, .sys, or .efi binary to analyze");
            ImGui::BulletText("F2: Patch selected instruction with NOP (0x90)");
            ImGui::BulletText("G: Follow branch or jump destination");
            ImGui::BulletText("X: Open cross-references (XREFs)");
            ImGui::BulletText("Esc: Navigate back");
            ImGui::BulletText("Right-Click: Context menu (Patch, SigMaker, Hex View)");
            ImGui::BulletText("Ctrl+S: Export patched binary");
            ImGui::BulletText("F1: Documentation & shortcuts");
        } else {
            render_security_flags_summary();
            ImGui::Spacing();

            if (ImGui::BeginTabBar("LeftPanelTabs")) {
                if (ImGui::BeginTabItem("Sections & Headers")) {
                    ImGui::TextColored(ImVec4(0.35f, 0.65f, 0.95f, 1.0f), "Sections (Shannon Entropy & Layout)");
                    ImGui::Separator();

                    if (ImGui::BeginTable("SectionTableReal", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit, ImVec2(0, 160))) {
                        ImGui::TableSetupColumn("Name");
                        ImGui::TableSetupColumn("RVA");
                        ImGui::TableSetupColumn("Raw Size");
                        ImGui::TableSetupColumn("Perms");
                        ImGui::TableSetupColumn("Entropy");
                        ImGui::TableHeadersRow();

                        for (const auto& sec : pe_file_->get_sections()) {
                            ImGui::TableNextRow();
                            ImGui::TableSetColumnIndex(0);

                            bool is_active_sec = (sec.name == active_section_name_);
                            if (ImGui::Selectable(sec.name.c_str(), is_active_sec, ImGuiSelectableFlags_SpanAllColumns)) {
                                active_section_name_ = sec.name;
                                disassemble_active_section();
                            }

                            ImGui::TableSetColumnIndex(1);
                            ImGui::Text("0x%08X", sec.virtual_address);

                            ImGui::TableSetColumnIndex(2);
                            ImGui::Text("0x%08X", sec.raw_size);

                            ImGui::TableSetColumnIndex(3);
                            std::string perms;
                            if (sec.is_readable) perms += "R";
                            if (sec.is_writable) perms += "W";
                            if (sec.is_executable) perms += "X";
                            ImGui::TextUnformatted(perms.c_str());

                            ImGui::TableSetColumnIndex(4);
                            ImVec4 ent_col = ImVec4(0.2f, 0.8f, 0.4f, 1.0f);
                            if (sec.entropy > 7.0) ent_col = ImVec4(0.95f, 0.2f, 0.2f, 1.0f);
                            else if (sec.entropy > 6.0) ent_col = ImVec4(0.95f, 0.7f, 0.2f, 1.0f);
                            ImGui::TextColored(ent_col, "%.2f", sec.entropy);
                        }
                        ImGui::EndTable();
                    }

                    ImGui::Spacing();
                    // Imports list
                    if (ImGui::CollapsingHeader("Import Address Table (IAT)", ImGuiTreeNodeFlags_DefaultOpen)) {
                        const auto& imports = pe_file_->get_imports();

                        if (imports.empty()) {
                            if (pe_file_->is_uefi()) {
                                ImGui::TextDisabled("No imports found (EFI protocol-based binary).");
                            } else {
                                ImGui::TextDisabled("No imports found.");
                            }
                        } else {
                            ImGui::TextDisabled("Total Imported APIs: %zu", imports.size());

                            if (ImGui::BeginChild("ImportsScroll", ImVec2(0, 160), true)) {
                                std::string current_dll = "";
                                for (const auto& imp : imports) {
                                    if (imp.dll_name != current_dll) {
                                        current_dll = imp.dll_name;
                                        ImGui::TextColored(ImVec4(0.85f, 0.65f, 0.15f, 1.0f), "[%s]", current_dll.c_str());
                                    }

                                    // Kernel API category tag for drivers
                                    std::string category_tag;
                                    if (pe_file_->is_driver()) {
                                        category_tag = get_kernel_api_category(imp.symbol_name);
                                    }

                                    std::string label;
                                    if (!category_tag.empty()) {
                                        label = std::format("  0x{:X} : {} [{}]", imp.iat_va, imp.symbol_name, category_tag);
                                    } else {
                                        label = std::format("  0x{:X} : {}", imp.iat_va, imp.symbol_name);
                                    }

                                    if (ImGui::Selectable(label.c_str())) {
                                        selected_address_ = imp.iat_va;
                                        selected_rva_ = imp.iat_rva;
                                        selected_file_offset_ = pe_file_->rva_to_file_offset(imp.iat_rva);
                                    }
                                }
                            }
                            ImGui::EndChild();
                        }
                    }

                    // Exports list
                    if (!pe_file_->get_exports().empty()) {
                        if (ImGui::CollapsingHeader("Export Address Table (EAT)")) {
                            for (const auto& exp : pe_file_->get_exports()) {
                                std::string label = std::format("  0x{:X} : {} (Ord: {})", exp.va, exp.name, exp.ordinal);
                                if (ImGui::Selectable(label.c_str())) {
                                    jump_to_address(exp.va);
                                }
                            }
                        }
                    }

                    // Keyboard Shortcuts Reference
                    ImGui::Spacing();
                    if (ImGui::CollapsingHeader("Keyboard Shortcuts")) {
                        ImGui::BulletText("F2: Fill instruction with NOP (0x90)");
                        ImGui::BulletText("G: Follow jump / call destination");
                        ImGui::BulletText("X: Cross-references (XREFs)");
                        ImGui::BulletText("Esc: Navigate back");
                        ImGui::BulletText("Right-Click: Context menu (Patch / SigMaker)");
                        ImGui::BulletText("Ctrl+S: Export patched binary");
                        ImGui::BulletText("F1: Technical documentation");
                    }

                    ImGui::EndTabItem();
                }

                std::string fn_tab_name = std::format("Functions ({})###FunctionsTab", function_manager_.get_functions().size());
                if (ImGui::BeginTabItem(fn_tab_name.c_str())) {
                    render_functions_tab();
                    ImGui::EndTabItem();
                }

                size_t str_cnt = analysis_session_ ? analysis_session_->string_db.string_count : 0;
                std::string str_tab_name = std::format("Strings ({})###StringsTab", str_cnt);
                if (ImGui::BeginTabItem(str_tab_name.c_str())) {
                    render_strings_tab();
                    ImGui::EndTabItem();
                }

                ImGui::EndTabBar();
            }
        }
    }
    ImGui::End();
}

void Application::render_functions_tab() {
    // Search / Filter Input
    ImGui::TextDisabled("Filter:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##FnFilter", "Search function name or address...", function_filter_buffer_, sizeof(function_filter_buffer_));
    ImGui::Spacing();

    const auto& fns = function_manager_.get_functions();
    std::string filter = function_filter_buffer_;
    std::transform(filter.begin(), filter.end(), filter.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    std::vector<const analysis::FunctionInfo*> filtered;
    filtered.reserve(fns.size());
    for (const auto& fn : fns) {
        if (filter.empty()) {
            filtered.push_back(&fn);
        } else {
            std::string name_lower = fn.name;
            std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            std::string va_hex = std::format("{:x}", fn.start_va);
            if (name_lower.contains(filter) || va_hex.contains(filter)) {
                filtered.push_back(&fn);
            }
        }
    }

    ImGui::TextDisabled("Showing %zu of %zu functions", filtered.size(), fns.size());
    ImGui::Separator();

    if (ImGui::BeginTable("FunctionsTableReal", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable, ImVec2(0, 0))) {
        ImGui::TableSetupColumn("Function Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Start VA", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 65.0f);
        ImGui::TableSetupColumn("Xrefs", ImGuiTableColumnFlags_WidthFixed, 45.0f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(filtered.size()), ImGui::GetTextLineHeightWithSpacing());

        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const auto* fn = filtered[i];
                ImGui::TableNextRow();

                ImGui::TableSetColumnIndex(0);
                ImVec4 name_col = ImVec4(0.95f, 0.85f, 0.30f, 1.0f); // Yellow default
                if (fn->is_entry_point) name_col = ImVec4(0.35f, 0.90f, 0.45f, 1.0f); // Green
                else if (fn->is_export) name_col = ImVec4(0.85f, 0.45f, 0.90f, 1.0f); // Purple
                else if (fn->is_from_pdata) name_col = ImVec4(0.40f, 0.75f, 1.00f, 1.0f); // Cyan

                bool is_selected = (selected_address_ >= fn->start_va && selected_address_ < fn->start_va + fn->length);
                ImGui::PushStyleColor(ImGuiCol_Text, name_col);
                if (ImGui::Selectable(fn->name.c_str(), is_selected, ImGuiSelectableFlags_SpanAllColumns)) {
                    jump_to_address(fn->start_va);
                }
                if (ImGui::BeginPopupContextItem()) {
                    if (ImGui::MenuItem("Jump to Function")) {
                        jump_to_address(fn->start_va);
                    }
                    if (ImGui::MenuItem("View Control Flow Graph (CFG)", "C")) {
                        open_cfg_view(fn->start_va);
                    }
                    ImGui::EndPopup();
                }
                ImGui::PopStyleColor();

                ImGui::TableSetColumnIndex(1);
                ImGui::Text("0x%010llX", fn->start_va);

                ImGui::TableSetColumnIndex(2);
                ImGui::Text("0x%X", fn->length);

                ImGui::TableSetColumnIndex(3);
                if (fn->xref_count > 0) {
                    ImGui::TextColored(ImVec4(0.40f, 0.90f, 0.45f, 1.0f), "%zu", fn->xref_count);
                } else {
                    ImGui::TextDisabled("-");
                }
            }
        }
        ImGui::EndTable();
    }
}

void Application::render_strings_tab() {
    if (!analysis_session_ || analysis_session_->string_db.string_count == 0) {
        ImGui::TextDisabled("No strings detected. Load a PE binary to analyze strings.");
        return;
    }

    // Search / Filter Input
    ImGui::TextDisabled("Filter:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##StrFilter", "Search string contents or address...", string_filter_buffer_, sizeof(string_filter_buffer_));
    ImGui::Spacing();

    const auto& sdb = analysis_session_->string_db;
    std::string filter = string_filter_buffer_;
    std::transform(filter.begin(), filter.end(), filter.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    std::vector<const IremStringEntry*> filtered;
    filtered.reserve(sdb.string_count);
    for (int i = 0; i < sdb.string_count; ++i) {
        const auto* s = &sdb.strings[i];
        if (filter.empty()) {
            filtered.push_back(s);
        } else {
            std::string preview_lower = s->preview;
            std::transform(preview_lower.begin(), preview_lower.end(), preview_lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            std::string va_hex = std::format("{:x}", s->va);
            if (preview_lower.contains(filter) || va_hex.contains(filter)) {
                filtered.push_back(s);
            }
        }
    }

    ImGui::TextDisabled("Showing %zu of %d strings (Click to inspect / jump):", filtered.size(), sdb.string_count);
    ImGui::Spacing();

    if (ImGui::BeginTable("StringsTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable, ImVec2(0, 0))) {
        ImGui::TableSetupColumn("String Preview", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("Section", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(filtered.size()), ImGui::GetTextLineHeightWithSpacing());

        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const auto* str = filtered[i];
                ImGui::TableNextRow();

                ImGui::TableSetColumnIndex(0);
                std::string display_preview = (str->encoding == IREM_STR_UTF16LE) ? std::format("L\"{}\"", str->preview) : std::format("\"{}\"", str->preview);
                if (ImGui::Selectable(display_preview.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                    // Check if there is a code xref for this string
                    bool jumped = false;
                    for (int x = 0; x < sdb.xref_count; ++x) {
                        if (sdb.xrefs[x].string_va == str->va) {
                            jump_to_address(sdb.xrefs[x].code_va);
                            jumped = true;
                            break;
                        }
                    }
                    if (!jumped) {
                        jump_to_address(str->va);
                    }
                }

                ImGui::TableSetColumnIndex(1);
                if (str->encoding == IREM_STR_UTF16LE) {
                    ImGui::TextColored(ImVec4(0.40f, 0.85f, 1.0f, 1.0f), "UTF16");
                } else {
                    ImGui::TextColored(ImVec4(0.85f, 0.85f, 0.85f, 1.0f), "ASCII");
                }

                ImGui::TableSetColumnIndex(2);
                ImGui::Text("0x%010llX", str->va);

                ImGui::TableSetColumnIndex(3);
                ImGui::TextDisabled("%s", str->section_name);
            }
        }
        ImGui::EndTable();
    }
}

void Application::render_sigmaker_modal() {
    if (show_sigmaker_modal_) {
        ImGui::OpenPopup("AOB SigMaker & Pattern Scanner - Ирем");
        show_sigmaker_modal_ = false;
    }

    ImGui::SetNextWindowSize(ImVec2(720, 380), ImGuiCond_FirstUseEver);
    if (ImGui::BeginPopupModal("AOB SigMaker & Pattern Scanner - Ирем", nullptr, ImGuiWindowFlags_None)) {
        ImGui::TextColored(ImVec4(0.35f, 0.85f, 1.0f, 1.0f), "Wildcard Signature (AOB)");
        ImGui::SameLine();
        ImGui::TextDisabled("(%d bytes)", current_signature_.byte_count);
        ImGui::Separator();
        ImGui::Spacing();

        // Match status badge
        if (current_signature_.is_unique) {
            ImGui::TextColored(ImVec4(0.35f, 0.95f, 0.45f, 1.0f), "[+] Unique: Exactly 1 occurrence found in binary");
        } else if (current_signature_.match_count > 1) {
            ImGui::TextColored(ImVec4(1.0f, 0.80f, 0.25f, 1.0f), "[!] Ambiguous: %d occurrences found (extend selection for uniqueness)", current_signature_.match_count);
        } else {
            ImGui::TextColored(ImVec4(1.0f, 0.40f, 0.40f, 1.0f), "[-] No pattern occurrences found");
        }
        ImGui::Spacing();

        // 1. IDA Pattern
        ImGui::Text("IDA Pattern:");
        ImGui::SetNextItemWidth(540.0f);
        ImGui::InputText("##IdaSig", current_signature_.ida_pattern, sizeof(current_signature_.ida_pattern), ImGuiInputTextFlags_ReadOnly);
        ImGui::SameLine();
        if (ImGui::Button("Copy##Ida", ImVec2(100, 0))) {
            ImGui::SetClipboardText(current_signature_.ida_pattern);
        }

        // 2. Cheat Engine Style
        ImGui::Text("Cheat Engine (AOB):");
        ImGui::SetNextItemWidth(540.0f);
        ImGui::InputText("##CeSig", current_signature_.ce_pattern, sizeof(current_signature_.ce_pattern), ImGuiInputTextFlags_ReadOnly);
        ImGui::SameLine();
        if (ImGui::Button("Copy##Ce", ImVec2(100, 0))) {
            ImGui::SetClipboardText(current_signature_.ce_pattern);
        }

        // 3. C/C++ Escaped Array & Mask
        ImGui::Text("C/C++ Escaped Array & Mask:");
        ImGui::SetNextItemWidth(540.0f);
        std::string c_full = std::format("Pattern: \"{}\"  Mask: \"{}\"", current_signature_.c_byte_escaped, current_signature_.c_mask);
        ImGui::InputText("##CSig", c_full.data(), c_full.size(), ImGuiInputTextFlags_ReadOnly);
        ImGui::SameLine();
        if (ImGui::Button("Copy##C", ImVec2(100, 0))) {
            ImGui::SetClipboardText(c_full.c_str());
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Button("Close", ImVec2(120, 0)) || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }
}

void Application::render_xref_modal() {
    if (show_xref_modal_) {
        ImGui::OpenPopup("Cross-References (XREFs) - Ирем");
        show_xref_modal_ = false;
    }

    ImGui::SetNextWindowSize(ImVec2(740, 420), ImGuiCond_FirstUseEver);
    if (ImGui::BeginPopupModal("Cross-References (XREFs) - Ирем", nullptr, ImGuiWindowFlags_None)) {
        const auto* enclosing_target = function_manager_.find_enclosing_function(xref_modal_target_va_);
        std::string target_desc = enclosing_target ? enclosing_target->name : std::format("0x{:X}", xref_modal_target_va_);
        if (enclosing_target && xref_modal_target_va_ != enclosing_target->start_va) {
            target_desc += std::format("+0x{:X}", xref_modal_target_va_ - enclosing_target->start_va);
        }

        ImGui::TextColored(ImVec4(0.35f, 0.75f, 1.0f, 1.0f), "Cross-References to: ");
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1.0f, 0.85f, 0.2f, 1.0f), "%s", target_desc.c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("(0x%llX)", xref_modal_target_va_);
        ImGui::Separator();
        ImGui::Spacing();

        const auto* xrefs = xref_manager_.get_xrefs_to(xref_modal_target_va_);
        if (!xrefs || xrefs->empty()) {
            ImGui::TextDisabled("No cross-references found for this address.");
            ImGui::Spacing();
            if (ImGui::Button("Close", ImVec2(120, 0)) || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
                ImGui::CloseCurrentPopup();
            }
        } else {
            ImGui::Text("Found %zu references (Click row to jump, Esc to close):", xrefs->size());
            ImGui::Spacing();

            if (ImGui::BeginTable("XrefTableReal", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable, ImVec2(0, 260))) {
                ImGui::TableSetupColumn("Calling Function / Location", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 110.0f);
                ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 130.0f);
                ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthFixed, 160.0f);
                ImGui::TableHeadersRow();

                for (size_t i = 0; i < xrefs->size(); ++i) {
                    const auto& ref = (*xrefs)[i];
                    ImGui::TableNextRow();

                    ImGui::TableSetColumnIndex(0);
                    bool selected = false;
                    if (ImGui::Selectable(ref.source_func_name.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns)) {
                        jump_to_address(ref.source_va);
                        ImGui::CloseCurrentPopup();
                    }

                    ImGui::TableSetColumnIndex(1);
                    ImVec4 type_col = ImVec4(0.35f, 0.8f, 1.0f, 1.0f);
                    if (ref.type == analysis::XrefType::Call) type_col = ImVec4(0.35f, 0.9f, 0.45f, 1.0f);
                    else if (ref.type == analysis::XrefType::JumpConditional) type_col = ImVec4(1.0f, 0.7f, 0.2f, 1.0f);
                    ImGui::TextColored(type_col, "%s", ref.type_name().c_str());

                    ImGui::TableSetColumnIndex(2);
                    ImGui::Text("0x%010llX", ref.source_va);

                    ImGui::TableSetColumnIndex(3);
                    ImGui::TextDisabled("%s", ref.instruction_text.c_str());
                }
                ImGui::EndTable();
            }

            ImGui::Spacing();
            if (ImGui::Button("Close", ImVec2(120, 0)) || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
                ImGui::CloseCurrentPopup();
            }
        }

        ImGui::EndPopup();
    }
}

void Application::render_disassembly_panel() {
    ImGui::SetNextWindowSize(ImVec2(720, 520), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("Disassembly###Disassembly (Irem View)", nullptr)) {
        if (instructions_.empty()) {
            ImGui::TextDisabled("No instructions decoded in active section (%s). Load a binary to begin.", active_section_name_.c_str());
        } else {
            ImDrawList* draw_list = ImGui::GetWindowDrawList();

            ImGui::TextDisabled("Gutter   Address                 Raw Bytes            Mnem   Operands                      Comment");
            ImGui::Separator();

            const float row_height = ImGui::GetTextLineHeightWithSpacing();
            const float gutter_width = 36.0f;

            if (ImGui::BeginChild("DisasmScrollRegion", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar)) {
                ImGuiListClipper clipper;
                clipper.Begin(static_cast<int>(instructions_.size()), row_height);

                // Track screen positions for visible instructions
                std::unordered_map<uint64_t, ImVec2> visible_positions;
                ImVec2 content_start_pos = ImGui::GetCursorScreenPos();

                while (clipper.Step()) {
                    const float line_h = ImGui::GetTextLineHeight();
                    const float half_spacing = (row_height - line_h) * 0.5f;

                    for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                        auto& ins = instructions_[i];
                        ImVec2 line_pos = ImGui::GetCursorScreenPos();
                        visible_positions[ins.va] = line_pos;

                        bool is_selected = (selected_instruction_idx_ == i);

                        // Auto-scroll request
                        if (scroll_to_selected_ && is_selected) {
                            ImGui::SetScrollHereY(0.35f);
                            scroll_to_selected_ = false;
                        }

                        // Row selection highlight (perfectly vertically centered with row height)
                        if (is_selected) {
                            ImVec2 r_min = ImVec2(line_pos.x, line_pos.y - half_spacing);
                            ImVec2 r_max = ImVec2(line_pos.x + ImGui::GetWindowWidth() + 400.0f, line_pos.y + line_h + half_spacing);
                            draw_list->AddRectFilled(r_min, r_max, IM_COL32(36, 43, 56, 160));
                        }

                        // Patched highlight (perfectly vertically centered with row height)
                        if (ins.is_patched) {
                            ImVec2 r_min = ImVec2(line_pos.x, line_pos.y - half_spacing);
                            ImVec2 r_max = ImVec2(line_pos.x + ImGui::GetWindowWidth() + 400.0f, line_pos.y + line_h + half_spacing);
                            draw_list->AddRectFilled(r_min, r_max, ui::colors::PatchedBg);
                        }

                        // Gutter blank space for ImDrawList jump arrows
                        ImGui::Dummy(ImVec2(gutter_width, line_h));
                        ImGui::SameLine();

                        // Address Column (.text:0000000140001000)
                        std::string addr_str = std::format("{}:{:016X}", active_section_name_, ins.va);
                        ImVec2 addr_cursor_pos = ImGui::GetCursorScreenPos();
                        ImVec2 text_sz = ImGui::CalcTextSize(addr_str.c_str());

                        // Symmetrical bubble bounds: exactly 6px padding horizontally, exactly 2px padding vertically
                        const float pad_x = 6.0f;
                        const float pad_y = 2.0f;
                        const float bubble_rounding = 3.5f;
                        ImVec2 bubble_min = ImVec2(addr_cursor_pos.x - pad_x, addr_cursor_pos.y - pad_y);
                        ImVec2 bubble_max = ImVec2(addr_cursor_pos.x + text_sz.x + pad_x, addr_cursor_pos.y + line_h + pad_y);

                        // Render background bubble BEFORE text so text renders cleanly on top
                        if (is_selected) {
                            // Selected: Crisp, symmetrical bubble badge with smooth rounded corners and border
                            draw_list->AddRectFilled(bubble_min, bubble_max, IM_COL32(52, 75, 110, 240), bubble_rounding);
                            draw_list->AddRect(bubble_min, bubble_max, IM_COL32(95, 140, 205, 255), bubble_rounding, 0, 1.0f);
                        } else if (ImGui::IsMouseHoveringRect(bubble_min, bubble_max)) {
                            // Hovered: Subtle translucent symmetrical bubble
                            draw_list->AddRectFilled(bubble_min, bubble_max, IM_COL32(42, 54, 75, 180), bubble_rounding);
                            draw_list->AddRect(bubble_min, bubble_max, IM_COL32(75, 105, 150, 180), bubble_rounding, 0, 1.0f);
                        }

                        // Push transparent header colors so ImGui's built-in 200px asymmetric box is never drawn
                        ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(0, 0, 0, 0));
                        ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(0, 0, 0, 0));
                        ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImVec4(0, 0, 0, 0));
                        ImGui::PushStyleColor(ImGuiCol_Text, is_selected ? IM_COL32(245, 248, 255, 255) : ui::colors::Address);

                        if (ImGui::Selectable(addr_str.c_str(), false, ImGuiSelectableFlags_None, ImVec2(200, 0))) {
                            selected_instruction_idx_ = i;
                            selected_address_ = ins.va;
                            selected_rva_ = ins.rva;
                            selected_file_offset_ = ins.file_offset;
                        }
                        ImGui::PopStyleColor(4);

                        // Context Menu on right click
                        if (ImGui::BeginPopupContextItem()) {
                            selected_instruction_idx_ = i;
                            selected_address_ = ins.va;
                            selected_rva_ = ins.rva;
                            selected_file_offset_ = ins.file_offset;

                            if (ImGui::MenuItem("Fill with NOPs (0x90)", "F2")) {
                                trigger_nop_patch_selected();
                            }
                            if (ImGui::MenuItem("Edit Instruction Bytes...")) {
                                std::string current_hex = ins.format_raw_bytes();
                                strncpy_s(edit_bytes_input_, current_hex.c_str(), sizeof(edit_bytes_input_) - 1);
                                show_edit_bytes_modal_ = true;
                            }
                            ImGui::Separator();
                            size_t xcnt = xref_manager_.get_xref_count(ins.va);
                            std::string xref_label = std::format("Cross-References (XREFs) [{}]", xcnt);
                            if (ImGui::MenuItem(xref_label.c_str(), "X")) {
                                show_xref_modal_ = true;
                                xref_modal_target_va_ = ins.va;
                            }
                            if (ImGui::MenuItem("View Control Flow Graph (CFG)", "C")) {
                                open_cfg_view(ins.va);
                            }
                            if (ImGui::MenuItem("Generate AOB Pattern...")) {
                                auto flat = engines::flatten_instructions(instructions_);
                                size_t end_idx = (std::min)((size_t)i + 4, flat.size() - 1);
                                if (irem_sigmaker_generate(flat.data(), flat.size(), i, end_idx, &current_signature_)) {
                                    if (pe_file_) {
                                        const auto* code_sec = pe_file_->get_code_section();
                                        if (code_sec) {
                                            IremScanMatch matches[16];
                                            current_signature_.match_count = irem_aob_scan(
                                                pe_file_->get_raw_bytes().data(),
                                                pe_file_->get_raw_bytes().size(),
                                                pe_file_->get_image_base(),
                                                code_sec->raw_offset,
                                                code_sec->raw_size,
                                                code_sec->virtual_address,
                                                current_signature_.bytes,
                                                current_signature_.byte_count,
                                                matches,
                                                16
                                            );
                                            current_signature_.is_unique = (current_signature_.match_count == 1);
                                            if (current_signature_.match_count > 0) {
                                                current_signature_.first_match_va = matches[0].match_va;
                                            }
                                        }
                                    }
                                    show_sigmaker_modal_ = true;
                                }
                            }
                            ImGui::Separator();
                            if (ins.is_jump || ins.is_call) {
                                if (ImGui::MenuItem("Follow Target (G)")) {
                                    jump_to_address(ins.branch_target_va);
                                }
                            }
                            if (ImGui::MenuItem("Navigate Back (Esc)", nullptr, false, !navigation_history_.empty())) {
                                navigate_back();
                            }
                            if (ImGui::MenuItem("Sync in Hex View")) {
                                selected_file_offset_ = ins.file_offset;
                            }
                            ImGui::EndPopup();
                        }

                        // Raw Bytes Column
                        ImGui::SameLine();
                        std::string bytes_str = ins.format_raw_bytes();
                        ImGui::PushStyleColor(ImGuiCol_Text, ins.is_patched ? ui::colors::PatchedByte : ui::colors::RawBytes);
                        ImGui::Text("%-16s", bytes_str.c_str());
                        ImGui::PopStyleColor();

                        // Mnemonic Column (e.g. mov, call, jne)
                        ImGui::SameLine();
                        ImGui::PushStyleColor(ImGuiCol_Text, ui::colors::Mnemonic);
                        ImGui::Text("%-7s", ins.mnemonic.c_str());
                        ImGui::PopStyleColor();

                        // Operands Column
                        ImGui::SameLine();
                        std::string ops_str = ins.format_operands();
                        ImGui::PushStyleColor(ImGuiCol_Text, ui::colors::Register);
                        ImGui::Text("%-26s", ops_str.c_str());
                        ImGui::PopStyleColor();

                        // Comment Column (API name / sub_xxx / user note / Function Entry / Xrefs)
                        std::string full_comment = ins.comment;
                        const auto* fn_start = function_manager_.find_function_by_va(ins.va);
                        if (fn_start) {
                            std::string fn_prefix = std::format("<{}>", fn_start->name);
                            full_comment = fn_prefix + (full_comment.empty() ? "" : (" | " + full_comment));
                        }
                        size_t xcnt_display = xref_manager_.get_xref_count(ins.va);
                        if (xcnt_display > 0) {
                            std::string xref_tag = std::format("[{} XREFs]", xcnt_display);
                            full_comment = (full_comment.empty() ? "" : (full_comment + " ")) + xref_tag;
                        }

                        if (!full_comment.empty()) {
                            ImGui::SameLine();
                            ImU32 text_col = fn_start ? IM_COL32(245, 215, 75, 255) : ui::colors::Comment;
                            ImGui::PushStyleColor(ImGuiCol_Text, text_col);
                            ImGui::Text("; %s", full_comment.c_str());
                            ImGui::PopStyleColor();
                        }
                    }
                }

                // Draw IDA-style orthogonal jump arrows with ImDrawList
                const float arrow_line_h = ImGui::GetTextLineHeight();
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                    const auto& ins = instructions_[i];
                    if ((ins.is_jump || ins.is_conditional_jump) && ins.branch_target_va != 0) {
                        auto it_src = visible_positions.find(ins.va);
                        if (it_src == visible_positions.end()) continue;

                        ImVec2 src_pos = it_src->second;
                        float src_y = src_pos.y + (arrow_line_h * 0.5f);

                        // Determine arrow color
                        ImU32 arrow_col = ui::colors::JumpUnconditional; // Blue
                        if (ins.is_conditional_jump) {
                            arrow_col = (ins.branch_target_va > ins.va) ? ui::colors::JumpTaken : ui::colors::JumpNotTaken; // Green / Red
                        }

                        // Check if target is visible
                        auto it_dst = visible_positions.find(ins.branch_target_va);
                        if (it_dst != visible_positions.end()) {
                            float dst_y = it_dst->second.y + (arrow_line_h * 0.5f);
                            float gutter_x = src_pos.x + 12.0f;
                            float gutter_right = src_pos.x + gutter_width - 4.0f;

                            // Orthogonal IDA-style routing
                            // 1. Line out to gutter
                            draw_list->AddLine(ImVec2(gutter_right, src_y), ImVec2(gutter_x, src_y), arrow_col, 1.5f);
                            // 2. Line vertical in gutter
                            draw_list->AddLine(ImVec2(gutter_x, src_y), ImVec2(gutter_x, dst_y), arrow_col, 1.5f);
                            // 3. Line in to target
                            draw_list->AddLine(ImVec2(gutter_x, dst_y), ImVec2(gutter_right, dst_y), arrow_col, 1.5f);

                            // 4. Triangle Arrowhead at target
                            draw_list->AddTriangleFilled(
                                ImVec2(gutter_right, dst_y),
                                ImVec2(gutter_right - 5.0f, dst_y - 4.0f),
                                ImVec2(gutter_right - 5.0f, dst_y + 4.0f),
                                arrow_col
                            );
                        } else {
                            // Target offscreen: draw stub arrow pointing up or down
                            float gutter_x = src_pos.x + 12.0f;
                            float gutter_right = src_pos.x + gutter_width - 4.0f;
                            bool target_below = ins.branch_target_va > ins.va;
                            float offscreen_y = target_below ? (src_y + 16.0f) : (src_y - 16.0f);

                            draw_list->AddLine(ImVec2(gutter_right, src_y), ImVec2(gutter_x, src_y), arrow_col, 1.5f);
                            draw_list->AddLine(ImVec2(gutter_x, src_y), ImVec2(gutter_x, offscreen_y), arrow_col, 1.5f);
                        }
                    }
                }

                clipper.End();
            }
            ImGui::EndChild();
        }
    }
    ImGui::End();
}

void Application::render_hex_view_panel() {
    ImGui::SetNextWindowSize(ImVec2(520, 240), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("Hex View & Memory", nullptr)) {
        ImGui::TextDisabled("Offset (h)   00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  Decoded ASCII");
        ImGui::Separator();

        const uint8_t* byte_ptr = nullptr;
        size_t total_bytes = 0;
        uint32_t base_offset = selected_file_offset_;

        if (pe_file_) {
            const auto& raw = pe_file_->get_raw_bytes();
            byte_ptr = raw.data();
            total_bytes = raw.size();
        }

        base_offset = (base_offset / 16) * 16;

        for (int line = 0; line < 12; ++line) {
            uint32_t line_offset = base_offset + (line * 16);
            if (line_offset >= total_bytes && pe_file_) break;

            std::string line_str = std::format("{:08X}   ", line_offset);

            // Hex values
            for (int b = 0; b < 16; ++b) {
                uint32_t current_byte_offset = line_offset + b;
                if (b == 8) line_str += " ";

                if (byte_ptr && current_byte_offset < total_bytes) {
                    line_str += std::format("{:02X} ", byte_ptr[current_byte_offset]);
                } else if (!byte_ptr) {
                    uint8_t demo_byte = static_cast<uint8_t>((line * 16 + b) ^ 0x48);
                    line_str += std::format("{:02X} ", demo_byte);
                } else {
                    line_str += "   ";
                }
            }
            line_str += " ";

            // ASCII values
            for (int b = 0; b < 16; ++b) {
                uint32_t current_byte_offset = line_offset + b;
                uint8_t val = 0;
                if (byte_ptr && current_byte_offset < total_bytes) {
                    val = byte_ptr[current_byte_offset];
                } else if (!byte_ptr) {
                    val = static_cast<uint8_t>((line * 16 + b) ^ 0x48);
                } else {
                    line_str += ' ';
                    continue;
                }
                line_str += (val >= 32 && val <= 126) ? static_cast<char>(val) : '.';
            }

            ImGui::TextUnformatted(line_str.c_str());
        }
    }
    ImGui::End();
}

void Application::render_patch_panel() {
    ImGui::SetNextWindowSize(ImVec2(400, 240), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("Patch Manager & Diff", nullptr)) {
        size_t patch_count = patch_manager_.count();
        ImGui::TextColored(ImVec4(0.95f, 0.40f, 0.50f, 1.0f), "Applied Patches (%zu modifications)", patch_count);
        ImGui::Separator();

        if (ImGui::BeginTable("PatchTableReal", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, 140))) {
            ImGui::TableSetupColumn("Time");
            ImGui::TableSetupColumn("Address");
            ImGui::TableSetupColumn("Original");
            ImGui::TableSetupColumn("Patched");
            ImGui::TableSetupColumn("Action");
            ImGui::TableHeadersRow();

            const auto& patches = patch_manager_.get_patches();
            int patch_to_revert = -1;

            for (size_t i = 0; i < patches.size(); ++i) {
                const auto& p = patches[i];
                ImGui::TableNextRow();

                ImGui::TableSetColumnIndex(0);
                ImGui::TextUnformatted(p.time_str.c_str());

                ImGui::TableSetColumnIndex(1);
                ImGui::Text("0x%llX", p.va);

                ImGui::TableSetColumnIndex(2);
                std::string orig_str;
                for (uint8_t b : p.original_bytes) orig_str += std::format("{:02X} ", b);
                ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "%s", orig_str.c_str());

                ImGui::TableSetColumnIndex(3);
                std::string patch_str;
                for (uint8_t b : p.patched_bytes) patch_str += std::format("{:02X} ", b);
                ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.4f, 1.0f), "%s", patch_str.c_str());

                ImGui::TableSetColumnIndex(4);
                std::string btn_id = std::format("Revert##{}", i);
                if (ImGui::SmallButton(btn_id.c_str())) {
                    patch_to_revert = static_cast<int>(i);
                }
            }

            if (patch_to_revert >= 0 && pe_file_) {
                patch_manager_.revert_patch(static_cast<size_t>(patch_to_revert), *pe_file_);
                disassemble_active_section();
                status_message_ = "Patch reverted";
            }

            ImGui::EndTable();
        }

        ImGui::Spacing();
        if (ImGui::Button("Fill Selection with NOPs (0x90) [F2]", ImVec2(-1, 0))) {
            trigger_nop_patch_selected();
        }

        if (ImGui::Button("Export Patched Binary... [Ctrl+S]", ImVec2(-1, 0))) {
            save_patched_file_dialog();
        }
    }
    ImGui::End();
}

void Application::render_edit_bytes_modal() {
    if (show_edit_bytes_modal_) {
        ImGui::OpenPopup("Edit Instruction Bytes");
        show_edit_bytes_modal_ = false;
    }

    if (ImGui::BeginPopupModal("Edit Instruction Bytes", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Enter hex bytes (e.g. 90 90, 31 C0, EB 10):");
        ImGui::Spacing();

        ImGui::SetNextItemWidth(300);
        bool enter_pressed = ImGui::InputText("##HexInput", edit_bytes_input_, sizeof(edit_bytes_input_), ImGuiInputTextFlags_EnterReturnsTrue);

        auto parsed = patch::PatchManager::parse_hex_string(edit_bytes_input_);
        ImGui::TextDisabled("Parsed: %zu bytes", parsed.size());

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if ((ImGui::Button("Apply Patch", ImVec2(120, 0)) || enter_pressed) && !parsed.empty()) {
            if (pe_file_ && selected_instruction_idx_ >= 0 && selected_instruction_idx_ < static_cast<int>(instructions_.size())) {
                auto& ins = instructions_[selected_instruction_idx_];
                if (patch_manager_.apply_custom_bytes(*pe_file_, ins.file_offset, ins.rva, ins.va, parsed, "Custom Hex Edit")) {
                    // Re-decode patched area
                    auto raw_span = pe_file_->get_bytes_at_rva(ins.rva, parsed.size());
                    disasm::Instruction new_ins = decoder_.decode_instruction(raw_span, ins.va, ins.rva, ins.file_offset, &(*pe_file_));
                    new_ins.is_patched = true;
                    new_ins.comment = "PATCHED: Custom edit";
                    instructions_[selected_instruction_idx_] = std::move(new_ins);
                    status_message_ = std::format("Wrote {} bytes to 0x{:X}", parsed.size(), ins.va);
                }
            }
            ImGui::CloseCurrentPopup();
        }

        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0))) {
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }
}

void Application::render_help_modal() {
    if (show_help_modal_) {
        ImGui::OpenPopup("About & Documentation - Irem");
        show_help_modal_ = false;
    }

    ImGui::SetNextWindowSize(ImVec2(760, 560), ImGuiCond_FirstUseEver);
    if (ImGui::BeginPopupModal("About & Documentation - Irem", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        // Banner Header with Logo
        if (logo_texture_.is_valid()) {
            float logo_h = 120.0f;
            float logo_w = logo_h * (static_cast<float>(logo_texture_.width) / static_cast<float>(logo_texture_.height));
            ImGui::Image(reinterpret_cast<ImTextureID>(logo_texture_.srv), ImVec2(logo_w, logo_h));
            ImGui::SameLine();
            ImGui::BeginGroup();
        }

        ImGui::TextColored(ImVec4(0.35f, 0.75f, 1.00f, 1.0f), "(Irem) - x86_64 Disassembler & Binary Patching Studio");
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::TextDisabled("Author:");
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1.00f, 0.85f, 0.20f, 1.0f), "mina");

        ImGui::TextDisabled("Target:");
        ImGui::SameLine();
        ImGui::TextUnformatted("Windows x86_64");

        ImGui::TextDisabled("Architecture:");
        ImGui::SameLine();
        ImGui::TextUnformatted("Analysis Engines | Windows | X86_64/UEFI / ImGui");

        if (logo_texture_.is_valid()) {
            ImGui::EndGroup();
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::BeginTabBar("HelpTabs")) {
            if (ImGui::BeginTabItem("Overview")) {
                ImGui::Spacing();
                ImGui::TextWrapped(
                    "Native x86_64 static analysis and binary patching utility engineered for "
                    "Windows executables, kernel-mode drivers, and UEFI firmware binaries. "
                    "Features linear and recursive disassembly, backward dataflow calling convention recovery, "
                    "runtime exception frame parsing (.pdata), and in-memory byte patching with direct PE export."
                );
                ImGui::Spacing();
                ImGui::TextColored(ImVec4(0.35f, 0.85f, 0.45f, 1.0f), "Core Specifications:");
                ImGui::BulletText("Target: Windows x86_64 PE32+ (UEFI)");
                ImGui::BulletText("Disassembly: Intel syntax with RIP-relative and register-indirect operand decoding");
                ImGui::BulletText("Symbols: Win32/NT IAT/EAT symbols, local PDBs, and Microsoft Symbol Server");
                ImGui::BulletText("Analysis: 10 static analysis engines");
                ImGui::BulletText("Patching: Real-time byte modification, diff tracking, and PE disk writer");
                ImGui::BulletText("Renderer: Direct3D 11 with Dear ImGui, interactive CFG graph & jump routing");
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Keyboard Shortcuts")) {
                ImGui::Spacing();
                if (ImGui::BeginTable("ShortcutsTable", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
                    ImGui::TableSetupColumn("Key / Input", ImGuiTableColumnFlags_WidthFixed, 140.0f);
                    ImGui::TableSetupColumn("Action");
                    ImGui::TableHeadersRow();

                    auto add_row = [](const char* key, const char* desc) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::TextColored(ImVec4(0.35f, 0.85f, 0.45f, 1.0f), "%s", key);
                        ImGui::TableSetColumnIndex(1);
                        ImGui::TextUnformatted(desc);
                    };

                    add_row("F1", "Open documentation and keybindings");
                    add_row("F2", "Fill selected instruction with NOPs (0x90)");
                    add_row("C", "Open interactive Control Flow Graph (CFG) view");
                    add_row("G", "Follow branch / jump target, or jump to entry point");
                    add_row("X", "Open cross-references (XREFs / callers)");
                    add_row("Esc", "Navigate back in jump history");
                    add_row("Ctrl + O", "Open PE binary (.exe, .dll, .sys, .efi)");
                    add_row("Ctrl + S", "Export patched binary to disk");
                    add_row("Right-Click", "Instruction context menu (Hex edit, SigMaker, Hex view)");
                    add_row("Drag & Drop", "Drop binary file into window to disassemble");

                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Analysis Engines")) {
                ImGui::Spacing();
                if (ImGui::BeginTable("EnginesTable", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
                    ImGui::TableSetupColumn("Engine", ImGuiTableColumnFlags_WidthFixed, 180.0f);
                    ImGui::TableSetupColumn("Technical Description");
                    ImGui::TableHeadersRow();

                    auto add_engine_row = [](const char* name, const char* desc) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::TextColored(ImVec4(0.35f, 0.85f, 1.0f, 1.0f), "%s", name);
                        ImGui::TableSetColumnIndex(1);
                        ImGui::TextUnformatted(desc);
                    };

                    add_engine_row("Fastcall Analyzer", "Backward dataflow recovery of x64 calling conventions (RCX, RDX, R8, R9, stack shadow).");
                    add_engine_row("Jump Table Resolver", "Resolution of relative (rel32) and direct (abs64) switch dispatch tables.");
                    add_engine_row("Unwind Parser", "PE32+ .pdata UNWIND_INFO deep parsing for stack frames, alloc sizes, and prolog bounds.");
                    add_engine_row("CFG Builder", "Basic block partitioning, control-flow edge categorization, and cyclomatic complexity.");
                    add_engine_row("String Scanner", "ASCII and UTF-16LE literal extraction with RIP-relative instruction cross-referencing.");
                    add_engine_row("WinAPI Database", "Bitmask decomposition, parameter semantics, and risk classification for Win32 and NT APIs.");
                    add_engine_row("SigMaker", "Wildcard pattern generation (IDA, Cheat Engine, C array) with SIMD-accelerated verification.");
                    add_engine_row("Struct Resolver", "x64 TEB, PEB, KPCR, KTHREAD field resolution via gs: segment and multi-level pointer dereferences.");
                    add_engine_row("API Hash Resolver", "Signatureless detection of ROR13, DJB2, FNV-1a, and CRC32 API hashing in obfuscated binaries and shellcode.");
                    add_engine_row("CFG Layout Engine", "Sugiyama-style layered hierarchical control flow graph layout with orthogonal routing and collision avoidance.");

                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("CLI Mode")) {
                ImGui::Spacing();
                ImGui::TextWrapped("The exact same Irem.exe executable can be operated entirely headlessly from PowerShell or cmd.exe by invoking any recognized command verb:");
                ImGui::Spacing();
                ImGui::BulletText("irem help                 -- Display CLI command reference");
                ImGui::BulletText("irem analyze <target>     -- Generate complete PE and engine analysis report");
                ImGui::BulletText("irem disasm <bin> [va]    -- Print disassembled instructions with comments");
                ImGui::BulletText("irem hash <0xHEX>         -- Identify API name from ROR13/DJB2/CRC32 hash");
                ImGui::BulletText("irem cfg <target> <va>    -- Dump basic blocks and CFG edge topology");
                ImGui::BulletText("irem patch <bin> <va> <\"hex\"> -o <out> -- Patch opcodes and write binary");
                ImGui::BulletText("irem entropy <target>     -- Shannon entropy scan for packer detection");
                ImGui::EndTabItem();
            }

            ImGui::EndTabBar();
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Button("Close", ImVec2(120, 30)) || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }
}

std::string Application::get_kernel_api_category(const std::string& api_name) {
    if (api_name.starts_with("Mm") || api_name.starts_with("ExAllocate") || api_name.starts_with("ExFree")) return "Memory";
    if (api_name.starts_with("Io") || api_name.starts_with("Iof")) return "I/O";
    if (api_name.starts_with("Ke")) return "Kernel / Sync";
    if (api_name.starts_with("Ps")) return "Process / Thread";
    if (api_name.starts_with("Ob")) return "Object";
    if (api_name.starts_with("Zw") || api_name.starts_with("Nt")) return "System Service";
    if (api_name.starts_with("Rtl")) return "Rtl Runtime";
    if (api_name.starts_with("Hal") || api_name.starts_with("READ_PORT") || api_name.starts_with("WRITE_PORT")) return "HAL";
    if (api_name.starts_with("Se")) return "Security";
    if (api_name.starts_with("Wdf")) return "KMDF";
    return "";
}

void Application::open_cfg_view(uint64_t func_va) {
    if (!pe_file_ || instructions_.empty()) {
        status_message_ = "No binary loaded";
        return;
    }
    if (!analysis_session_) {
        status_message_ = "Analysis session not ready";
        return;
    }

    const analysis::FunctionInfo* fn = function_manager_.find_function_by_va(func_va);
    if (!fn) {
        fn = function_manager_.find_enclosing_function(func_va);
    }
    if (!fn) {
        status_message_ = std::format("No function found containing 0x{:X}", func_va);
        return;
    }

    uint64_t target_va = fn->start_va;
    auto it = analysis_session_->function_cfgs.find(target_va);
    if (it == analysis_session_->function_cfgs.end() || it->second.block_count == 0) {
        status_message_ = std::format("No CFG blocks available for function {}", fn->name);
        return;
    }

    const IremCFG& cfg = it->second;

    auto flat = engines::flatten_instructions(instructions_);
    float char_w = ImGui::GetFontSize() * 0.55f;
    float line_h = ImGui::GetTextLineHeightWithSpacing();

    irem_cfg_layout_free(&cfg_layout_);
    irem_cfg_layout_init(&cfg_layout_);

    if (irem_cfg_layout_compute(&cfg_layout_, &cfg, flat.data(), flat.size(), char_w, line_h)) {
        cfg_view_func_va_ = target_va;
        show_cfg_view_ = true;
        cfg_selected_block_ = -1;
        cfg_hovered_block_ = -1;
        cfg_zoom_ = 1.0f;
        cfg_pan_x_ = 80.0f;
        cfg_pan_y_ = 60.0f;
        status_message_ = std::format("Opened CFG for {} ({} blocks, {} edges)", fn->name, cfg.block_count, cfg.edge_count);
    } else {
        status_message_ = "Failed to calculate CFG layout";
    }
}

void Application::render_cfg_view() {
    if (!show_cfg_view_) return;

    ImGui::SetNextWindowSize(ImVec2(1050, 720), ImGuiCond_FirstUseEver);
    std::string win_title = "Control Flow Graph (CFG)";
    const analysis::FunctionInfo* fn = function_manager_.find_function_by_va(cfg_view_func_va_);
    if (fn) {
        win_title += std::format(" - {} (0x{:010X})###CFGWindow", fn->name, fn->start_va);
    } else {
        win_title += "###CFGWindow";
    }

    if (!ImGui::Begin(win_title.c_str(), &show_cfg_view_, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
        ImGui::End();
        return;
    }

    if (!analysis_session_ || cfg_layout_.node_count == 0) {
        ImGui::TextDisabled("No CFG data loaded for current function.");
        ImGui::End();
        return;
    }

    auto it = analysis_session_->function_cfgs.find(cfg_view_func_va_);
    if (it == analysis_session_->function_cfgs.end()) {
        ImGui::TextDisabled("CFG data unavailable.");
        ImGui::End();
        return;
    }
    const IremCFG& cfg = it->second;

    // --- Toolbar ---
    ImGui::TextColored(ImVec4(0.35f, 0.75f, 1.0f, 1.0f), "%s", fn ? fn->name.c_str() : "Function CFG");
    ImGui::SameLine();
    ImGui::TextDisabled("| Blocks: %d | Edges: %d | Zoom: %.0f%%", cfg_layout_.node_count, cfg_layout_.edge_count, cfg_zoom_ * 100.0f);
    ImGui::SameLine();

    if (ImGui::SmallButton(" - ")) {
        cfg_zoom_ = (std::max)(cfg_zoom_ * 0.85f, 0.2f);
    }
    ImGui::SameLine();
    if (ImGui::SmallButton(" + ")) {
        cfg_zoom_ = (std::min)(cfg_zoom_ * 1.15f, 3.0f);
    }
    ImGui::SameLine();
    if (ImGui::SmallButton(" 100% ")) {
        cfg_zoom_ = 1.0f;
    }
    ImGui::SameLine();
    if (ImGui::SmallButton(" Center Graph ")) {
        cfg_zoom_ = 1.0f;
        ImVec2 avail = ImGui::GetContentRegionAvail();
        cfg_pan_x_ = avail.x * 0.5f - (cfg_layout_.bounds_min_x + cfg_layout_.total_width * 0.5f);
        cfg_pan_y_ = 40.0f;
    }
    ImGui::SameLine();
    if (cfg_selected_block_ >= 0 && cfg_selected_block_ < cfg.block_count) {
        if (ImGui::SmallButton(" Jump to Selected Block ")) {
            jump_to_address(cfg.blocks[cfg_selected_block_].start_va);
        }
        ImGui::SameLine();
    }
    ImGui::TextDisabled("(Pan: Mid/Right-drag | Zoom: Wheel | Jump: Double-click)");

    ImGui::Separator();

    // --- Canvas Area ---
    ImVec2 canvas_p0 = ImGui::GetCursorScreenPos();
    ImVec2 canvas_sz = ImGui::GetContentRegionAvail();
    if (canvas_sz.x < 50.0f || canvas_sz.y < 50.0f) {
        ImGui::End();
        return;
    }
    ImVec2 canvas_p1 = ImVec2(canvas_p0.x + canvas_sz.x, canvas_p0.y + canvas_sz.y);

    ImDrawList* draw_list = ImGui::GetWindowDrawList();

    // Canvas background
    draw_list->AddRectFilled(canvas_p0, canvas_p1, IM_COL32(16, 18, 22, 255));

    // Invisible button for capturing mouse input across the entire canvas
    ImGui::InvisibleButton("##cfg_canvas", canvas_sz, ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight | ImGuiButtonFlags_MouseButtonMiddle);
    bool is_hovered = ImGui::IsItemHovered();
    bool is_active = ImGui::IsItemActive();
    const ImGuiIO& io = ImGui::GetIO();

    // Pan handling
    if (is_active && (ImGui::IsMouseDragging(ImGuiMouseButton_Middle) || 
                      ImGui::IsMouseDragging(ImGuiMouseButton_Right) || 
                      (ImGui::IsMouseDragging(ImGuiMouseButton_Left) && io.KeyCtrl))) {
        cfg_pan_x_ += io.MouseDelta.x;
        cfg_pan_y_ += io.MouseDelta.y;
    }

    // Zoom handling
    if (is_hovered && io.MouseWheel != 0.0f) {
        float old_zoom = cfg_zoom_;
        float zoom_factor = (io.MouseWheel > 0.0f) ? 1.15f : (1.0f / 1.15f);
        cfg_zoom_ = std::clamp(cfg_zoom_ * zoom_factor, 0.2f, 3.0f);

        ImVec2 mouse_canvas = ImVec2(io.MousePos.x - canvas_p0.x, io.MousePos.y - canvas_p0.y);
        cfg_pan_x_ = mouse_canvas.x - (mouse_canvas.x - cfg_pan_x_) * (cfg_zoom_ / old_zoom);
        cfg_pan_y_ = mouse_canvas.y - (mouse_canvas.y - cfg_pan_y_) * (cfg_zoom_ / old_zoom);
    }

    // Grid rendering
    float grid_step = 40.0f * cfg_zoom_;
    if (grid_step > 14.0f) {
        float x_start = fmodf(cfg_pan_x_, grid_step);
        if (x_start < 0.0f) x_start += grid_step;
        for (float x = x_start; x < canvas_sz.x; x += grid_step) {
            draw_list->AddLine(ImVec2(canvas_p0.x + x, canvas_p0.y), ImVec2(canvas_p0.x + x, canvas_p1.y), IM_COL32(30, 33, 40, 150));
        }
        float y_start = fmodf(cfg_pan_y_, grid_step);
        if (y_start < 0.0f) y_start += grid_step;
        for (float y = y_start; y < canvas_sz.y; y += grid_step) {
            draw_list->AddLine(ImVec2(canvas_p0.x, canvas_p0.y + y), ImVec2(canvas_p1.x, canvas_p0.y + y), IM_COL32(30, 33, 40, 150));
        }
    }

    draw_list->PushClipRect(canvas_p0, canvas_p1, true);

    auto to_screen = [&](float wx, float wy) -> ImVec2 {
        return ImVec2(canvas_p0.x + cfg_pan_x_ + wx * cfg_zoom_,
                      canvas_p0.y + cfg_pan_y_ + wy * cfg_zoom_);
    };

    // --- Render Edges ---
    for (int e = 0; e < cfg_layout_.edge_count; ++e) {
        const auto& edge = cfg_layout_.edges[e];
        ImU32 col = IM_COL32(160, 165, 175, 200);
        if (edge.is_back_edge) {
            col = IM_COL32(255, 193, 7, 240); // Amber/Yellow loop
        } else if (edge.type == IREM_EDGE_JUMP_TRUE) {
            col = IM_COL32(66, 189, 99, 240); // Green (Taken)
        } else if (edge.type == IREM_EDGE_JUMP_FALSE) {
            col = IM_COL32(239, 83, 80, 240); // Red (Not Taken)
        } else if (edge.type == IREM_EDGE_JUMP_UNCOND) {
            col = IM_COL32(66, 165, 245, 240); // Blue (Unconditional)
        }

        ImVec2 pts[4];
        pts[0] = to_screen(edge.start_x, edge.start_y);
        pts[1] = to_screen(edge.mid_x1, edge.mid_y1);
        pts[2] = to_screen(edge.mid_x2, edge.mid_y2);
        pts[3] = to_screen(edge.end_x, edge.end_y);

        float line_thick = edge.is_back_edge ? (2.5f * cfg_zoom_) : (2.0f * cfg_zoom_);
        line_thick = std::clamp(line_thick, 1.2f, 4.0f);
        draw_list->AddPolyline(pts, edge.point_count, col, 0, line_thick);

        // Arrowhead at destination
        ImVec2 end_pt = pts[edge.point_count - 1];
        float arrow_sz = std::clamp(6.0f * cfg_zoom_, 3.5f, 10.0f);
        if (!edge.is_back_edge) {
            draw_list->AddTriangleFilled(
                end_pt,
                ImVec2(end_pt.x - arrow_sz, end_pt.y - arrow_sz * 1.5f),
                ImVec2(end_pt.x + arrow_sz, end_pt.y - arrow_sz * 1.5f),
                col
            );
        } else {
            draw_list->AddTriangleFilled(
                end_pt,
                ImVec2(end_pt.x - arrow_sz * 1.5f, end_pt.y - arrow_sz),
                ImVec2(end_pt.x - arrow_sz * 1.5f, end_pt.y + arrow_sz),
                col
            );
        }
    }

    // --- Render Nodes (Basic Blocks) ---
    cfg_hovered_block_ = -1;
    for (int i = 0; i < cfg_layout_.node_count; ++i) {
        const auto& node = cfg_layout_.nodes[i];
        if (node.block_id < 0 || node.block_id >= cfg.block_count) continue;
        const IremBasicBlock* bb = &cfg.blocks[node.block_id];

        ImVec2 bmin = to_screen(node.x, node.y);
        ImVec2 bmax = to_screen(node.x + node.width, node.y + node.height);

        // Viewport culling
        if (bmax.x < canvas_p0.x || bmin.x > canvas_p1.x || bmax.y < canvas_p0.y || bmin.y > canvas_p1.y) {
            continue;
        }

        bool is_hover = is_hovered && ImGui::IsMouseHoveringRect(bmin, bmax);
        if (is_hover) {
            cfg_hovered_block_ = node.block_id;
            if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                cfg_selected_block_ = node.block_id;
            }
            if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                jump_to_address(bb->start_va);
            }
        }

        // Header color
        ImU32 header_bg = IM_COL32(38, 43, 52, 255);
        if (bb->is_entry) header_bg = IM_COL32(28, 68, 42, 255); // Entry green
        else if (bb->is_exit) header_bg = IM_COL32(75, 28, 32, 255); // Exit red
        else if (bb->is_loop_header) header_bg = IM_COL32(82, 65, 20, 255); // Loop amber

        // Border color
        ImU32 border_col = IM_COL32(55, 62, 74, 255);
        float border_thick = 1.0f;
        if (cfg_selected_block_ == node.block_id) {
            border_col = IM_COL32(0, 220, 255, 255); // Cyan active
            border_thick = 2.5f;
        } else if (is_hover) {
            border_col = IM_COL32(180, 195, 225, 255);
            border_thick = 1.5f;
        } else if (bb->is_entry) {
            border_col = IM_COL32(66, 189, 99, 200);
        } else if (bb->is_exit) {
            border_col = IM_COL32(239, 83, 80, 200);
        } else if (bb->is_loop_header) {
            border_col = IM_COL32(255, 193, 7, 200);
        }

        // Block background
        draw_list->AddRectFilled(bmin, bmax, IM_COL32(22, 25, 31, 245), 4.0f);

        // Header bar
        float header_h = std::clamp(24.0f * cfg_zoom_, 16.0f, 32.0f);
        draw_list->AddRectFilled(bmin, ImVec2(bmax.x, bmin.y + header_h), header_bg, 4.0f, ImDrawFlags_RoundCornersTop);
        draw_list->AddRect(bmin, bmax, border_col, 4.0f, 0, border_thick);

        // Header Text
        std::string hdr_text = std::format("loc_{:X} (Block #{})", bb->start_va, bb->block_id);
        if (bb->is_entry) hdr_text += " [ENTRY]";
        if (bb->is_exit) hdr_text += " [EXIT]";
        if (bb->is_loop_header) hdr_text += " [LOOP]";

        float font_sz = ImGui::GetFontSize() * cfg_zoom_;
        if (cfg_zoom_ >= 0.45f) {
            draw_list->AddText(nullptr, font_sz, ImVec2(bmin.x + 8.0f * cfg_zoom_, bmin.y + 3.0f * cfg_zoom_), IM_COL32(235, 238, 242, 255), hdr_text.c_str());

            // Instruction lines
            float line_y = bmin.y + header_h + 4.0f * cfg_zoom_;
            float line_h = ImGui::GetTextLineHeightWithSpacing() * cfg_zoom_;

            for (size_t k = bb->start_idx; k <= bb->end_idx && k < instructions_.size(); ++k) {
                if (line_y + line_h > bmax.y) break;
                const auto& ins = instructions_[k];

                // Address
                std::string va_str = std::format("{:08X} ", (uint32_t)ins.va);
                draw_list->AddText(nullptr, font_sz, ImVec2(bmin.x + 8.0f * cfg_zoom_, line_y), IM_COL32(110, 118, 130, 255), va_str.c_str());

                // Mnemonic
                float mnem_x = bmin.x + (8.0f + 65.0f) * cfg_zoom_;
                ImU32 mnem_col = IM_COL32(230, 230, 235, 255);
                if (ins.is_call) mnem_col = IM_COL32(245, 166, 35, 255);
                else if (ins.is_jump || ins.is_conditional_jump) mnem_col = IM_COL32(77, 171, 247, 255);
                else if (ins.is_ret) mnem_col = IM_COL32(239, 83, 80, 255);
                draw_list->AddText(nullptr, font_sz, ImVec2(mnem_x, line_y), mnem_col, ins.mnemonic.c_str());

                // Operands
                float ops_x = mnem_x + 55.0f * cfg_zoom_;
                std::string ops_str = ins.format_operands();
                draw_list->AddText(nullptr, font_sz, ImVec2(ops_x, line_y), IM_COL32(175, 185, 200, 255), ops_str.c_str());

                // Comment / Annotation (TEB, Hash, String, Xrefs)
                if (!ins.comment.empty()) {
                    float cmt_x = ops_x + (float)(ops_str.size() * 7 + 10) * cfg_zoom_;
                    if (cmt_x < bmax.x - 10.0f) {
                        std::string cmt_str = "; " + ins.comment;
                        draw_list->AddText(nullptr, font_sz, ImVec2(cmt_x, line_y), IM_COL32(100, 200, 120, 220), cmt_str.c_str());
                    }
                }

                line_y += line_h;
            }
        } else {
            // Low-zoom LOD
            std::string lod_text = std::format("{} insns", bb->instruction_count);
            draw_list->AddText(nullptr, 12.0f, ImVec2(bmin.x + 6.0f, bmin.y + 3.0f), IM_COL32(200, 205, 215, 255), lod_text.c_str());
        }
    }

    draw_list->PopClipRect();
    ImGui::End();
}

LRESULT WINAPI Application::wnd_proc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) {
        return true;
    }

    Application* app = reinterpret_cast<Application*>(GetWindowLongPtr(hWnd, GWLP_USERDATA));

    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCT* cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        SetWindowLongPtr(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        return 0;
    }
    case WM_DROPFILES: {
        HDROP hDrop = reinterpret_cast<HDROP>(wParam);
        wchar_t droppedPath[MAX_PATH];
        if (::DragQueryFileW(hDrop, 0, droppedPath, MAX_PATH)) {
            if (app) {
                app->open_binary(droppedPath);
            }
        }
        ::DragFinish(hDrop);
        return 0;
    }
    case WM_SIZE:
        if (app && wParam != SIZE_MINIMIZED) {
            app->resize_width_ = (UINT)LOWORD(lParam);
            app->resize_height_ = (UINT)HIWORD(lParam);
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU)
            return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}

} // namespace agy
