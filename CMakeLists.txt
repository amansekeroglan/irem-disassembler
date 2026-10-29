cmake_minimum_required(VERSION 3.25)
project(Irem LANGUAGES CXX C RC)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Enable modern MSVC flags
if (MSVC)
    add_compile_options(/W4 /permissive- /Zc:__cplusplus /utf-8)
    add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
endif()

# Fetch Dear ImGui
include(FetchContent)
FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        docking
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(imgui)

# Create ImGui static library with Win32 and DirectX 11 backends
add_library(imgui STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp
)

target_include_directories(imgui PUBLIC
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
)

target_link_libraries(imgui PUBLIC
    d3d11
    d3dcompiler
    dxgi
)

# Source files
set(SOURCES
    src/main.cpp
    src/app/app.cpp
    src/app/texture_loader.cpp
    src/pe/pe_parser.cpp
    src/disasm/instruction.cpp
    src/disasm/x86_decoder.cpp
    src/patch/patch_manager.cpp
    src/analysis/function_manager.cpp
    src/analysis/xref_manager.cpp
    src/symbols/pdb_loader.cpp
    src/engines/unwind_parser.c
    src/engines/string_scanner.c
    src/engines/cfg_builder.c
    src/engines/winapi_db.c
    src/engines/fastcall_analyzer.c
    src/engines/jumptable_resolver.c
    src/engines/sigmaker.c
    src/engines/struct_resolver.c
    src/engines/api_hash_resolver.c
    src/engines/cfg_layout.c
    src/engines/engines_bridge.cpp
    src/cli/cli.cpp
    src/app/irem.rc
)

set(HEADERS
    src/app/app.hpp
    src/app/ui_theme.hpp
    src/app/texture_loader.hpp
    src/app/resource.h
    src/pe/pe_parser.hpp
    src/disasm/instruction.hpp
    src/disasm/x86_decoder.hpp
    src/patch/patch_manager.hpp
    src/analysis/function_manager.hpp
    src/analysis/xref_manager.hpp
    src/symbols/pdb_loader.hpp
    src/engines/irem_types.h
    src/engines/irem_engines.h
    src/engines/unwind_parser.h
    src/engines/string_scanner.h
    src/engines/cfg_builder.h
    src/engines/winapi_db.h
    src/engines/fastcall_analyzer.h
    src/engines/jumptable_resolver.h
    src/engines/sigmaker.h
    src/engines/struct_resolver.h
    src/engines/api_hash_resolver.h
    src/engines/cfg_layout.h
    src/engines/engines_bridge.hpp
    src/cli/cli.hpp
)

add_executable(${PROJECT_NAME} WIN32 ${SOURCES} ${HEADERS})

target_include_directories(${PROJECT_NAME} PRIVATE
    src
    src/app
    src/analysis
    src/symbols
    src/engines
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    imgui
    d3d11
    d3dcompiler
    dxgi
    dwmapi
    windowscodecs
    dbghelp
    urlmon
)

# Test executable (Headless Console Core Verification)
    src/pe/pe_parser.cpp
    src/disasm/instruction.cpp
    src/disasm/x86_decoder.cpp
    src/patch/patch_manager.cpp
    src/analysis/function_manager.cpp
    src/analysis/xref_manager.cpp
    src/symbols/pdb_loader.cpp
    src/engines/unwind_parser.c
    src/engines/string_scanner.c
    src/engines/cfg_builder.c
    src/engines/winapi_db.c
    src/engines/fastcall_analyzer.c
    src/engines/jumptable_resolver.c
    src/engines/sigmaker.c
    src/engines/struct_resolver.c
    src/engines/api_hash_resolver.c
    src/engines/cfg_layout.c
    src/engines/engines_bridge.cpp
)

target_include_directories(test_core PRIVATE
    src
    src/analysis
    src/symbols
    src/engines
)

target_link_libraries(test_core PRIVATE
    dbghelp
    urlmon
)


