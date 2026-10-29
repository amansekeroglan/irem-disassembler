#pragma once

#include <imgui.h>
#include <cstdint>

namespace agy::ui {

// Professional IDA Pro / Ghidra dark palette
namespace colors {
    inline constexpr ImU32 BgDark          = IM_COL32(24, 26, 31, 255);
    inline constexpr ImU32 PanelBg         = IM_COL32(33, 37, 43, 255);
    inline constexpr ImU32 HeaderBg        = IM_COL32(40, 44, 52, 255);
    inline constexpr ImU32 Selection       = IM_COL32(62, 68, 81, 200);

    // Disassembly Syntax Colors
    inline constexpr ImU32 Address         = IM_COL32(197, 134, 192, 255); // Purple / Violet
    inline constexpr ImU32 RawBytes        = IM_COL32(110, 118, 129, 255); // Dark Gray / Muted
    inline constexpr ImU32 Mnemonic        = IM_COL32(86, 156, 214, 255);  // Bright Blue / Cyan
    inline constexpr ImU32 Register        = IM_COL32(229, 192, 123, 255); // Amber / Yellow
    inline constexpr ImU32 Immediate       = IM_COL32(181, 206, 168, 255); // Light Green
    inline constexpr ImU32 MemoryRef       = IM_COL32(78, 201, 176, 255);  // Teal / Cyan
    inline constexpr ImU32 Comment         = IM_COL32(106, 153, 85, 255);  // Forest / Olive Green

    // Control Flow / Jump Arrows (ImDrawList)
    inline constexpr ImU32 JumpUnconditional = IM_COL32(59, 130, 246, 230); // Blue
    inline constexpr ImU32 JumpTaken         = IM_COL32(16, 185, 129, 230); // Emerald Green
    inline constexpr ImU32 JumpNotTaken      = IM_COL32(239, 68, 68, 230);  // Red
    inline constexpr ImU32 ArrowHover        = IM_COL32(250, 204, 21, 255); // Yellow Highlight

    // Patch & Modification Highlight
    inline constexpr ImU32 PatchedByte       = IM_COL32(244, 63, 94, 255);  // Neon Pink / Red
    inline constexpr ImU32 PatchedBg         = IM_COL32(80, 20, 35, 180);
}

inline void apply_ida_dark_theme() {
    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;

    style.WindowRounding    = 4.0f;
    style.ChildRounding     = 3.0f;
    style.FrameRounding     = 3.0f;
    style.PopupRounding     = 4.0f;
    style.ScrollbarRounding = 4.0f;
    style.GrabRounding      = 3.0f;
    style.TabRounding       = 4.0f;
    style.WindowBorderSize  = 1.0f;
    style.FrameBorderSize   = 0.0f;
    style.ItemSpacing       = ImVec2(8.0f, 4.0f);
    style.ItemInnerSpacing  = ImVec2(6.0f, 4.0f);
    style.IndentSpacing     = 20.0f;

    colors[ImGuiCol_Text]                  = ImVec4(0.90f, 0.92f, 0.94f, 1.00f);
    colors[ImGuiCol_TextDisabled]          = ImVec4(0.50f, 0.55f, 0.60f, 1.00f);
    colors[ImGuiCol_WindowBg]              = ImVec4(0.12f, 0.13f, 0.15f, 1.00f);
    colors[ImGuiCol_ChildBg]               = ImVec4(0.14f, 0.15f, 0.17f, 1.00f);
    colors[ImGuiCol_PopupBg]               = ImVec4(0.14f, 0.15f, 0.18f, 0.98f);
    colors[ImGuiCol_Border]                = ImVec4(0.22f, 0.25f, 0.29f, 0.80f);
    colors[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg]               = ImVec4(0.18f, 0.20f, 0.24f, 1.00f);
    colors[ImGuiCol_FrameBgHovered]        = ImVec4(0.24f, 0.27f, 0.32f, 1.00f);
    colors[ImGuiCol_FrameBgActive]         = ImVec4(0.28f, 0.32f, 0.38f, 1.00f);
    colors[ImGuiCol_TitleBg]               = ImVec4(0.10f, 0.11f, 0.13f, 1.00f);
    colors[ImGuiCol_TitleBgActive]         = ImVec4(0.14f, 0.16f, 0.19f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed]      = ImVec4(0.10f, 0.11f, 0.13f, 0.75f);
    colors[ImGuiCol_MenuBarBg]             = ImVec4(0.14f, 0.15f, 0.18f, 1.00f);
    colors[ImGuiCol_ScrollbarBg]           = ImVec4(0.12f, 0.13f, 0.15f, 0.60f);
    colors[ImGuiCol_ScrollbarGrab]         = ImVec4(0.25f, 0.28f, 0.34f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.32f, 0.36f, 0.44f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive]   = ImVec4(0.40f, 0.45f, 0.55f, 1.00f);
    colors[ImGuiCol_CheckMark]             = ImVec4(0.35f, 0.65f, 0.95f, 1.00f);
    colors[ImGuiCol_SliderGrab]            = ImVec4(0.35f, 0.65f, 0.95f, 1.00f);
    colors[ImGuiCol_SliderGrabActive]      = ImVec4(0.45f, 0.75f, 1.00f, 1.00f);
    colors[ImGuiCol_Button]                = ImVec4(0.20f, 0.23f, 0.28f, 1.00f);
    colors[ImGuiCol_ButtonHovered]         = ImVec4(0.28f, 0.33f, 0.40f, 1.00f);
    colors[ImGuiCol_ButtonActive]          = ImVec4(0.34f, 0.40f, 0.50f, 1.00f);
    colors[ImGuiCol_Header]                = ImVec4(0.22f, 0.26f, 0.32f, 1.00f);
    colors[ImGuiCol_HeaderHovered]         = ImVec4(0.28f, 0.34f, 0.42f, 1.00f);
    colors[ImGuiCol_HeaderActive]          = ImVec4(0.34f, 0.42f, 0.52f, 1.00f);
    colors[ImGuiCol_Separator]             = ImVec4(0.24f, 0.27f, 0.33f, 1.00f);
    colors[ImGuiCol_SeparatorHovered]      = ImVec4(0.35f, 0.65f, 0.95f, 0.78f);
    colors[ImGuiCol_SeparatorActive]       = ImVec4(0.35f, 0.65f, 0.95f, 1.00f);
    colors[ImGuiCol_ResizeGrip]            = ImVec4(0.25f, 0.28f, 0.34f, 0.50f);
    colors[ImGuiCol_ResizeGripHovered]     = ImVec4(0.35f, 0.65f, 0.95f, 0.78f);
    colors[ImGuiCol_ResizeGripActive]      = ImVec4(0.45f, 0.75f, 1.00f, 1.00f);
    colors[ImGuiCol_Tab]                   = ImVec4(0.16f, 0.18f, 0.22f, 1.00f);
    colors[ImGuiCol_TabHovered]            = ImVec4(0.26f, 0.31f, 0.38f, 1.00f);
    colors[ImGuiCol_TabSelected]           = ImVec4(0.22f, 0.26f, 0.32f, 1.00f);
    colors[ImGuiCol_TabDimmed]             = ImVec4(0.13f, 0.14f, 0.17f, 1.00f);
    colors[ImGuiCol_TabDimmedSelected]     = ImVec4(0.17f, 0.20f, 0.24f, 1.00f);
    colors[ImGuiCol_TableHeaderBg]         = ImVec4(0.16f, 0.18f, 0.22f, 1.00f);
    colors[ImGuiCol_TableBorderStrong]     = ImVec4(0.22f, 0.25f, 0.30f, 1.00f);
    colors[ImGuiCol_TableBorderLight]      = ImVec4(0.18f, 0.20f, 0.24f, 1.00f);
    colors[ImGuiCol_TableRowBg]            = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_TableRowBgAlt]         = ImVec4(1.00f, 1.00f, 1.00f, 0.02f);
}

} // namespace agy::ui

