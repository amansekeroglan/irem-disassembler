#include "app/app.hpp"
#include "cli/cli.hpp"
#include <windows.h>
#include <shellapi.h>

int WINAPI wWinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR lpCmdLine,
    _In_ int nShowCmd
) {
    (void)hInstance;
    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nShowCmd;

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv && argc > 1 && agy::cli::is_cli_verb(argv[1])) {
        int result = agy::cli::execute(argc, argv);
        LocalFree(argv);
        return result;
    }

    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    agy::Application app;
    if (!app.initialize(L"Ирем - x86_64 Disassembler & Patching Studio", 1366, 820)) {
        MessageBoxW(nullptr, L"Failed to initialize DirectX 11 or Win32 window!", L"Error", MB_ICONERROR);
        if (argv) LocalFree(argv);
        CoUninitialize();
        return 1;
    }

    if (argv && argc > 1) {
        app.open_binary(argv[1]);
    }
    if (argv) {
        LocalFree(argv);
    }

    app.run();
    CoUninitialize();
    return 0;
}
