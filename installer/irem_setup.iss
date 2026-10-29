; Ирем (Irem) - x86_64 Disassembler & Binary Patching Studio
; Inno Setup Installer Script
; Author: mina

#define MyAppName "Irem"
#define MyAppDisplayName "Ирем - x86_64 Disassembler & Patching Studio"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "mina"
#define MyAppExeName "Irem.exe"
#define MyAppDescription "Lightning-fast x86_64 disassembler and binary patching studio for PE, SYS, and EFI binaries."

[Setup]
AppId={{B8A54611-712F-4C73-95AD-80BF457C3D39}
AppName={#MyAppDisplayName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppDisplayName} v{#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppDisplayName}
AllowNoIcons=yes
; Output installer to installer\output\
OutputDir=output
OutputBaseFilename=Irem_Setup_v{#MyAppVersion}_x64
SetupIconFile=assets\irem.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppDisplayName}
Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes
; Installer UI
WizardStyle=modern
WizardImageFile=assets\wizard_image.bmp
WizardSmallImageFile=assets\wizard_small.bmp
; Architecture
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Privileges
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
; Misc
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppDescription}
VersionInfoCopyright=Copyright (c) 2026 {#MyAppPublisher}
VersionInfoProductName={#MyAppDisplayName}
VersionInfoProductVersion={#MyAppVersion}
DisableProgramGroupPage=yes
LicenseFile=assets\LICENSE.txt
InfoBeforeFile=assets\README_BEFORE.txt

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "fileassoc_exe"; Description: "Associate .exe files (Open with Ирем)"; GroupDescription: "File Associations:"; Flags: unchecked
Name: "fileassoc_dll"; Description: "Associate .dll files (Open with Ирем)"; GroupDescription: "File Associations:"; Flags: unchecked
Name: "fileassoc_sys"; Description: "Associate .sys files (Open with Ирем)"; GroupDescription: "File Associations:"; Flags: unchecked
Name: "fileassoc_efi"; Description: "Associate .efi files (Open with Ирем)"; GroupDescription: "File Associations:"; Flags: unchecked

[Files]
; Main executable
Source: "..\build\Release\Irem.exe"; DestDir: "{app}"; Flags: ignoreversion
; Logo image (for Help/About screen when loaded from disk as fallback)
Source: "..\makyairemi.jpg"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Start Menu
Name: "{group}\{#MyAppDisplayName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"; Comment: "{#MyAppDescription}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
; Desktop
Name: "{autodesktop}\{#MyAppDisplayName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon; IconFilename: "{app}\{#MyAppExeName}"; Comment: "{#MyAppDescription}"

[Registry]
; File associations - .exe
Root: HKCR; Subkey: ".exe\OpenWithProgids"; ValueType: string; ValueName: "Irem.exe"; ValueData: ""; Flags: uninsdeletevalue; Tasks: fileassoc_exe
Root: HKCR; Subkey: "Irem.exe"; ValueType: string; ValueName: ""; ValueData: "PE Executable (Irem)"; Flags: uninsdeletekey; Tasks: fileassoc_exe
Root: HKCR; Subkey: "Irem.exe\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName},0"; Tasks: fileassoc_exe
Root: HKCR; Subkey: "Irem.exe\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Tasks: fileassoc_exe

; File associations - .dll
Root: HKCR; Subkey: ".dll\OpenWithProgids"; ValueType: string; ValueName: "Irem.dll"; ValueData: ""; Flags: uninsdeletevalue; Tasks: fileassoc_dll
Root: HKCR; Subkey: "Irem.dll"; ValueType: string; ValueName: ""; ValueData: "DLL Library (Irem)"; Flags: uninsdeletekey; Tasks: fileassoc_dll
Root: HKCR; Subkey: "Irem.dll\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName},0"; Tasks: fileassoc_dll
Root: HKCR; Subkey: "Irem.dll\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Tasks: fileassoc_dll

; File associations - .sys
Root: HKCR; Subkey: ".sys\OpenWithProgids"; ValueType: string; ValueName: "Irem.sys"; ValueData: ""; Flags: uninsdeletevalue; Tasks: fileassoc_sys
Root: HKCR; Subkey: "Irem.sys"; ValueType: string; ValueName: ""; ValueData: "Kernel Driver (Irem)"; Flags: uninsdeletekey; Tasks: fileassoc_sys
Root: HKCR; Subkey: "Irem.sys\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName},0"; Tasks: fileassoc_sys
Root: HKCR; Subkey: "Irem.sys\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Tasks: fileassoc_sys

; File associations - .efi
Root: HKCR; Subkey: ".efi\OpenWithProgids"; ValueType: string; ValueName: "Irem.efi"; ValueData: ""; Flags: uninsdeletevalue; Tasks: fileassoc_efi
Root: HKCR; Subkey: "Irem.efi"; ValueType: string; ValueName: ""; ValueData: "UEFI Firmware (Irem)"; Flags: uninsdeletekey; Tasks: fileassoc_efi
Root: HKCR; Subkey: "Irem.efi\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName},0"; Tasks: fileassoc_efi
Root: HKCR; Subkey: "Irem.efi\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Tasks: fileassoc_efi

; Add to "Open with" context menu for all PE types
Root: HKCR; Subkey: "*\shell\OpenWithIrem"; ValueType: string; ValueName: ""; ValueData: "Disassemble with Ирем"; Flags: uninsdeletekey
Root: HKCR; Subkey: "*\shell\OpenWithIrem"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#MyAppExeName},0"
Root: HKCR; Subkey: "*\shell\OpenWithIrem\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppDisplayName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
  // Check for existing installation
  if RegValueExists(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B8A54611-712F-4C73-95AD-80BF457C3D39}_is1', 'UninstallString') then
  begin
    if MsgBox('A previous version of Ирем is already installed. Do you want to uninstall it first?', mbConfirmation, MB_YESNO) = IDYES then
    begin
      // Let the user proceed to install over it
    end;
  end;
end;

