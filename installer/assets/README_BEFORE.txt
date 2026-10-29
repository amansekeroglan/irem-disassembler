Welcome to the Ирем (Irem) Installer

Ирем is a lightning-fast, lightweight x86_64 disassembler and binary
patching studio built from scratch in modern C++23.

What makes Ирем special:

  * 100% custom x86_64 instruction decoder — no Capstone, no Zydis,
    no LLVM. Every opcode byte is decoded by hand-written logic.

  * Instant analysis — loads and disassembles hundreds of thousands
    of instructions in fractions of a second, with zero database
    creation overhead.

  * First-class support for:
      - Windows Executables (.exe, .dll)
      - Windows Kernel Drivers (.sys)
      - UEFI Firmware Binaries (.efi)

  * Live binary patching — NOP-fill instructions, edit opcode bytes,
    and export patched binaries with one click.

  * IDA Pro style UI — dark theme, color-coded disassembly, jump
    arrow visualization, Shannon entropy analysis.

  * Security analysis — ASLR, DEP/NX, CFG, High-Entropy VA detection.

System Requirements:

  * Windows 10 or later (x64)
  * DirectX 11 compatible GPU
  * ~2 MB disk space (+ binaries you analyze)

Written by mina.

