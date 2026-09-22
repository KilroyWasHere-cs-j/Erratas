# Example YARA rule sets

Illustrative starter rules, split one file per target category to match
the file types Erratas already classifies (`src/types.rs`'s
`RealFileType` / `RealFileSubType`):

| File                          | Targets                                      |
| ------------------------------ | --------------------------------------------- |
| `pe_windows.yar`               | Windows PE/DLL executables                    |
| `elf_linux.yar`                | Linux ELF/SO executables                      |
| `macho_macos.yar`              | macOS Mach-O executables                      |
| `office_documents.yar`         | DOC/DOCX/XLS/XLSX/PPT/PPTX/OLECFB/OOXML       |
| `pdf_documents.yar`            | PDF                                           |
| `scripts_and_lolbins.yar`      | Generic script/dropper indicators (any file)  |
| `archives_and_installers.yar`  | ZIP/RAR/7z/TAR, MSI installers, LNK shortcuts |
| `shellcode.yar`                | Embedded shellcode payloads (any file, #5)    |
.

## Caveats

- These are **teaching examples**, not a production detection set. They're
  narrow, string/pattern-based, and will both miss real malware and flag
  legitimate files (e.g. `elf_ld_preload_hijack` will match any binary that
  merely mentions `LD_PRELOAD` in a comment or log string; `shellcode_nop_sled`
  will match any long run of 0x90 bytes regardless of why it's there, which
  includes some legitimate alignment padding).
- A few PE/ELF rules use yara-x's `pe`/`elf`/`math` modules
  (`pe.imports(...)`, `pe.sections[i]`, `math.entropy(...)`) - these mirror
  the classic YARA module APIs and were compile-checked against yara-x
  1.20.0 (the version pinned in `Cargo.toml`). The Mach-O rules deliberately
  avoid the `macho` module and stick to plain strings, since its field
  names are newer/less stable across yara-x versions - verify against your
  installed version before depending on it.
- For a maintained, production-grade rule set, pull from a community
  source instead of hand-rolling everything - see the options already
  noted in `src/malware.rs`'s comments (`Yara-Rules/rules`,
  `Neo23x0/signature-base`, abuse.ch's feed, ReversingLabs).
