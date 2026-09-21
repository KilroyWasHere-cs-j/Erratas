// Example YARA rules for Linux ELF targets (RealFileType::LinuxExecutable,
// sub-types ELF/SO). Not wired into malware.rs yet - see rules/README.md.

import "elf"

// Reverse-shell one-liners show up verbatim in a lot of Linux droppers and
// post-exploitation tooling rather than being built dynamically.
rule elf_reverse_shell_strings
{
    meta:
        description = "Common reverse-shell command strings"
        severity    = "high"
        target      = "LinuxExecutable/ELF, LinuxExecutable/SO"

    strings:
        $a = "/bin/sh -i"
        $b = "bash -i >& /dev/tcp/"
        $c = "mkfifo /tmp/"
        $d = "nc -e /bin/sh"

    condition:
        any of them
}

// LD_PRELOAD hijacking is the classic Linux equivalent of DLL injection -
// swap in a malicious shared object that gets loaded before anything else.
rule elf_ld_preload_hijack
{
    meta:
        description = "References LD_PRELOAD, a common Linux persistence/hijack technique"
        severity    = "medium"
        target      = "LinuxExecutable/ELF, LinuxExecutable/SO"

    strings:
        $a = "LD_PRELOAD"
        $b = "/etc/ld.so.preload"

    condition:
        any of them
}

// A statically-linked, stripped executable that still needs dlopen/dlsym is
// a light heuristic for a loader/stager - not a verdict on its own, meant
// to be combined with other flags.
rule elf_stripped_with_dynamic_loading
{
    meta:
        description = "Stripped ELF that still references dlopen/dlsym (dynamic runtime loading, common in loaders)"
        severity    = "low"
        target      = "LinuxExecutable/ELF"

    strings:
        $a = "dlopen"
        $b = "dlsym"

    condition:
        elf.type == elf.ET_EXEC and elf.symtab_entries == 0 and any of them
}
