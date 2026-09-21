// Example YARA rules for Windows PE targets (RealFileType::WinExecutable,
// sub-types PE/DLL). Not wired into malware.rs yet - see rules/README.md.

import "pe"
import "math"

// Chained imports classically used to inject code into another process:
// allocate memory there, write shellcode into it, then start a thread on it.
rule pe_process_injection_apis
{
    meta:
        description = "Imports commonly chained for process injection (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)"
        severity    = "high"
        target      = "WinExecutable/PE, WinExecutable/DLL"

    condition:
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        pe.imports("kernel32.dll", "CreateRemoteThread")
}

// UPX leaves behind well-known section names even though it re-compresses
// the rest of the binary, so this is a cheap first-pass packer check.
rule pe_upx_packed
{
    meta:
        description = "PE contains UPX packer section names"
        severity    = "medium"
        target      = "WinExecutable/PE, WinExecutable/DLL"

    condition:
        for any i in (0..pe.number_of_sections - 1):
            (pe.sections[i].name == "UPX0" or pe.sections[i].name == "UPX1")
}

// Packers/crypters that don't leave a named signature still show up as
// high-entropy sections, since compressed/encrypted data looks like noise.
rule pe_high_entropy_section
{
    meta:
        description = "PE section entropy >= 7.5 (likely packed or encrypted)"
        severity    = "medium"
        target      = "WinExecutable/PE, WinExecutable/DLL"

    condition:
        for any i in (0..pe.number_of_sections - 1):
            (math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) >= 7.5)
}

// Droppers frequently carry the literal PowerShell invocation as a string
// rather than building it at runtime - cheap to catch, worth keeping.
rule pe_embedded_powershell_encoded_command
{
    meta:
        description = "Embedded 'powershell -enc' / '-EncodedCommand' launch string"
        severity    = "high"
        target      = "WinExecutable/PE, WinExecutable/DLL"

    strings:
        $a = "powershell -enc" nocase
        $b = "powershell -EncodedCommand" nocase
        $c = "-nop -w hidden" nocase

    condition:
        any of them
}
