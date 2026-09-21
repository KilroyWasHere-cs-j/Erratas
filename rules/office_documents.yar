// Example YARA rules for Office documents (RealFileType::Document,
// sub-types DOC/DOCX/XLS/XLSX/PPT/PPTX/OOXML/OLECFB). Not wired into
// malware.rs yet - see rules/README.md.

// The single most common malicious-document pattern: a macro that runs
// automatically on open, paired with a call that shells out to run
// something else (usually a PowerShell dropper).
rule office_macro_autoexec_shell
{
    meta:
        description = "VBA auto-run macro combined with a shell-out call"
        severity    = "high"
        target      = "Document/DOC, Document/DOCX, Document/XLS, Document/XLSX, Document/PPT, Document/PPTX, Document/OLECFB, Document/OOXML"

    strings:
        $auto1  = "AutoOpen" nocase
        $auto2  = "AutoExec" nocase
        $auto3  = "Document_Open" nocase
        $shell1 = "Shell(" nocase
        $shell2 = "WScript.Shell" nocase
        $shell3 = "CreateObject(\"WScript.Shell\")" nocase

    condition:
        any of ($auto*) and any of ($shell*)
}

// Same idea as the executable-focused rules, but for the macro-embedded
// version: build/decode a PowerShell command from inside the document.
rule office_macro_powershell_dropper
{
    meta:
        description = "Macro-embedded PowerShell download/execute pattern"
        severity    = "high"
        target      = "Document/DOCX, Document/XLSX, Document/PPTX, Document/OOXML"

    strings:
        $a = "powershell" nocase
        $b = "-enc" nocase
        $c = "DownloadString" nocase
        $d = "Invoke-Expression" nocase
        $e = "IEX(" nocase

    condition:
        $a and 1 of ($b, $c, $d, $e)
}

// Legacy .doc/.xls files are OLE compound files; a "Package" stream or an
// embedded .exe-looking name is the classic embedded-object attack.
rule office_ole_embedded_object
{
    meta:
        description = "OLE compound file with an embedded executable/object stream (common malicious-attachment pattern)"
        severity    = "medium"
        target      = "Document/DOC, Document/OLECFB"

    strings:
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }
        $obj1      = "Package" wide
        $obj2      = ".exe" nocase wide ascii

    condition:
        $ole_magic at 0 and any of ($obj1, $obj2)
}
