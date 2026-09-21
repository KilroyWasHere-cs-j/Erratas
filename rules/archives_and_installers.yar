// Example YARA rules for archives and Windows installer/shortcut targets
// (RealFileType::Archive, and WinExecutable sub-types MSI/LNK). Not wired
// into malware.rs yet - see rules/README.md.

// A double extension (invoice.pdf.exe) relies on Explorer hiding the real
// extension by default - the filename string still shows up in the archive
// listing/central directory even when the icon lies.
rule archive_double_extension_lure
{
    meta:
        description = "Filename in the archive listing uses a double extension to disguise an executable as a document"
        severity    = "medium"
        target      = "Archive/ZIP, Archive/RAR, Archive/SEVENZ, Archive/TAR"

    strings:
        $a = ".pdf.exe" nocase
        $b = ".doc.exe" nocase
        $c = ".docx.exe" nocase
        $d = ".jpg.exe" nocase
        $e = ".txt.exe" nocase
        $f = ".xlsx.exe" nocase

    condition:
        any of them
}

// MSI installers can run arbitrary commands during setup via the
// CustomAction table - a shell-out entry there is a common malicious-
// installer pattern (strings are stored UTF-16LE inside the MSI, hence
// checking both wide and ascii).
rule msi_custom_action_shell
{
    meta:
        description = "MSI installer with a CustomAction table entry that shells out"
        severity    = "high"
        target      = "WinExecutable/MSI"

    strings:
        $ca   = "CustomAction" wide ascii
        $cmd1 = "cmd.exe /c" nocase wide ascii
        $cmd2 = "powershell" nocase wide ascii

    condition:
        $ca and any of ($cmd1, $cmd2)
}

// The classic phishing-attachment shortcut trick: a .lnk whose target or
// arguments string launches PowerShell with a hidden/encoded command,
// instead of pointing at the document it pretends to be.
rule lnk_shortcut_powershell_target
{
    meta:
        description = "Windows shortcut (.lnk) whose target/arguments launch PowerShell"
        severity    = "high"
        target      = "WinExecutable/LNK"

    strings:
        $lnk_magic = { 4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
        $ps1       = "powershell" nocase wide ascii
        $ps2       = "-windowstyle hidden" nocase wide ascii
        $ps3       = "-enc" nocase wide ascii

    condition:
        $lnk_magic at 0 and any of ($ps1, $ps2, $ps3)
}
