// Example YARA rules for PDF targets (RealFileType::Document,
// sub-type PDF). Not wired into malware.rs yet - see rules/README.md.

// A PDF that runs JavaScript the moment it's opened, with no user action
// required, is the standard malicious-PDF pattern.
rule pdf_javascript_autorun
{
    meta:
        description = "PDF with embedded JavaScript and an automatic open action"
        severity    = "high"
        target      = "Document/PDF"

    strings:
        $js1 = "/JavaScript"
        $js2 = "/JS"
        $oa  = "/OpenAction"

    condition:
        $oa and any of ($js1, $js2)
}

// /Launch can spawn an external program or command straight from the
// viewer - most modern readers prompt for it, but older ones may not.
rule pdf_launch_action
{
    meta:
        description = "PDF /Launch action - can spawn an external program/command when opened"
        severity    = "high"
        target      = "Document/PDF"

    strings:
        $a = "/Launch"

    condition:
        $a
}

// An embedded file with an executable-style extension is a common way to
// smuggle a payload inside an otherwise normal-looking PDF.
rule pdf_embedded_file_suspicious_ext
{
    meta:
        description = "PDF embeds a file with an executable-style extension"
        severity    = "high"
        target      = "Document/PDF"

    strings:
        $ef  = "/EmbeddedFile"
        $exe = ".exe" nocase
        $scr = ".scr" nocase
        $js  = ".js" nocase
        $vbs = ".vbs" nocase

    condition:
        $ef and any of ($exe, $scr, $js, $vbs)
}

// Legitimate PDF JS rarely needs eval/unescape/fromCharCode together -
// that combo is a strong sign the script is deliberately obfuscated.
rule pdf_obfuscated_js
{
    meta:
        description = "Common obfuscation calls (eval/unescape/String.fromCharCode) inside PDF JS"
        severity    = "medium"
        target      = "Document/PDF"

    strings:
        $a = "eval("
        $b = "unescape("
        $c = "String.fromCharCode"

    condition:
        2 of them
}
