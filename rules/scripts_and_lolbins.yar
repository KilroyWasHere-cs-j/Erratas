// Example YARA rules for generic script/dropper indicators that aren't
// tied to one specific RealFileType - payloads like these can land inside
// almost any container this project scans (executables, documents,
// archives). Not wired into malware.rs yet - see rules/README.md.

// EncodedCommand payloads are base64 of UTF-16LE text, so the marker often
// shows up doubled/spaced out in raw bytes - still cheap and worth a check.
rule script_base64_powershell
{
    meta:
        description = "Base64-encoded PowerShell command"
        severity    = "high"
        target      = "generic - any file type"

    strings:
        $a = "powershell" nocase
        $b = "-EncodedCommand" nocase
        $c = "-enc " nocase
        $d = "FromBase64String" nocase

    condition:
        $a and any of ($b, $c, $d)
}

// "Living off the land" binaries - legitimate Windows tools abused to
// download or decode a payload without dropping a separate executable.
rule script_lolbin_download_execute
{
    meta:
        description = "Living-off-the-land binaries commonly abused to download/execute a payload"
        severity    = "medium"
        target      = "generic - any file type"

    strings:
        $certutil  = "certutil" nocase
        $decode    = "-decode" nocase
        $mshta     = "mshta" nocase
        $regsvr    = "regsvr32" nocase
        $rundll    = "rundll32" nocase
        $bitsadmin = "bitsadmin" nocase

    condition:
        ($certutil and $decode) or $mshta or $regsvr or $rundll or $bitsadmin
}

// The cross-platform download-and-execute one-liner: pull a script and
// pipe it straight into a shell without ever touching disk.
rule script_curl_pipe_shell
{
    meta:
        description = "Download-and-execute one-liner (curl/wget piped straight into a shell)"
        severity    = "high"
        target      = "generic - any file type"

    strings:
        $a = /(curl|wget)\s+[^\n]{0,80}\|\s*(ba)?sh/ nocase

    condition:
        $a
}
