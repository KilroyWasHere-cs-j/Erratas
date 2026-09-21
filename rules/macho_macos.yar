// Example YARA rules for macOS Mach-O targets (RealFileType::MacExecutable).
// Kept to plain string matching rather than a "macho" module import - field
// names there are less stable across yara-x versions, so verify module
// availability/API before relying on it in production. Not wired into
// malware.rs yet - see rules/README.md.

// LaunchAgents/LaunchDaemons plists are the standard macOS persistence
// mechanism - a binary that references these paths is commonly installing
// itself to survive reboots.
rule macho_persistence_launchd
{
    meta:
        description = "References launchd persistence paths (LaunchAgents/LaunchDaemons)"
        severity    = "medium"
        target      = "MacExecutable/MachO"

    strings:
        $a = "/Library/LaunchAgents/"
        $b = "/Library/LaunchDaemons/"
        $c = "~/Library/LaunchAgents/"

    condition:
        any of them
}

// Download-and-execute one-liners and AppleScript shell-outs are common in
// macOS malvertising/adware droppers and malicious installer scripts.
rule macho_curl_pipe_shell
{
    meta:
        description = "Embedded 'curl ... | sh' style download-and-execute string, or an osascript shell-out"
        severity    = "high"
        target      = "MacExecutable/MachO"

    strings:
        $a = /curl\s+-[a-zA-Z]*\s*\S+\s*\|\s*(ba)?sh/ nocase
        $b = "osascript -e"

    condition:
        any of them
}
