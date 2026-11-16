// Rules for HTML files (#7). Each one only fires when the file looks like
// HTML (a doctype or <html> tag in the first 1 KB), so a binary that merely
// contains these strings isn't flagged. Plain <script> tags, event handlers
// and iframes are checked by the parser in malware.rs (html_scan) instead.

// eval() applied directly to a decoder call is the classic way to hide a
// JavaScript payload. eval, atob etc. merely appearing in the same file (as
// in bundled or minified code) is not enough, so the call must be nested.
rule html_obfuscated_javascript
{
    meta:
        description = "eval(atob(...)), eval(unescape(...)) or eval(String.fromCharCode(...))"
        severity    = "high"
        target      = "Document/HTML"

    strings:
        $d1 = "<!doctype html" nocase
        $d2 = "<html" nocase
        $nested = /eval\s*\(\s*(atob|unescape|String\.fromCharCode)\s*\(/ nocase

    condition:
        any of ($d*) in (0..1024) and $nested
}

// document.write(unescape("%3Cscript...")) writes hidden markup at load time.
rule html_document_write_unescape
{
    meta:
        description = "document.write(unescape(...)) injecting hidden markup"
        severity    = "high"
        target      = "Document/HTML"

    strings:
        $d1 = "<!doctype html" nocase
        $d2 = "<html" nocase
        $dw = "document.write(unescape(" nocase

    condition:
        any of ($d*) in (0..1024) and $dw
}

// Long runs of \x41\x42... or %u0041%u0042... are encoded payloads, not prose.
rule html_long_escape_run
{
    meta:
        description = "Long run of \\x or %u escape sequences (encoded payload)"
        severity    = "high"
        target      = "Document/HTML"

    strings:
        $d1 = "<!doctype html" nocase
        $d2 = "<html" nocase
        $hex = /(\\x[0-9a-f]{2}){20,}/ nocase
        $uni = /(%u[0-9a-f]{4}){10,}/ nocase

    condition:
        any of ($d*) in (0..1024) and any of ($hex, $uni)
}

// A <meta> refresh to another host redirects the visitor without any script.
rule html_meta_refresh_external
{
    meta:
        description = "<meta http-equiv=refresh> redirecting to an external URL"
        severity    = "high"
        target      = "Document/HTML"

    strings:
        $d1 = "<!doctype html" nocase
        $d2 = "<html" nocase
        $refresh = /<meta[^>]{0,200}http-equiv\s*=\s*["']?refresh[^>]{0,200}url\s*=\s*["']?(https?:)?\/\//i

    condition:
        any of ($d*) in (0..1024) and $refresh
}
