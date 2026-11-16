pub static YARA_SCANNER_TIMEOUT: u64 = 5000;
pub static YARA_RULESET_DIR: &str = "rules";
// Entries containing a '.' are domains and match as substrings; the rest are
// multi-word names and match only as whole words. Bare brand words ("deeper",
// "slayed"...) are deliberately absent: they flag ordinary text.
pub static STRIKE3_IP: &[&str] = &[
    "vixen.com",
    "vixen plus",
    "tushy.com",
    "blacked.com",
    "blacked raw",
    "tushy raw",
    "deeper.com",
    "slayed.com",
    "milfy.com",
    "wifey.com",
];
