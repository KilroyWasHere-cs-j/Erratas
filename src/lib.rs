//! Erratas — a standalone file-auditing engine.
//!
//! Given a file, reports back on two independent axes: whether it looks
//! malicious (`malware`) and whether its content trips any policy checks
//! (`content`). Meant to be called as a CLI from any language/tool, not
//! linked in as a library — see main.rs for the entry point.
use std::fs;
use content::profanity;
use malware::magick_bytes;

use error::ErratasError;

pub mod malware;
pub mod content;
pub mod error;

pub fn scan(path: &str) {
    let file = load_file(path);
}

fn load_file(path: &str) -> Result<(), ErratasError> {
    // TODO: Sanitize file path.
    let file_content = fs::read(path)?;

    println!("Scanning for malware...");
    magick_bytes(&file_content);
    profanity();
    Ok(())
}
