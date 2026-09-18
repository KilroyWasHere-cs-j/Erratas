//! Erratas — a standalone file-auditing engine.
//!
//! Given a file, reports back on two independent axes: whether it looks
//! malicious (`malware`) and whether its content trips any policy checks
//! (`content`). Meant to be called as a CLI from any language/tool, not
//! linked in as a library — see main.rs for the entry point.
use std::fs;
use content::profanity;
use files::identify_type;

use error::ErratasError;

pub mod malware;
pub mod content;
pub mod error;
pub mod types;
pub mod files;

pub fn scan(path: &str) {
    match load_file(path) {
        Ok(_) => {
            println!("All good!");
        },
        Err(ErratasError::FileNotFound) => {
            println!("File not found.");
        },
        Err(ErratasError::ContentsTooShort) => {
            println!("File too short.");
        },
        Err(e) => {
            println!("Error: {e}");
        }
    }
}

fn load_file(path: &str) -> Result<(), ErratasError> {
    // TODO: Sanitize file path.
    
    if !fs::metadata(path).is_ok() {
        return Err(ErratasError::FileNotFound);
    }
    let file_content = fs::read(path)?;


    println!("Scanning for malware...");
    let result = identify_type(&file_content);
    println!("Detected type: {:?} ({:?})", result.file_type, result.file_sub_type);
    profanity();
    Ok(())
}
