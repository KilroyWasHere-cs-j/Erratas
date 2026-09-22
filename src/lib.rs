//! Erratas — a standalone file-auditing engine.
//!
//! Given a file, reports back on two independent axes: whether it looks
//! malicious (`malware`) and whether its content trips any policy checks
//! (`content`). Meant to be called as a CLI from any language/tool, not
//! linked in as a library — see main.rs for the entry point.
use files::identify_real_filetype;
use std::error::Error;
use std::fs;

use crate::{
    content::scan_content,
    malware::yara_scan,
    types::{ErratasJob, FileInfo},
};

pub mod consts;
pub mod content;
pub mod error;
pub mod files;
pub mod malware;
pub mod types;

pub fn scan(path: &str) -> ErratasJob {
    match load_file(path) {
        Ok(mut erratas_job) => {
            println!("Begining scanning");
            identify_real_filetype(&mut erratas_job);
            println!("Yara results {:?}", yara_scan(&mut erratas_job));
            match scan_content(&mut erratas_job) {
                Ok(_) => {}
                Err(e) => {
                    println!("Error: {e}");
                }
            }
            erratas_job
        }
        // No file could be read, so there's no real ErratasJob to hand
        // back -- fills in the same "nothing determined yet" shape
        // load_file itself starts every job from, just with an empty
        // contents buffer instead of the unreadable file's bytes.
        Err(e) => {
            println!("Error: {e}");
            ErratasJob {
                file_info: FileInfo {
                    contents: Vec::new(),
                    bad_language: false,
                    pii: false,
                    zipbomb: false,
                    malware: false,
                    strike3: Vec::new(),
                    hashmatches: Vec::new(),
                    yara_finds: Vec::new(),
                    file_type: Vec::new(),
                    file_sub_type: Vec::new(),
                },
            }
        }
    }
}

fn load_file(path: &str) -> Result<ErratasJob, Box<dyn Error>> {
    // TODO: Sanitize file path.

    let erratas_job = ErratasJob {
        file_info: FileInfo {
            contents: fs::read(path)?,
            bad_language: false,
            pii: false,
            zipbomb: false,
            malware: false,
            strike3: Vec::new(),
            hashmatches: Vec::new(),
            yara_finds: Vec::new(),
            file_type: Vec::new(),
            file_sub_type: Vec::new(),
        },
    };
    Ok(erratas_job)
}
