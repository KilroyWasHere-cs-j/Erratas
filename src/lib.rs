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
    types::{ErratasContentFlag, ErratasJob, FileInfo, RealFileSubType, RealFileType},
};

pub mod consts;
pub mod content;
pub mod error;
pub mod files;
pub mod malware;
pub mod types;

pub fn scan(path: &str) {
    match load_file(path) {
        Ok(mut erratas_job) => {
            println!("Begining scanning");
            identify_real_filetype(&mut erratas_job);
            println!("Yara results {:?}", yara_scan(&mut erratas_job));
            // OCR only makes sense on image content -- every other type
            // (archives, executables, ...) would just fail format-sniffing
            // in preprocess() every time, so skip the call entirely rather
            // than pay for it and throw the error away.
            if erratas_job.file_info.file_type == RealFileType::Image {
                println!("Content scan results {:?}", scan_content(&mut erratas_job));
            }
        }
        Err(e) => {
            println!("Error: {e}");
        }
    }
}

fn load_file(path: &str) -> Result<ErratasJob, Box<dyn Error>> {
    // TODO: Sanitize file path.

    Ok(ErratasJob {
        file_info: FileInfo {
            contents: fs::read(path)?,
            content_flag: ErratasContentFlag::Scanning,
            file_type: RealFileType::Unknown,
            file_sub_type: RealFileSubType::Unknown(types::UnknownSubType::Unknown),
        },
    })
}
