//! Erratas — a standalone file-auditing engine.
//!
//! Given a file, reports back on two independent axes: whether it looks
//! malicious (`malware`) and whether its content trips any policy checks
//! (`content`). Meant to be called as a CLI from any language/tool, not
//! linked in as a library — see main.rs for the entry point.
use std::fs;
use std::{error::Error, io};

use crate::{
    content::scan_content,
    files::identify_real_filetype,
    malware::yara_scan,
    types::{ErratasJob, FileInfo},
};

mod consts;
mod content;
mod files;
pub mod malware;
mod server;
pub mod types;

/// Reads the file at `path` and runs every check on it: real file type, then
/// YARA, then content (OCR/text) scanning. The checks run in that order because
/// the content scan reads the file type the first step fills in.
///
/// # Arguments
///
/// * `path` - File to scan. Not sanitized yet (see the TODO in `load_file`),
///   so callers must not pass untrusted paths.
///
/// # Returns
///
/// The finished job. A check that fails does not fail the scan: its message is
/// pushed onto `file_info.errors` and the other checks still run.
///
/// # Errors
///
/// Returns an error only if the file can't be read.
pub fn scan_path(path: &str) -> Result<ErratasJob, Box<dyn Error>> {
    match load_file(path) {
        Ok(mut erratas_job) => {
            println!("Beginning scanning");
            identify_real_filetype(&mut erratas_job);
            yara_scan(&mut erratas_job);
            scan_content(&mut erratas_job);
            Ok(erratas_job)
        }
        Err(e) => return Err(e.into()),
    }
}

/// Runs every check on bytes already in memory, for callers that have the data
/// but no file on disk. Does the same checks in the same order as `scan_path`.
///
/// # Arguments
///
/// * `bytes` - The whole file. Copied into the job, so the caller keeps its
///   own buffer, but a large file briefly takes up memory twice.
///
/// # Returns
///
/// The finished job. A check that fails does not fail the scan: its message is
/// pushed onto `file_info.errors` and the other checks still run.
///
/// # Errors
///
/// Returns an error only if building the job fails, which currently can't happen.
pub fn scan_bytes(bytes: &[u8]) -> Result<ErratasJob, Box<dyn Error>> {
    match load_bytes(bytes) {
        Ok(mut erratas_job) => {
            println!("Beginning scanning");
            identify_real_filetype(&mut erratas_job);
            yara_scan(&mut erratas_job);
            scan_content(&mut erratas_job);
            Ok(erratas_job)
        }
        Err(e) => return Err(e.into()),
    }
}

/// Wraps bytes in a job with every result field still at its "nothing found
/// yet" value.
///
/// # Arguments
///
/// * `bytes` - The file contents, copied into `file_info.contents`.
///
/// # Returns
///
/// A fresh job. The `Result` only mirrors `load_file`'s signature; this never fails.
fn load_bytes(bytes: &[u8]) -> Result<ErratasJob, io::Error> {
    Ok(ErratasJob {
        file_info: FileInfo {
            contents: bytes.to_vec(),
            bad_language: false,
            pii: false,
            malware: false,
            strike3: Vec::new(),
            hashmatches: Vec::new(),
            yara_finds: Vec::new(),
            file_type: Vec::new(),
            file_sub_type: Vec::new(),
            errors: Vec::new(),
        },
    })
}

/// Reads the whole file into memory and wraps it in a job with every result
/// field still at its "nothing found yet" value.
///
/// # Arguments
///
/// * `path` - File to read. The entire file is loaded, so memory use grows
///   with file size.
///
/// # Returns
///
/// A fresh job holding the file's bytes in `file_info.contents`.
///
/// # Errors
///
/// Returns the I/O error if the file is missing or unreadable.
fn load_file(path: &str) -> Result<ErratasJob, io::Error> {
    // TODO: Sanitize file path.
    // let (contents, err) = match fs::read(path) {
    //     Ok(bytes) => (bytes, None),
    //     Err(e) => (Vec::new(), Some(format!("Failed to read file: {e}"))),
    // };
    // if err
    let contents = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => return Err(e),
    };
    Ok(ErratasJob {
        file_info: FileInfo {
            contents: contents,
            bad_language: false,
            pii: false,
            malware: false,
            strike3: Vec::new(),
            hashmatches: Vec::new(),
            yara_finds: Vec::new(),
            file_type: Vec::new(),
            file_sub_type: Vec::new(),
            errors: Vec::new(),
        },
    })
}

/// Starts the TCP upload-and-scan server. Blocks the calling thread for as long
/// as the server runs.
///
/// # Arguments
///
/// * `ip` - Address to bind. Use `127.0.0.1` to accept local connections only;
///   anything wider exposes an unauthenticated upload port.
/// * `port` - Port to listen on. Fails if it's already taken.
///
/// # Errors
///
/// Returns an error if the address can't be bound.
pub fn spawn_server(ip: String, port: u16) -> Result<(), Box<dyn Error>> {
    server::serve(&ip, port)
}
