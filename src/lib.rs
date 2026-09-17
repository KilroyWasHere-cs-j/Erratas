//! Erratas — a standalone file-auditing engine.
//!
//! Given a file, reports back on two independent axes: whether it looks
//! malicious (`malware`) and whether its content trips any policy checks
//! (`content`). Meant to be called as a CLI from any language/tool, not
//! linked in as a library — see main.rs for the entry point.
use std::fs::File;
use std::io::Read;

pub mod malware;
pub mod content;
pub mod error;

pub fn scan(path: &str) {
    let file = load_file(path);
}

fn load_file(path: &str) {
    let mut f = File::open(path).unwrap();
    let mut contents = String::new();
    f.read_to_string(&mut contents).unwrap();
    if contents.len() < 2 {
        println!("File is too small to be scanned.");
        return;
    }
    println!("With text:\n{}", contents);
}
