// Scans a single file with erratas' YARA rules and prints every rule
// identifier that matched, one per line. Used by
// scripts/scan_yara_examples.sh to check that the resources/yara_examples/
// fixtures still trip the rule their filename claims.
use std::env;
use std::fs;
use std::process::ExitCode;

use erratas::types::{ErratasJob, FileInfo};

fn main() -> ExitCode {
    let mut args = env::args();
    let _bin = args.next();
    let Some(path) = args.next() else {
        eprintln!("usage: yara_scan_file <file>");
        return ExitCode::FAILURE;
    };

    let contents = match fs::read(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    // yara_scan takes the whole ErratasJob now rather than raw bytes,
    // so build the same "freshly read, not yet scanned" starting point
    // load_file/identify_type's tests use -- only file_info.contents
    // actually matters here, the rest is unexamined by yara_scan today.
    let mut result = ErratasJob {
        file_info: FileInfo {
            contents,
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

    match erratas::malware::yara_scan(&mut result) {
        Ok(matches) => {
            for rule in matches {
                println!("{rule}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("scan error: {e}");
            ExitCode::FAILURE
        }
    }
}
