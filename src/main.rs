use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: erratas <file>");
        return ExitCode::FAILURE;
    };

    // TODO: once audit_file is implemented, format the AuditReport as
    // JSON on stdout so other tools can consume this over a subprocess
    // call, per the CLI-binary interface decided on.
    match erratas::audit_file(&PathBuf::from(path)) {
        Ok(report) => {
            println!("{report:#?}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("erratas: {err}");
            ExitCode::FAILURE
        }
    }
}
