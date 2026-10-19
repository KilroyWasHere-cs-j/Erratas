use std::env;
use std::fs;
use std::process;

use erratas::scan_path;
use erratas::spawn_server;

/// Command-line entry point: `erratas <file> [host] [port]`.
///
/// Passing the word `host` instead of a file name starts the upload server
/// rather than scanning anything. Exits with code 1 on a missing or extra
/// argument, an invalid port, a missing file, or a server error.
///
/// # Arguments
///
/// Read from the command line, not the signature:
///
/// * `file` - Path to scan, or `host` to run as a server.
/// * `host` - Address to bind in server mode. Defaults to `127.0.0.1`.
/// * `port` - Port to bind in server mode, 0 to 65535. Defaults to 9000.
fn main() {
    // Skip item 0, which is usually the program's own path.
    let mut args = env::args().skip(1);

    // Required: exit with a usage message if it's missing.
    let Some(file) = args.next() else {
        eprintln!("usage: erratas <file> [host] [port]");
        process::exit(1);
    };

    // Optional: fall back to a default when left off.
    let host = args.next().unwrap_or_else(|| "127.0.0.1".to_string());

    // Optional and numeric: default when missing, error when it isn't a valid number.
    let port: u16 = match args.next() {
        None => 9000,
        Some(p) => p.parse().unwrap_or_else(|_| {
            eprintln!("port must be a number from 0 to 65535, got '{p}'");
            process::exit(1);
        }),
    };

    // Reject extra args instead of silently ignoring them.
    if args.next().is_some() {
        eprintln!("too many arguments");
        process::exit(1);
    }

    if file == "host" {
        hosted_run(host, port);
    } else {
        cli_run(&file);
    }
}

/// Scans one file and prints the result. Exits the process with code 1 if the
/// file doesn't exist; a failed scan is printed but does not change the exit code.
///
/// # Arguments
///
/// * `file` - Path of the file to scan.
fn cli_run(file: &str) {
    if !fs::metadata(&file).is_ok() {
        eprintln!("File {file} doesn't exist");
        process::exit(1);
    }
    println!("Scanning {}", &file);
    match scan_path(&file) {
        Ok(erratas_job) => println!("{}", erratas_job),
        Err(error) => println!("Failed to scan file {error}"),
    }
}

/// Runs the scan server until it stops. Exits the process with code 1 if the
/// server fails to start or dies with an error.
///
/// # Arguments
///
/// * `host` - Address to bind.
/// * `port` - Port to listen on.
fn hosted_run(host: String, port: u16) {
    if let Err(e) = spawn_server(host, port) {
        eprintln!("server error: {e}");
        process::exit(1);
    }
}
