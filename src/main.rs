use std::env;
use std::fs;
use std::process;

use erratas::scan;
use erratas::spawn_server;

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

fn cli_run(file: &str) {
    if !fs::metadata(&file).is_ok() {
        eprintln!("File {file} doesn't exist");
        process::exit(1);
    }
    println!("Scanning {}", &file);
    let erratas_job = scan(&file);
    println!("{}", erratas_job);
}

fn hosted_run(host: String, port: u16) {
    if let Err(e) = spawn_server(host, port) {
        eprintln!("server error: {e}");
        process::exit(1);
    }
}
