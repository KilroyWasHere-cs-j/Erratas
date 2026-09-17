use std::env;
use erratas::scan;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: erratas <file>");
        return;
    }
    let path = &args[1];
    println!("Scanning {}", path);
    scan(path);
}
