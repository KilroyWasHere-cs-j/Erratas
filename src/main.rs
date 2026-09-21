use erratas::scan;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: erratas <file>");
        return;
    }
    let path = &args[1];
    println!("Scanning {}", path);
    let erratas_job = scan(path);
    println!(
        "Content flag: {} | Bad language: {} | File type: {} | File sub type: {}",
        erratas_job.file_info.content_flag,
        erratas_job.file_info.bad_language,
        erratas_job.file_info.file_type,
        erratas_job.file_info.file_sub_type
    );
}
