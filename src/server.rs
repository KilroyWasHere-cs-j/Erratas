use std::error::Error;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

// Reject anything bigger than this before reading a single byte of it.
const MAX_UPLOAD: u64 = 100 * 1024 * 1024; // 100 MB

// Gives each upload its own file name.
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

fn handle_client(mut stream: TcpStream) -> io::Result<()> {
    // Drop clients that stall, so they can't tie up a thread forever.
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    // Framing: the client sends the file size first, as 8 big-endian bytes.
    // TCP is one continuous byte stream, so this is how we know where the file ends.
    let mut len_buf = [0u8; 8];
    stream.read_exact(&mut len_buf)?;
    let len = u64::from_be_bytes(len_buf);

    if len > MAX_UPLOAD {
        stream.write_all(b"ERR too large\n")?;
        return Ok(());
    }

    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let path = format!("upload-{id}.bin");
    let mut file = BufWriter::new(File::create(&path)?);

    // Stream exactly `len` bytes from the socket into the file, in small chunks.
    // The whole file is never held in memory.
    // `(&mut stream).take(..)` borrows the stream so we can still reply afterwards.
    let copied = io::copy(&mut (&mut stream).take(len), &mut file)?;
    file.flush()?;

    // Fewer bytes than promised means the client hung up partway through.
    if copied != len {
        std::fs::remove_file(&path)?;
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "upload cut short",
        ));
    }

    // Tell the client it arrived. A real server could run a scan here and send the result.
    writeln!(stream, "OK {copied} bytes saved to {path}")?;
    Ok(())
}

pub fn serve(ip: &str, port: u16) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind((ip, port))?;
    println!("Listening on {}", listener.local_addr()?);

    for stream in listener.incoming() {
        match stream {
            // One thread per client, so one slow upload doesn't block the rest.
            // `handle_client` takes no `self`, so the closure owns everything it uses.
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream) {
                        eprintln!("client error: {e}");
                    }
                });
            }
            // A failed accept is about one connection, not the listener. Keep going.
            Err(e) => eprintln!("accept failed: {e}"),
        }
    }
    Ok(())
}
