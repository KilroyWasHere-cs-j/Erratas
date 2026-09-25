use std::error::Error;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use crate::scan;

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

    let job = scan(&path);

    // Serialize directly into the stream, with no String in the middle.
    // serde_json::Error converts into io::Error, so `?` works here too.
    serde_json::to_writer(&mut stream, &job)?;

    // to_writer doesn't add a line break; add one so the client can read line by line
    stream.write_all(b"\n")?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Shutdown, SocketAddr};
    use std::thread::JoinHandle;

    // Upper bound on how long a client waits for a reply, so a hung
    // server fails the test instead of hanging `cargo test` forever.
    // Generous because the first scan also compiles the YARA rules.
    const CLIENT_TIMEOUT: Duration = Duration::from_secs(60);

    // Binds to port 0 (OS picks a free one) and hands exactly one
    // connection to `handle_client`. Returning the JoinHandle lets a test
    // inspect the handler's own Result, not just what the client saw.
    fn one_shot_server() -> (SocketAddr, JoinHandle<io::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept()?;
            handle_client(stream)
        });

        (addr, handle)
    }

    fn connect(addr: SocketAddr) -> TcpStream {
        let stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(CLIENT_TIMEOUT)).unwrap();
        stream
    }

    // Sends a well-formed upload (8-byte big-endian length, then the body)
    // and reads everything the server says until it closes the socket.
    fn upload(addr: SocketAddr, body: &[u8]) -> String {
        let mut stream = connect(addr);
        stream
            .write_all(&(body.len() as u64).to_be_bytes())
            .unwrap();
        stream.write_all(body).unwrap();

        let mut reply = String::new();
        stream.read_to_string(&mut reply).unwrap();
        reply
    }

    // Pulls "upload-N.bin" out of the "OK ... saved to <path>" line so the
    // test can check the file and clean it up afterwards (the server
    // writes into the working directory and never deletes on success).
    fn saved_path(reply: &str) -> String {
        let first = reply.lines().next().expect("empty reply");
        first
            .rsplit(' ')
            .next()
            .expect("no path in OK line")
            .to_string()
    }

    // Finds a port that's free right now. Small window where another
    // process could grab it before `serve` binds, but fine for tests.
    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    // `serve` binds on its own thread, so the first connects can land
    // before it's listening -- retry briefly instead of sleeping blindly.
    fn connect_with_retry(port: u16) -> TcpStream {
        for _ in 0..50 {
            if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
                stream.set_read_timeout(Some(CLIENT_TIMEOUT)).unwrap();
                return stream;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("server never started listening on port {port}");
    }

    #[test]
    fn upload_is_saved_and_acknowledged() {
        let body = b"hello from the erratas server tests";
        let (addr, handle) = one_shot_server();

        let reply = upload(addr, body);
        handle.join().unwrap().unwrap();

        let path = saved_path(&reply);
        assert!(
            reply.starts_with(&format!("OK {} bytes saved to upload-", body.len())),
            "unexpected reply: {reply}"
        );

        // Bytes on disk must match exactly what was sent.
        let on_disk = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(on_disk, body);
    }

    #[test]
    fn scan_result_line_is_valid_json() {
        let (addr, handle) = one_shot_server();

        let reply = upload(addr, b"plain text, nothing to see here");
        handle.join().unwrap().unwrap();
        std::fs::remove_file(saved_path(&reply)).unwrap();

        // Line 2 is the scan result a client would parse.
        let json_line = reply.lines().nth(1).expect("no scan result line");
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(json_line);
        assert!(parsed.is_ok(), "scan line isn't valid JSON: {json_line}");

        // Spot-check the shape so a silently empty object doesn't pass.
        let value = parsed.unwrap();
        assert!(value["file_info"]["malware"].is_boolean());
    }

    #[test]
    fn empty_upload_is_accepted() {
        let (addr, handle) = one_shot_server();

        let reply = upload(addr, b"");
        handle.join().unwrap().unwrap();

        let path = saved_path(&reply);
        assert!(
            reply.starts_with("OK 0 bytes saved to "),
            "unexpected reply: {reply}"
        );
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn oversized_upload_is_rejected_before_reading_body() {
        let (addr, handle) = one_shot_server();
        let mut stream = connect(addr);

        // Only the header is sent -- if the server tried to read a body
        // it would block, so getting a reply at all proves it didn't.
        stream.write_all(&(MAX_UPLOAD + 1).to_be_bytes()).unwrap();

        let mut reply = String::new();
        stream.read_to_string(&mut reply).unwrap();

        assert_eq!(reply, "ERR too large\n");
        assert!(handle.join().unwrap().is_ok());
    }

    #[test]
    fn upload_at_exact_limit_is_not_rejected_by_size_check() {
        let (addr, handle) = one_shot_server();
        let mut stream = connect(addr);

        // Claim exactly MAX_UPLOAD, send nothing, then hang up. The size
        // check must let it through, so the failure is "cut short" rather
        // than "too large" -- this pins the boundary at `>` not `>=`.
        stream.write_all(&MAX_UPLOAD.to_be_bytes()).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();

        let mut reply = String::new();
        stream.read_to_string(&mut reply).unwrap();

        assert_ne!(reply, "ERR too large\n");
        let err = handle.join().unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn truncated_upload_is_reported_as_error() {
        let (addr, handle) = one_shot_server();
        let mut stream = connect(addr);

        // Promise 100 bytes, deliver 10, then close our write side so the
        // server sees end-of-stream instead of waiting on the read timeout.
        stream.write_all(&100u64.to_be_bytes()).unwrap();
        stream.write_all(&[0xAB; 10]).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();

        // Client should get no "OK" -- the socket just closes.
        let mut reply = String::new();
        stream.read_to_string(&mut reply).unwrap();
        assert!(reply.is_empty(), "expected no reply, got: {reply}");

        let err = handle.join().unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(err.to_string(), "upload cut short");
    }

    #[test]
    fn partial_length_header_is_reported_as_error() {
        let (addr, handle) = one_shot_server();
        let mut stream = connect(addr);

        // Only 3 of the 8 header bytes, then hang up.
        stream.write_all(&[0, 0, 1]).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();

        let err = handle.join().unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn serve_handles_several_clients_at_once() {
        let port = free_port();

        // `serve` loops forever, so this thread is intentionally leaked;
        // it dies with the test process.
        thread::spawn(move || serve("127.0.0.1", port).unwrap());

        // Open every connection before any of them finishes, so the
        // uploads overlap and exercise the one-thread-per-client path.
        let bodies: Vec<Vec<u8>> = (0..4).map(|i| vec![b'a' + i as u8; 64 * (i + 1)]).collect();
        let mut streams: Vec<TcpStream> = bodies.iter().map(|_| connect_with_retry(port)).collect();

        for (stream, body) in streams.iter_mut().zip(&bodies) {
            stream
                .write_all(&(body.len() as u64).to_be_bytes())
                .unwrap();
            stream.write_all(body).unwrap();
        }

        // Each client gets its own ack, its own file, and its own bytes.
        let mut paths = Vec::new();
        for (stream, body) in streams.iter_mut().zip(&bodies) {
            let mut reply = String::new();
            stream.read_to_string(&mut reply).unwrap();
            assert!(
                reply.starts_with(&format!("OK {} bytes saved to ", body.len())),
                "unexpected reply: {reply}"
            );

            let path = saved_path(&reply);
            assert_eq!(&std::fs::read(&path).unwrap(), body);
            paths.push(path);
        }

        for path in &paths {
            std::fs::remove_file(path).unwrap();
        }

        // Unique ids -> no two uploads overwrote each other.
        paths.sort();
        paths.dedup();
        assert_eq!(paths.len(), bodies.len());
    }

    #[test]
    fn serve_errors_when_port_is_taken() {
        // Hold the port so `serve` can't bind it.
        let squatter = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = squatter.local_addr().unwrap().port();

        assert!(serve("127.0.0.1", port).is_err());
    }
}
