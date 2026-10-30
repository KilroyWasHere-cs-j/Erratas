# Erratas

A standalone file-auditing engine written in Rust. It runs as its own
process, either as a CLI you point at a file or as a TCP server you upload
files to, so any tool in any language can use it without linking it in as a
library. Originally split out to replace the ad-hoc validation checks in
[Dewey](https://github.com/KilroyWasHere-cs-j/Dewey)'s file uploader, but
meant to be reused across other tools too.

## What it checks

Every scan runs three steps, in this order (later steps depend on the first):

1. **Real file type** — identifies the file from its magic bytes (not its
   extension) in a single Aho-Corasick pass. Covers images (PNG, JPEG, GIF,
   BMP, WEBP, TIFF), video (MP4, WEBM, AVI), audio (WAV, FLAC, OGG, MP3),
   documents (DOC/DOCX, XLS/XLSX, PPT/PPTX, PDF, CHM), archives (ZIP, TAR,
   RAR, 7z, CAB, DMG, ISO) and executables (PE, ELF, Mach-O, DLL, SO, LNK).
2. **Malware** — runs the YARA rules in `rules/` (via `yara-x`) over the
   file. Every hit is recorded with its rule name, severity, tags, targets
   and matched strings. `malware` is set to `true` on any **Medium or
   higher** severity hit.
3. **Content** — extracts text and checks it for bad language and for
   known Strike 3 brand names (`STRIKE3_IP` in `src/consts.rs`). Text comes
   from OCR for images, and direct extraction for PDF, DOCX, XLSX and PPTX.

A step that fails (bad OCR, corrupt PDF, YARA timeout) doesn't stop the
scan. Its message goes into `errors` and the other steps still run.

## Why a separate process instead of a library

Malware scanning means parsing untrusted, adversarial bytes. A bug in
that code should crash an isolated subprocess, not the application that
called it — which is the same reason most AV/content-scanning engines
run as their own process rather than linking in as a library. It also
means Erratas ships and updates independently of whatever's calling it.

## Why Rust (not Go)

Came up while investigating the scan hot-path performance work
([#27](https://github.com/KilroyWasHere-cs-j/Erratas/issues/27)): would Go
be meaningfully slower for this kind of byte-scanning workload? Tested it
directly rather than guessing, with two standalone (non-project) mockups —
a hand-rolled Aho-Corasick automaton (trie + failure links, no external
dependencies) built identically in both languages, searching the same 37
magic-byte patterns from `MAGIC_PATTERNS` in `src/files.rs`:

| Scenario | Go | Rust | Rust is... |
|---|---:|---:|---:|
| 64 B file | 0.001s | 0.001s | tied |
| 518 KB real PDF | 0.011s | 0.002s | ~5.5x faster |
| 10 MB, worst case | 0.165s | 0.021s | ~8x faster |

Same algorithm, same patterns, same inputs — the gap is real, likely from
Go's GC and less aggressive inlining/bounds-check elision showing up on a
tight per-byte scan loop.

Beyond the raw numbers, the two heaviest dependencies this project leans
on are also a better fit in Rust specifically: `yara-x` is a from-scratch
*pure-Rust* reimplementation of YARA, chosen to avoid linking the C
`libyara` at all, and Tesseract OCR needs FFI either way but Rust's is
lower-overhead than Go's cgo. A Go rewrite would mean pulling `libyara`
back in via cgo (or a less mature Go YARA binding) and paying cgo's
per-call overhead on every OCR call too.

## Requirements

- Rust (edition 2024, so a recent stable toolchain)
- Tesseract and Leptonica development libraries (the `tesseract` crate
  links against them), plus `libclang` for the generated bindings, and the
  English language data (`eng`) at runtime:

  ```bash
  # Debian / Ubuntu
  sudo apt-get install libtesseract-dev libleptonica-dev libclang-dev tesseract-ocr-eng
  ```

## Usage

Erratas reads the YARA rules from the `ERRATAS_RULES_DIR` environment
variable if it's set, otherwise from `rules/` relative to the **current
working directory**, so run it from the repo root (or wherever `rules/`
sits). Programs using Erratas as a library can call `malware::set_rules_dir`
once at startup instead.

### CLI mode

```bash
cargo run -- <file>
```

Prints a one-line summary: file type, PII / malware / bad-language flags,
Strike 3 matches, YARA hits, and any non-fatal errors. The exit code is 1
only if the file doesn't exist; a failed scan is printed but doesn't change
the exit code.

### Server mode

```bash
cargo run -- host [host] [port]    # defaults: 127.0.0.1 9000
```

Starts a TCP server. Each client gets its own thread and sends:

1. An 8-byte big-endian length.
2. That many bytes of file data.

The server replies with:

1. `OK <n> bytes saved to <path>` (or `ERR too large` if the length is over
   1 GB, in which case nothing is saved).
2. One line of JSON: the full scan result (`{"file_info": {...}}`).

The uploaded file is saved to the working directory as `upload-<id>.bin`
and deleted when the connection finishes, success or not. Reads time out
after 30 seconds.

**Security notes:** the server has no authentication and no cap on
simultaneous clients. Bind to `127.0.0.1` or put it behind a trusted
network boundary. Also, the scan path is not sanitized yet (see the TODO in
`load_file` in `src/lib.rs`), so don't pass untrusted paths to the CLI.

### Result fields

`file_info` in the JSON output contains:

| Field | Meaning |
|---|---|
| `file_type`, `file_sub_type` | Detected type(s) from magic bytes |
| `malware` | `true` if any YARA hit is Medium severity or higher |
| `yara_finds` | Every rule hit (rule, namespace, tags, description, severity, targets, matched strings) |
| `bad_language` | Profanity / offensive / sexual text found in extracted text |
| `strike3` | Strike 3 brand names found in extracted text |
| `errors` | Non-fatal problems hit during the scan |
| `pii`, `hashmatches` | Placeholders for now, always empty / `false` (see TODO) |

## Container deploy

`Containerfile` builds a slim image that runs `erratas host 0.0.0.0 9000`
as an unprivileged user. `deploy.py` builds it and (re)creates `erratas-pod`
with podman, dropping all capabilities and publishing port 9000:

```bash
python3 deploy.py
```

## YARA rules

The starter rule sets in `rules/` are teaching examples, not a production
detection set. See [rules/README.md](rules/README.md) for what each file
covers and the caveats. Rules take `description`, `severity`
(`low` / `medium` / `high` / `critical`) and `target` metadata; an
unrecognized severity is reported as `Unknown` and does not set `malware`.

## Testing

```bash
cargo test                       # Rust unit tests
python3 scripts/run_all_tests.py # everything: Rust tests, format detection, YARA fixtures, strike3 word list and server mode
```

Run `scripts/run_all_tests.py` from the repo root.

CI (`.github/workflows/ci.yml`) builds and runs `cargo test` on every push
and pull request.

## Layout

```
src/
  main.rs      CLI entry point — file scan, or `host` for server mode
  lib.rs       scan_path() / scan_bytes() run file type → YARA → content; spawn_server()
  files.rs     real file type detection (magic bytes)
  malware.rs   YARA rule loading and scanning
  content.rs   text extraction (OCR / PDF / Office) and bad-language / brand checks
  server.rs    TCP upload-and-scan server
  types.rs     FileInfo, ErratasJob, RuleHit, file type enums
  consts.rs    YARA timeout and rules directory, Strike 3 term list
rules/         YARA rule sets
scripts/       combined test runner
Containerfile, deploy.py   container build and podman deploy
```

Binary and library live in the same Cargo package (`main.rs` links to
the lib via the package's own name) — no workspace split needed yet.

## TODO

- [ ] PII detection (SSN, credit card, email, phone) — `content::_pii` is an empty stub and `pii` is never set
- [ ] Known-bad hash lookup — `malware::_hash_matching` is an empty stub and `hashmatches` is never filled; needs a maintained signature source
- [ ] Archive structure checks (compression-ratio / nesting-depth limits) to catch zip bombs before decompressing
- [ ] Sanitize the file path in `load_file`
- [ ] Authentication and a client cap for server mode
- [ ] Server mode still saves each upload to disk; switch it to `scan_bytes`
