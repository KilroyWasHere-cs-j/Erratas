#!/usr/bin/env python3
"""Runs every testing script this repo has scattered across scripts/ and
strike3/ as one combined suite:

  0. cargo test              -- the Rust unit test suite.
  1. Format detection        -- was scripts/generate_and_scan_examples.sh.
                                 Generates one synthetic fixture per format
                                 identify_real_filetype() knows how to
                                 detect, in both its "normal" mode (magic
                                 bytes at their expected offset) and its
                                 "shifted" mode (magic bytes pushed back by
                                 a 0x90 filler block, forcing each check_*'s
                                 scan_for()/scan_for_at_offset() fallback
                                 path instead of its fast fixed-offset one),
                                 then runs erratas against each and checks
                                 a real type came back.
  2. YARA rule fixtures       -- was scripts/scan_yara_examples.sh. Runs
                                 every fixture in resources/yara_examples/
                                 through the yara_scan_file example and
                                 checks it trips the rule its filename is
                                 named after.
  3. strike3 word list        -- was strike3/generate_images.sh +
                                 test_strike3.sh + run_erratas.sh combined:
                                 generates one block-letter-on-black PNG per
                                 term in src/consts.rs's STRIKE3_IP (the
                                 single source of truth for the blocklist --
                                 not a separate wordlist file, which drifted
                                 out of sync with it in practice), verifies
                                 Tesseract reads each one back correctly,
                                 then runs erratas against each and checks
                                 the strike3 field in its output actually
                                 fired.
  4. Server mode              -- starts `erratas host 127.0.0.1 <port>` as
                                 a real subprocess and talks to it over TCP
                                 the way an outside caller would: uploads
                                 each format fixture and checks the JSON
                                 scan result, checks a strike3 image trips
                                 the content scan, that oversized and
                                 cut-short uploads are handled, that the
                                 server survives a bad client, that
                                 overlapping uploads all succeed, and that
                                 no upload-*.bin files are left behind.

Each phase reports its own pass/fail tally; the script's exit code is
nonzero if anything, anywhere, failed.

Usage: python3 scripts/run_all_tests.py
"""

from __future__ import annotations

import json
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO_ROOT = Path(__file__).resolve().parent.parent
RESOURCES_DIR = REPO_ROOT / "resources"
YARA_EXAMPLES_DIR = RESOURCES_DIR / "yara_examples"
STRIKE3_DIR = REPO_ROOT / "strike3"
CONSTS_RS = REPO_ROOT / "src" / "consts.rs"
FONT_PATH = "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf"

GREEN = "\033[0;32m"
RED = "\033[0;31m"
RESET = "\033[0m"


class Tally:
    """Running pass/fail count for one phase."""

    def __init__(self, name: str):
        self.name = name
        self.passed = 0
        self.failed = 0

    def record(self, ok: bool, label: str, detail: str = "") -> None:
        color = GREEN if ok else RED
        status = "PASS" if ok else "FAIL"
        if ok:
            self.passed += 1
        else:
            self.failed += 1
        suffix = f" -- {detail}" if detail else ""
        print(f"{color}{status:4} {label}{suffix}{RESET}")

    def summary(self) -> bool:
        total = self.passed + self.failed
        print(f"\n{self.name}: {self.passed}/{total} passed\n")
        return self.failed == 0


def run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=cwd or REPO_ROOT, capture_output=True, text=True, check=False
    )


def header(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def extract_display_output(stdout: str) -> str:
    """Returns everything main.rs printed after its stable "Yara results"
    marker -- i.e. the FileInfo Display line. Fields like `strike3` can
    embed raw OCR text (including trailing newlines from Tesseract), so
    that line isn't reliably the *last* line of output -- grabbing
    everything after the marker instead of just the last line keeps a
    field's value intact even when it wraps onto its own line."""
    marker = "Yara results"
    idx = stdout.find(marker)
    if idx == -1:
        return stdout.strip()
    after_marker = stdout[idx + len(marker) :]
    _, _, remainder = after_marker.partition("\n")
    return remainder.strip("\n")


# --- Phase 0: cargo test --------------------------------------------------


def phase_cargo_test() -> bool:
    header("Phase 0: cargo test (Rust unit tests)")
    result = run(["cargo", "test", "--quiet"])
    print(result.stdout)
    if result.returncode != 0:
        print(f"{RED}cargo test failed:{RESET}")
        print(result.stderr)
        return False
    print(f"{GREEN}cargo test passed{RESET}")
    return True


# --- Phase 1: format detection (normal + shifted) -------------------------

# (name, min_size, initial bytes at offset 0, [(offset, bytes), ...], append_after_padding)
FormatFixture = tuple[str, int, bytes, list[tuple[int, bytes]], bytes | None]

FORMAT_FIXTURES: list[FormatFixture] = [
    # --- executables ---
    ("example.elf", 64, bytes([0x7F, 0x45, 0x4C, 0x46]), [], None),
    (
        "example.so",
        64,
        bytes(
            [
                0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x03, 0x00,
            ]
        ),
        [],
        None,
    ),
    ("example.exe", 64, bytes([0x4D, 0x5A]), [(60, bytes([0x50, 0x45, 0x00, 0x00]))], None),
    (
        "example.dll",
        256,
        bytes([0x4D, 0x5A]),
        [
            (60, bytes([0x80, 0x00, 0x00, 0x00])),
            (128, bytes([0x50, 0x45, 0x00, 0x00])),
            (132, bytes([0x64, 0x86])),
            (150, bytes([0x00, 0x20])),
        ],
        None,
    ),
    (
        "example.lnk",
        64,
        bytes(
            [
                0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00,
                0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
            ]
        ),
        [],
        None,
    ),
    ("example_macho32.bin", 64, bytes([0xFE, 0xED, 0xFA, 0xCE]), [], None),
    ("example_macho64.bin", 64, bytes([0xFE, 0xED, 0xFA, 0xCF]), [], None),
    ("example_macho_fat.bin", 64, bytes([0xCA, 0xFE, 0xBA, 0xBE]), [], None),
    # --- archives / disk images ---
    ("example.dmg", 1024, b"", [(512, bytes([0x6B, 0x6F, 0x6C, 0x79]))], None),
    ("example.zip", 64, bytes([0x50, 0x4B, 0x03, 0x04]), [], None),
    ("example.rar", 64, bytes([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]), [], None),
    ("example.7z", 64, bytes([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]), [], None),
    ("example.cab", 64, bytes([0x4D, 0x53, 0x43, 0x46]), [], None),
    ("example.tar", 512, b"", [(257, bytes([0x75, 0x73, 0x74, 0x61, 0x72]))], None),
    (
        "example.iso",
        0x8001 + 8,
        b"",
        [(0x8001, bytes([0x43, 0x44, 0x30, 0x30, 0x31]))],
        None,
    ),
    # --- documents ---
    ("example.pdf", 64, bytes([0x25, 0x50, 0x44, 0x46, 0x2D]), [], None),
    (
        "example_legacy.doc",
        64,
        bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
        [],
        None,
    ),
    (
        "example_installer.msi",
        64,
        bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
        [],
        None,
    ),
    ("example.chm", 64, bytes([0x49, 0x54, 0x53, 0x46]), [], None),
    # OOXML fixtures: check_ooxml needs the ZIP signature plus
    # "[Content_Types].xml" present anywhere to classify as a Document at
    # all, then ooxml_subtype needs each format's own main-part path
    # (word/document.xml, xl/workbook.xml, xl/workbook.bin, or
    # ppt/presentation.xml) to pick the specific subtype -- so every
    # entry below carries both markers.
    (
        "example.docx",
        64,
        bytes([0x50, 0x4B, 0x03, 0x04]),
        [],
        b"[Content_Types].xmlword/document.xml",
    ),
    (
        "example.xlsx",
        64,
        bytes([0x50, 0x4B, 0x03, 0x04]),
        [],
        b"[Content_Types].xmlxl/workbook.xml",
    ),
    (
        # .xlsb (Excel Binary Workbook) -- same OOXML zip container, but
        # its main part is binary (xl/workbook.bin) instead of XML.
        "example.xlsb",
        64,
        bytes([0x50, 0x4B, 0x03, 0x04]),
        [],
        b"[Content_Types].xmlxl/workbook.bin",
    ),
    (
        "example.pptx",
        64,
        bytes([0x50, 0x4B, 0x03, 0x04]),
        [],
        b"[Content_Types].xmlppt/presentation.xml",
    ),
    # --- images ---
    (
        "example.png",
        64,
        bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
        [],
        None,
    ),
    ("example.jpg", 64, bytes([0xFF, 0xD8, 0xFF, 0xE0]), [], None),
    ("example.gif", 64, bytes([0x47, 0x49, 0x46, 0x38, 0x39, 0x61]), [], None),
    ("example.bmp", 64, bytes([0x42, 0x4D]), [], None),
    (
        "example.webp",
        64,
        bytes([0x52, 0x49, 0x46, 0x46]),
        [(8, bytes([0x57, 0x45, 0x42, 0x50]))],
        None,
    ),
    ("example.tiff", 64, bytes([0x49, 0x49, 0x2A, 0x00]), [], None),
    # --- audio ---
    (
        "example.wav",
        64,
        bytes([0x52, 0x49, 0x46, 0x46]),
        [(8, bytes([0x57, 0x41, 0x56, 0x45]))],
        None,
    ),
    ("example.flac", 64, bytes([0x66, 0x4C, 0x61, 0x43]), [], None),
    ("example.ogg", 64, bytes([0x4F, 0x67, 0x67, 0x53]), [], None),
    (
        "example_id3.mp3",
        64,
        bytes([0x49, 0x44, 0x33, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        [],
        None,
    ),
    # check_mp3's frame-sync fallback now requires two consecutive, valid
    # frame headers (see #34) -- this header (MPEG1 Layer III, 32kbps,
    # 44100Hz, no padding: 0xFF 0xFB 0x10 0x00) computes a 104-byte frame
    # size, so a second identical header is poked in at that exact offset.
    (
        "example_raw.mp3",
        128,
        bytes([0xFF, 0xFB, 0x10, 0x00]),
        [(104, bytes([0xFF, 0xFB, 0x10, 0x00]))],
        None,
    ),
    # --- video ---
    (
        "example.mp4",
        64,
        bytes(
            [0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6F, 0x6D]
        ),
        [],
        None,
    ),
    ("example.webm", 64, bytes([0x1A, 0x45, 0xDF, 0xA3]), [], None),
    (
        "example.avi",
        64,
        bytes([0x52, 0x49, 0x46, 0x46]),
        [(8, bytes([0x41, 0x56, 0x49, 0x20]))],
        None,
    ),
]


def build_fixture_bytes(
    min_size: int, initial: bytes, pokes: list[tuple[int, bytes]], prefix: int
) -> bytearray:
    data = bytearray(b"\x90" * prefix) if prefix else bytearray()
    data.extend(initial)
    target = min_size + prefix
    if len(data) < target:
        data.extend(b"\x00" * (target - len(data)))
    for offset, poke_bytes in pokes:
        absolute = offset + prefix
        data[absolute : absolute + len(poke_bytes)] = poke_bytes
    return data


def generate_format_fixtures(mode: str) -> list[Path]:
    prefix = 192 if mode == "shifted" else 0
    tag = "shifted_example" if mode == "shifted" else "example"
    paths = []
    for name, min_size, initial, pokes, append in FORMAT_FIXTURES:
        out_name = name.replace("example", tag, 1)
        data = build_fixture_bytes(min_size, initial, pokes, prefix)
        if append:
            data.extend(append)
        out_path = RESOURCES_DIR / out_name
        out_path.write_bytes(data)
        paths.append(out_path)
    return paths


def phase_format_detection(mode: str, bin_path: Path) -> bool:
    header(f"Phase 1: format detection -- {mode} mode")
    RESOURCES_DIR.mkdir(exist_ok=True)
    paths = generate_format_fixtures(mode)
    tally = Tally(f"format detection ({mode})")

    for path in sorted(paths):
        result = run([str(bin_path), str(path)])
        stdout = result.stdout
        # A content-scan Error (e.g. OCR failing to decode a fixture that's
        # only a magic-byte stub, not a real image) is a separate concern
        # from format *detection* -- this phase only cares whether
        # identify_real_filetype resolved a real type, so that kind of
        # error is noted but doesn't fail the check on its own.
        error_line = next(
            (line for line in stdout.splitlines() if line.startswith("Error:")), None
        )
        # Any "Error:" line prints *before* the final Display line, not as
        # part of it (scan() prints its own Error, then main.rs prints the
        # Display line after scan() returns) -- skip those before treating
        # the next line as the Display output's real first line.
        display_output = extract_display_output(stdout)
        display_lines = [
            line for line in display_output.splitlines() if not line.startswith("Error:")
        ]
        first_line = display_lines[0] if display_lines else ""
        file_type = first_line.split(" (", 1)[0].strip().lower()

        if result.returncode != 0:
            tally.record(False, path.name, f"exit code {result.returncode}")
        elif file_type == "unknown" or not file_type:
            tally.record(False, path.name, f"detected: {first_line}")
        elif error_line:
            tally.record(True, path.name, f"detected: {file_type} (content-scan note: {error_line})")
        else:
            tally.record(True, path.name, f"detected: {file_type}")

    return tally.summary()


# --- Phase 2: YARA rule fixtures ------------------------------------------

YARA_OVERRIDES = {
    "elf_reverse_shell.txt": "elf_reverse_shell_strings",
    "script_lolbin_certutil.txt": "script_lolbin_download_execute",
}


def phase_yara_examples(yara_bin_path: Path) -> bool:
    header("Phase 2: YARA rule fixtures")
    if not YARA_EXAMPLES_DIR.is_dir():
        print(f"skipping: {YARA_EXAMPLES_DIR} not present locally")
        return True

    tally = Tally("YARA rule fixtures")
    for fixture in sorted(YARA_EXAMPLES_DIR.iterdir()):
        base = fixture.stem
        expected = YARA_OVERRIDES.get(fixture.name, base)
        # Run from REPO_ROOT -- build_yara_rules() reads the "rules"
        # directory relative to the process's cwd, not the fixture's path.
        result = run([str(yara_bin_path), str(fixture)], cwd=REPO_ROOT)
        matches = [line for line in result.stdout.splitlines() if line.strip()]
        ok = expected in matches
        tally.record(ok, fixture.name, f"expected={expected} matched={matches}")

    return tally.summary()


# --- Phase 3: strike3 word list --------------------------------------------


def slugify(term: str) -> str:
    slug_chars = [c.lower() if c.isalnum() else "_" for c in term]
    slug = "".join(slug_chars)
    while "__" in slug:
        slug = slug.replace("__", "_")
    return slug.strip("_")


def generate_strike3_images(terms: list[str]) -> list[tuple[str, Path]]:
    STRIKE3_DIR.mkdir(exist_ok=True)
    font = ImageFont.truetype(FONT_PATH, 90)
    out = []
    for term in terms:
        slug = slugify(term)
        image = Image.new("RGB", (900, 300), "black")
        draw = ImageDraw.Draw(image)
        text = term.upper()
        bbox = draw.textbbox((0, 0), text, font=font)
        text_w, text_h = bbox[2] - bbox[0], bbox[3] - bbox[1]
        position = ((900 - text_w) / 2 - bbox[0], (300 - text_h) / 2 - bbox[1])
        draw.text(position, text, font=font, fill="white")
        path = STRIKE3_DIR / f"{slug}.png"
        image.save(path)
        out.append((term, path))
    return out


def load_strike3_terms() -> list[str]:
    """Reads STRIKE3_IP directly out of src/consts.rs -- the single source
    of truth for the blocklist -- rather than a separate wordlist file,
    which already drifted out of sync with it once (consts.rs gained
    "blacked" and "deeper" that a standalone list never picked up)."""
    text = CONSTS_RS.read_text()
    match = re.search(r"STRIKE3_IP:\s*&\[&str\]\s*=\s*&\[(.*?)\];", text, re.DOTALL)
    if not match:
        raise RuntimeError(f"could not find STRIKE3_IP in {CONSTS_RS}")
    return re.findall(r'"([^"]*)"', match.group(1))


def phase_strike3(bin_path: Path) -> bool:
    header("Phase 3: strike3 word list")
    terms = load_strike3_terms()
    if not terms:
        print(f"skipping: no terms found in {CONSTS_RS}'s STRIKE3_IP")
        return True

    fixtures = generate_strike3_images(terms)

    ocr_tally = Tally("strike3 OCR readability")
    for term, path in fixtures:
        result = run(["tesseract", str(path), "stdout"])
        extracted = " ".join(result.stdout.lower().split())
        ocr_tally.record(extracted == term.lower(), path.name, f"got \"{extracted}\"")
    ocr_ok = ocr_tally.summary()

    detect_tally = Tally("strike3 detection (erratas)")
    for term, path in fixtures:
        result = run([str(bin_path), str(path)])
        display_output = extract_display_output(result.stdout)
        strike3_field = (
            display_output.split("strike3:", 1)[-1].strip()
            if "strike3:" in display_output
            else ""
        )
        detect_tally.record(bool(strike3_field), path.name, f"strike3=\"{strike3_field}\"")
    detect_ok = detect_tally.summary()

    return ocr_ok and detect_ok


# --- Phase 4: server mode --------------------------------------------------

# Mirrors src/server.rs's MAX_UPLOAD -- anything above this must be refused.
SERVER_MAX_UPLOAD = 100 * 1024 * 1024
SERVER_HOST = "127.0.0.1"

# Per-request socket timeout. Generous because the server compiles the
# YARA rules on its first scan.
SERVER_TIMEOUT = 60


def free_port() -> int:
    """Asks the OS for a free port. Tiny window where something else could
    grab it before the server binds, but fine for a test run."""
    with socket.socket() as s:
        s.bind((SERVER_HOST, 0))
        return s.getsockname()[1]


def wait_for_server(port: int, proc: subprocess.Popen, deadline_s: float = 10) -> bool:
    """Polls until the server accepts a connection, or gives up. Bails out
    early if the process already died (e.g. the port was taken)."""
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            # Connect-and-close counts as a client that sent nothing; the
            # server just logs an EOF error for it and keeps going.
            with socket.create_connection((SERVER_HOST, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def recv_all(sock: socket.socket) -> bytes:
    """Reads until the server closes the connection -- it closes after
    every reply, so that's where a response ends."""
    chunks = []
    while chunk := sock.recv(65536):
        chunks.append(chunk)
    return b"".join(chunks)


def server_upload(port: int, body: bytes) -> str:
    """Sends one well-formed upload: 8-byte big-endian length, then the
    bytes. Returns the server's full reply as text."""
    with socket.create_connection((SERVER_HOST, port), timeout=SERVER_TIMEOUT) as sock:
        sock.sendall(struct.pack(">Q", len(body)) + body)
        return recv_all(sock).decode("utf-8", errors="replace")


def parse_upload_reply(reply: str, expected_len: int) -> tuple[str | None, dict | None, str]:
    """Splits a reply into (saved path, parsed scan JSON, problem). Problem
    is "" when both lines look right."""
    lines = reply.splitlines()
    if not lines:
        return None, None, "empty reply"

    # Line 1: "OK <n> bytes saved to <path>"
    ok_prefix = f"OK {expected_len} bytes saved to "
    if not lines[0].startswith(ok_prefix):
        return None, None, f"bad ack line: {lines[0]!r}"
    saved = lines[0][len(ok_prefix):].strip()

    # Line 2: the scan result, which must be plain JSON.
    if len(lines) < 2:
        return saved, None, "no scan result line"
    try:
        return saved, json.loads(lines[1]), ""
    except json.JSONDecodeError as e:
        return saved, None, f"scan line isn't JSON ({e}): {lines[1][:120]!r}"


def remove_upload(saved: str | None) -> None:
    """Server saves relative to its cwd (REPO_ROOT), so resolve from there."""
    if saved:
        (REPO_ROOT / saved).unlink(missing_ok=True)


def phase_server(bin_path: Path) -> bool:
    header("Phase 4: server mode (erratas host)")
    tally = Tally("server mode")
    port = free_port()

    # Snapshot existing uploads so the leftover check at the end only
    # flags files *this* run created.
    uploads_before = set(REPO_ROOT.glob("upload-*.bin"))

    # stdout/stderr go to a temp file, not a pipe: the server prints on
    # every scan, and a pipe nobody reads fills up and stalls it. cwd is
    # REPO_ROOT because build_yara_rules() loads "rules/" relative to it.
    log = tempfile.TemporaryFile(mode="w+")
    proc = subprocess.Popen(
        [str(bin_path), "host", SERVER_HOST, str(port)],
        cwd=REPO_ROOT,
        stdout=log,
        stderr=subprocess.STDOUT,
    )

    try:
        if not wait_for_server(port, proc):
            log.seek(0)
            tally.record(False, "server start", f"not listening on {port}\n{log.read()[-2000:]}")
            return tally.summary()
        tally.record(True, "server start", f"listening on {SERVER_HOST}:{port}")

        # --- every format fixture, over the wire ---
        # Same fixtures Phase 1 uses via the CLI; here the check is that
        # the JSON result reports a real type, not "Unknown".
        for path in sorted(generate_format_fixtures("normal")):
            body = path.read_bytes()
            try:
                saved, result, problem = parse_upload_reply(server_upload(port, body), len(body))
            except OSError as e:
                tally.record(False, f"upload {path.name}", f"socket error: {e}")
                continue
            remove_upload(saved)

            if problem:
                tally.record(False, f"upload {path.name}", problem)
                continue
            file_types = result.get("file_info", {}).get("file_type", [])
            detected = [t for t in file_types if t != "Unknown"]
            tally.record(bool(detected), f"upload {path.name}", f"file_type={file_types}")

        # --- content scan runs server-side too ---
        # One strike3 image is enough to prove OCR + blocklist fire
        # through the server path; Phase 3 covers the full list.
        terms = load_strike3_terms()
        if terms:
            [(term, img)] = generate_strike3_images(terms[:1])
            body = img.read_bytes()
            try:
                saved, result, problem = parse_upload_reply(server_upload(port, body), len(body))
                remove_upload(saved)
                strike3 = (result or {}).get("file_info", {}).get("strike3", [])
                tally.record(not problem and bool(strike3), f"strike3 via server ({term})",
                             problem or f"strike3={strike3}")
            except OSError as e:
                tally.record(False, f"strike3 via server ({term})", f"socket error: {e}")

        # --- oversized upload refused from the header alone ---
        # No body is sent: a reply at all proves the server didn't wait on one.
        try:
            with socket.create_connection((SERVER_HOST, port), timeout=SERVER_TIMEOUT) as sock:
                sock.sendall(struct.pack(">Q", SERVER_MAX_UPLOAD + 1))
                reply = recv_all(sock).decode()
            tally.record(reply == "ERR too large\n", "oversized upload rejected", repr(reply))
        except OSError as e:
            tally.record(False, "oversized upload rejected", f"socket error: {e}")

        # --- cut-short upload gets no ack ---
        # Promise 100 bytes, send 10, close our write side.
        try:
            with socket.create_connection((SERVER_HOST, port), timeout=SERVER_TIMEOUT) as sock:
                sock.sendall(struct.pack(">Q", 100) + b"\xab" * 10)
                sock.shutdown(socket.SHUT_WR)
                reply = recv_all(sock)
            tally.record(reply == b"", "cut-short upload gets no ack", repr(reply[:80]))
        except OSError as e:
            tally.record(False, "cut-short upload gets no ack", f"socket error: {e}")

        # --- server still alive after the bad clients above ---
        body = b"still alive?"
        try:
            saved, _, problem = parse_upload_reply(server_upload(port, body), len(body))
            remove_upload(saved)
            tally.record(not problem and proc.poll() is None, "server survives bad clients", problem)
        except OSError as e:
            tally.record(False, "server survives bad clients", f"socket error: {e}")

        # --- overlapping uploads ---
        # Different sizes per client so a mixed-up reply would show up as
        # a wrong byte count in the ack line.
        bodies = [bytes([0x41 + i]) * (512 * (i + 1)) for i in range(4)]
        with ThreadPoolExecutor(max_workers=len(bodies)) as pool:
            replies = list(pool.map(lambda b: server_upload(port, b), bodies))

        saved_paths = []
        concurrent_problems = []
        for body, reply in zip(bodies, replies):
            saved, _, problem = parse_upload_reply(reply, len(body))
            saved_paths.append(saved)
            remove_upload(saved)
            if problem:
                concurrent_problems.append(problem)

        # Distinct paths -> no two uploads landed on the same file.
        if len(set(saved_paths)) != len(bodies):
            concurrent_problems.append(f"paths not unique: {saved_paths}")
        tally.record(not concurrent_problems, f"{len(bodies)} overlapping uploads",
                     "; ".join(concurrent_problems))

        # --- nothing left on disk ---
        # Everything this phase knew about was removed above, so anything
        # new here is a file the server itself should have cleaned up
        # (e.g. the cut-short upload).
        leftovers = set(REPO_ROOT.glob("upload-*.bin")) - uploads_before
        for leftover in leftovers:
            leftover.unlink(missing_ok=True)
        tally.record(not leftovers, "no leftover upload files",
                     ", ".join(p.name for p in sorted(leftovers)))

    finally:
        # Server loops forever; stop it whatever happened above.
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()

    return tally.summary()


# --- main ------------------------------------------------------------------


def main() -> int:
    results: dict[str, bool] = {}

    results["cargo test"] = phase_cargo_test()

    print("\nBuilding erratas + yara_scan_file example ...")
    build = run(["cargo", "build", "--quiet"])
    if build.returncode != 0:
        print(f"{RED}cargo build failed:{RESET}\n{build.stderr}")
        return 1
    build_example = run(["cargo", "build", "--quiet", "--example", "yara_scan_file"])
    if build_example.returncode != 0:
        print(f"{RED}cargo build --example yara_scan_file failed:{RESET}\n{build_example.stderr}")
        return 1

    bin_path = REPO_ROOT / "target" / "debug" / "erratas"
    yara_bin_path = REPO_ROOT / "target" / "debug" / "examples" / "yara_scan_file"

    results["format detection (normal)"] = phase_format_detection("normal", bin_path)
    results["format detection (shifted)"] = phase_format_detection("shifted", bin_path)
    results["YARA fixtures"] = phase_yara_examples(yara_bin_path)
    results["strike3"] = phase_strike3(bin_path)
    results["server mode"] = phase_server(bin_path)

    header("Overall summary")
    all_ok = True
    for name, ok in results.items():
        color = GREEN if ok else RED
        print(f"{color}{'PASS' if ok else 'FAIL'}{RESET}  {name}")
        all_ok = all_ok and ok

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
