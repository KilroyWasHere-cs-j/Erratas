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
                                 term in strike3_ips.txt, verifies Tesseract
                                 reads each one back correctly, then runs
                                 erratas against each and checks the
                                 strike3 field in its output actually fired.

Each phase reports its own pass/fail tally; the script's exit code is
nonzero if anything, anywhere, failed.

Usage: python3 scripts/run_all_tests.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO_ROOT = Path(__file__).resolve().parent.parent
RESOURCES_DIR = REPO_ROOT / "resources"
YARA_EXAMPLES_DIR = RESOURCES_DIR / "yara_examples"
STRIKE3_DIR = REPO_ROOT / "strike3"
STRIKE3_WORDLIST = REPO_ROOT / "strike3_ips.txt"
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
    (
        "example.docx",
        64,
        bytes([0x50, 0x4B, 0x03, 0x04]),
        [],
        b"[Content_Types].xml",
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
    ("example_raw.mp3", 64, bytes([0xFF, 0xFB, 0x90, 0x00]), [], None),
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


def phase_strike3(bin_path: Path) -> bool:
    header("Phase 3: strike3 word list")
    if not STRIKE3_WORDLIST.exists():
        print(f"skipping: {STRIKE3_WORDLIST} not present")
        return True

    terms = [
        line.strip()
        for line in STRIKE3_WORDLIST.read_text().splitlines()
        if line.strip()
    ]
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

    header("Overall summary")
    all_ok = True
    for name, ok in results.items():
        color = GREEN if ok else RED
        print(f"{color}{'PASS' if ok else 'FAIL'}{RESET}  {name}")
        all_ok = all_ok and ok

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
