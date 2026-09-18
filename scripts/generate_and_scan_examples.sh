#!/usr/bin/env bash
# Generates one small synthetic example file per format identify_type()
# knows how to detect, drops them in resources/, builds the project, then
# runs the erratas binary against each one so you can eyeball the
# detected type/subtype for every format at a glance.
#
# These are minimal byte-pattern stubs (same idea as the resources/test_*
# fixtures already in the repo) -- just enough to trip each check_*
# function, not real openable documents/media/executables.
#
# Usage: ./generate_and_scan_examples.sh [normal|shifted]
#   normal  (default) -- magic bytes at their expected offset.
#   shifted            -- every format's magic bytes pushed back by a
#                          block of 0x90 filler, the same trick the
#                          hand-made resources/shifted_*/strange_offset.exe
#                          fixtures already use. This defeats each check_*
#                          function's fast, fixed-offset path and forces it
#                          onto its scan_for()/scan_for_at_offset() fallback
#                          -- formats with a working fallback still detect
#                          correctly (green), formats without one reveal
#                          themselves by going Unknown (red).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RESOURCES_DIR="$REPO_ROOT/resources"
mkdir -p "$RESOURCES_DIR"

MODE="${1:-normal}"
case "$MODE" in
    normal)
        FILE_TAG="example"
        PREFIX=0
        ;;
    shifted)
        FILE_TAG="shifted_example"
        PREFIX=192
        ;;
    *)
        echo "Usage: $0 [normal|shifted]" >&2
        exit 1
        ;;
esac
echo "Mode: $MODE (files tagged '$FILE_TAG', $PREFIX-byte prefix)"

# resource_file <path using the literal "example" prefix>
# Lets every write_padded/poke call below just say ".../example.foo"
# regardless of mode -- swaps in "shifted_example" instead when that mode
# is selected, so normal and shifted fixtures never collide on disk.
resource_file() {
    echo "${1/example/$FILE_TAG}"
}

# write_padded <file> <min_size> [byte byte ...]
# Writes the given hex bytes (space-separated, no "0x" prefix) to the
# start of a file, then zero-pads it out to at least <min_size> bytes.
# In "shifted" mode, leads with PREFIX bytes of 0x90 filler first, so the
# magic doesn't start at offset 0 -- this is what exercises each check_*'s
# scan_for fallback instead of its fast, fixed-offset check.
write_padded() {
    local file min_size
    file="$(resource_file "$1")"
    min_size="$2"
    shift 2
    : > "$file"
    if [ "$PREFIX" -gt 0 ]; then
        dd if=/dev/zero bs=1 count="$PREFIX" 2>/dev/null | tr '\0' '\220' >> "$file"
    fi
    for b in "$@"; do
        printf "\\x$b" >> "$file"
    done
    local size
    size=$(wc -c < "$file" | tr -d ' ')
    local target=$((min_size + PREFIX))
    if [ "$size" -lt "$target" ]; then
        dd if=/dev/zero bs=1 count=$((target - size)) >> "$file" 2>/dev/null
    fi
}

# poke <file> <offset> <byte byte ...>
# Overwrites bytes at the given offset in an existing file without
# truncating the rest of it -- used for magic bytes that don't sit at
# offset 0 (e.g. the "ftyp"/"WAVE"/"CD001" family). The offset shifts by
# the same PREFIX as write_padded, so a format's own internal layout
# (e.g. WAVE sitting 8 bytes after RIFF) stays intact either way.
poke() {
    local file offset
    file="$(resource_file "$1")"
    offset=$(( $2 + PREFIX ))
    shift 2
    local tmp
    tmp="$(mktemp)"
    for b in "$@"; do
        printf "\\x$b" >> "$tmp"
    done
    dd if="$tmp" of="$file" bs=1 seek="$offset" conv=notrunc 2>/dev/null
    rm -f "$tmp"
}

echo "Generating example files in $RESOURCES_DIR ..."

# --- executables ---------------------------------------------------------

write_padded "$RESOURCES_DIR/example.elf" 64 7f 45 4c 46

# Same ELF magic as example.elf, but with EI_DATA (offset 5) set to
# little-endian and e_type (offset 16-17) set to ET_DYN (3) -- what
# is_elf_shared_object looks at to tell a shared library apart from a
# regular executable.
write_padded "$RESOURCES_DIR/example.so" 64 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 03 00

# MZ at 0, "PE\0\0" literally at offset 0x3C (60) -- what check_winexe's
# fast path actually looks at.
write_padded "$RESOURCES_DIR/example.exe" 64 4d 5a
poke "$RESOURCES_DIR/example.exe" 60 50 45 00 00

# MZ at 0, e_lfanew (offset 0x3C) pointing to a real PE header at 0x80,
# with the IMAGE_FILE_DLL characteristic flag set -- this is what makes
# check_dll (rather than check_winexe) the one that classifies it.
write_padded "$RESOURCES_DIR/example.dll" 256 4d 5a
poke "$RESOURCES_DIR/example.dll" 60 80 00 00 00
poke "$RESOURCES_DIR/example.dll" 128 50 45 00 00
poke "$RESOURCES_DIR/example.dll" 132 64 86
poke "$RESOURCES_DIR/example.dll" 150 00 20

write_padded "$RESOURCES_DIR/example.lnk" 64 4c 00 00 00 01 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46

write_padded "$RESOURCES_DIR/example_macho32.bin" 64 fe ed fa ce
write_padded "$RESOURCES_DIR/example_macho64.bin" 64 fe ed fa cf
write_padded "$RESOURCES_DIR/example_macho_fat.bin" 64 ca fe ba be

# --- archives / disk images ----------------------------------------------

# "koly" UDIF trailer 512 bytes from the end of a 1024-byte file.
write_padded "$RESOURCES_DIR/example.dmg" 1024
poke "$RESOURCES_DIR/example.dmg" 512 6b 6f 6c 79

write_padded "$RESOURCES_DIR/example.zip" 64 50 4b 03 04
write_padded "$RESOURCES_DIR/example.rar" 64 52 61 72 21 1a 07
write_padded "$RESOURCES_DIR/example.7z" 64 37 7a bc af 27 1c
write_padded "$RESOURCES_DIR/example.cab" 64 4d 53 43 46

# "ustar" 257 bytes into a 512-byte record.
write_padded "$RESOURCES_DIR/example.tar" 512
poke "$RESOURCES_DIR/example.tar" 257 75 73 74 61 72

# "CD001" at byte offset 0x8001 (32769).
write_padded "$RESOURCES_DIR/example.iso" $((0x8001 + 8))
poke "$RESOURCES_DIR/example.iso" $((0x8001)) 43 44 30 30 31

# --- documents -------------------------------------------------------------

write_padded "$RESOURCES_DIR/example.pdf" 64 25 50 44 46 2d

# Legacy Office doc and an MSI installer -- same CFB magic, a real
# collision check_ole_cfb can't resolve any further on its own.
write_padded "$RESOURCES_DIR/example_legacy.doc" 64 d0 cf 11 e0 a1 b1 1a e1
write_padded "$RESOURCES_DIR/example_installer.msi" 64 d0 cf 11 e0 a1 b1 1a e1

write_padded "$RESOURCES_DIR/example.chm" 64 49 54 53 46

# Synthetic OOXML: a ZIP signature plus the literal "[Content_Types].xml"
# name check_ooxml scans for -- not a real, openable .docx.
write_padded "$RESOURCES_DIR/example.docx" 64 50 4b 03 04
printf '[Content_Types].xml' >> "$(resource_file "$RESOURCES_DIR/example.docx")"

# --- images ----------------------------------------------------------------

write_padded "$RESOURCES_DIR/example.png" 64 89 50 4e 47 0d 0a 1a 0a
write_padded "$RESOURCES_DIR/example.jpg" 64 ff d8 ff e0
write_padded "$RESOURCES_DIR/example.gif" 64 47 49 46 38 39 61
write_padded "$RESOURCES_DIR/example.bmp" 64 42 4d

write_padded "$RESOURCES_DIR/example.webp" 64 52 49 46 46
poke "$RESOURCES_DIR/example.webp" 8 57 45 42 50

# --- audio -------------------------------------------------------------

write_padded "$RESOURCES_DIR/example.wav" 64 52 49 46 46
poke "$RESOURCES_DIR/example.wav" 8 57 41 56 45

write_padded "$RESOURCES_DIR/example.flac" 64 66 4c 61 43
write_padded "$RESOURCES_DIR/example.ogg" 64 4f 67 67 53
write_padded "$RESOURCES_DIR/example_id3.mp3" 64 49 44 33 04 00 00 00 00 00 00
write_padded "$RESOURCES_DIR/example_raw.mp3" 64 ff fb 90 00

# --- video -------------------------------------------------------------

write_padded "$RESOURCES_DIR/example.mp4" 64 00 00 00 18 66 74 79 70 69 73 6f 6d
write_padded "$RESOURCES_DIR/example.webm" 64 1a 45 df a3
write_padded "$RESOURCES_DIR/example.avi" 64 52 49 46 46
poke "$RESOURCES_DIR/example.avi" 8 41 56 49 20

echo "Done generating examples."
echo

echo "Building erratas ..."
(cd "$REPO_ROOT" && cargo build --quiet)
BIN="$REPO_ROOT/target/debug/erratas"

echo
echo "Running each example through erratas:"
echo

GREEN='\033[0;32m'
RED='\033[0;31m'
RESET='\033[0m'

for f in "$RESOURCES_DIR/$FILE_TAG"*; do
    echo "== $(basename "$f") =="
    output="$("$BIN" "$f")"

    # "Worked" means a real type came back with no error line -- an Unknown
    # result (e.g. "Unknown (Unknown(Unknown))") or a printed "Error:" both
    # count as "didn't work".
    if echo "$output" | grep -qE "^Error:|^Detected type: Unknown \("; then
        color="$RED"
    else
        color="$GREEN"
    fi

    while IFS= read -r line; do
        printf "%b%s%b\n" "$color" "$line" "$RESET"
    done <<< "$(echo "$output" | grep -E "^(Detected type|Error|Scanning for)")"
    echo
done
