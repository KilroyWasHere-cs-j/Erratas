// TODO: Check the file's extension first, and only fall through to the
// magic-byte checks below if that doesn't resolve it.

use crate::error::ErratasError;
use crate::types::{ArchiveSubType, ErratasContentFlag, ErratasResult, ExecutableSubType, RealFileType, DocumentSubType, ImageSubType, AudioSubType, VideoSubType, UnknownSubType, RealFileSubType};

pub fn identify_type(contents: &[u8]) -> ErratasResult {
    match check_elf(contents) {
        RealFileType::LinuxExecutable => {
            let file_sub_type = if is_elf_shared_object(contents) {
                ExecutableSubType::SO
            } else {
                ExecutableSubType::ELF
            };
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::LinuxExecutable,
                file_sub_type: RealFileSubType::Executable(file_sub_type)
            }
        },
        _ => {}
    }

    match check_winexe(contents) {
        Ok(RealFileType::WinExecutable) => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::WinExecutable,
                file_sub_type: RealFileSubType::Executable(ExecutableSubType::PE)
            }
        },
        Ok(_) => {},
        Err(e) => {
            println!("Error: {e}");
        }
    }

    match check_dll(contents) {
        RealFileType::WinExecutable => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::WinExecutable,
                file_sub_type: RealFileSubType::Executable(ExecutableSubType::DLL)
            }
        },
        _ => {}
    }

    match check_lnk(contents) {
        RealFileType::WinExecutable => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::WinExecutable,
                file_sub_type: RealFileSubType::Executable(ExecutableSubType::LNK)
            }
        },
        _ => {}
    }

    match check_macho(contents) {
        RealFileType::MacExecutable => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::MacExecutable,
                file_sub_type: RealFileSubType::Executable(ExecutableSubType::MachO)
            }
        },
        _ => {}
    }

    match check_dmg(contents) {
        RealFileType::Archive => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Archive,
                file_sub_type: RealFileSubType::Archive(ArchiveSubType::DMG)
            }
        },
        _ => {}
    }

    // Must come before check_zip -- otherwise a .docx/.xlsx/.pptx would
    // already match as a plain Archive before we get a chance to notice
    // it's actually an OOXML document.
    match check_ooxml(contents) {
        RealFileType::Document => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Document,
                file_sub_type: RealFileSubType::Document(DocumentSubType::OOXML)
            }
        },
        _ => {}
    }

    match check_zip(contents) {
        RealFileType::Archive => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Archive,
                file_sub_type: RealFileSubType::Archive(ArchiveSubType::ZIP)
            }
        },
        _ => {}
    }

    match check_rar(contents) {
        RealFileType::Archive => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Archive,
                file_sub_type: RealFileSubType::Archive(ArchiveSubType::RAR)
            }
        },
        _ => {}
    }
    match check_7z(contents) {
        RealFileType::Archive => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Archive,
                file_sub_type: RealFileSubType::Archive(ArchiveSubType::SEVENZ)
            } 
        },
        _ => {}
    }

    match check_cab(contents) {
        RealFileType::Archive => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Archive,
                file_sub_type: RealFileSubType::Archive(ArchiveSubType::CAB)
            }
        },
        _ => {}
    }

    match check_tar(contents) {
        RealFileType::Archive => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Archive,
                file_sub_type: RealFileSubType::Archive(ArchiveSubType::TAR)
            }
        },
        _ => {}
    }

    match check_iso(contents) {
        RealFileType::Archive => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Archive,
                file_sub_type: RealFileSubType::Archive(ArchiveSubType::ISO)
            }
        },
        RealFileType::WinExecutable => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::WinExecutable,
                file_sub_type: RealFileSubType::Executable(ExecutableSubType::PE)
            }
        },
        _ => {}
    }

    match check_pdf(contents) {
        RealFileType::Document => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Document,
                file_sub_type: RealFileSubType::Document(DocumentSubType::PDF)
            }
        },
        _ => {}
    }

    match check_ole_cfb(contents) {
        RealFileType::Document => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Document,
                file_sub_type: RealFileSubType::Document(DocumentSubType::OLECFB)
            }
        },
        _ => {}
    }

    match check_chm(contents) {
        RealFileType::Document => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Document,
                file_sub_type: RealFileSubType::Document(DocumentSubType::CHM)
            }
        },
        _ => {}
    }

    match check_png(contents) {
        RealFileType::Image => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Image,
                file_sub_type: RealFileSubType::Image(ImageSubType::PNG)
            }
        },
        _ => {}
    }
    match check_jpeg(contents) {
        RealFileType::Image => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Image,
                file_sub_type: RealFileSubType::Image(ImageSubType::JPEG)
            }
        },
        _ => {}
    }
    match check_gif(contents) {
        RealFileType::Image => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Image,
                file_sub_type: RealFileSubType::Image(ImageSubType::GIF)
            }
        },
        _ => {}
    }
    match check_bmp(contents) {
        RealFileType::Image => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Image,
                file_sub_type: RealFileSubType::Image(ImageSubType::BMP)
            }
        },
        _ => {}
    }
    match check_webp(contents) {
        RealFileType::Image => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Image,
                file_sub_type: RealFileSubType::Image(ImageSubType::WEBP)
            }
        },
        _ => {}
    }

    match check_wav(contents) {
        RealFileType::Audio => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Audio,
                file_sub_type: RealFileSubType::Audio(AudioSubType::WAV)
            }
        },
        _ => {}
    }
    match check_flac(contents) {
        RealFileType::Audio => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Audio,
                file_sub_type: RealFileSubType::Audio(AudioSubType::FLAC)
            }
        },
        _ => {}
    }
    match check_ogg(contents) {
        RealFileType::Audio => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Audio,
                file_sub_type: RealFileSubType::Audio(AudioSubType::OGG)
            }
        },
        _ => {}
    }
    match check_mp3(contents) {
        RealFileType::Audio => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Audio,
                file_sub_type: RealFileSubType::Audio(AudioSubType::MP3)
            }
        },
        _ => {}
    }

    match check_mp4(contents) {
        RealFileType::Video => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Video,
                file_sub_type: RealFileSubType::Video(VideoSubType::MP4)
            }
        },
        _ => {}
    }
    match check_webm(contents) {
        RealFileType::Video => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Video,
                file_sub_type: RealFileSubType::Video(VideoSubType::WEBM)
            }
        },
        _ => {}
    }
    match check_avi(contents) {
        RealFileType::Video => {
            return ErratasResult {
                flags: vec![ErratasContentFlag::BandedFileType],
                file_type: RealFileType::Video,
                file_sub_type: RealFileSubType::Video(VideoSubType::AVI)
            }
        },
        _ => {}
    }

    return ErratasResult {
        flags: vec![ErratasContentFlag::Unknown],
        file_type: RealFileType::Unknown,
        file_sub_type: RealFileSubType::Unknown(UnknownSubType::Unknown)
    };
}

fn check_elf(contents: &[u8]) -> RealFileType {
    if contents[0] == 0x7F && contents[1] == 0x45 && contents[2] == 0x4C && contents[3] == 0x46 {
        return RealFileType::LinuxExecutable;
    }
    return RealFileType::Unknown;
}

// e_type (offset 16, 2 bytes) tells ELF binaries and shared objects apart --
// ET_DYN (3) is a .so, ET_EXEC (2) is a regular executable. Byte order for
// that field follows EI_DATA at offset 5 (1 = little-endian, 2 = big-endian),
// since ELF (unlike PE) isn't always little-endian.
const ET_DYN: u16 = 3;

fn is_elf_shared_object(contents: &[u8]) -> bool {
    if contents.len() < 18 {
        return false;
    }
    let e_type = match contents[5] {
        2 => u16::from_be_bytes([contents[16], contents[17]]),
        _ => u16::from_le_bytes([contents[16], contents[17]]),
    };
    e_type == ET_DYN
}

// Fallback scanner for when a format's magic bytes aren't where they're
// normally expected -- a crafted or carved file (a payload appended after
// other data, junk prepended to dodge a fixed-offset check, the same
// trick strange_offset.exe demonstrates for PE) can still be caught this
// way. The cost is scanning the whole file, and a real risk of false
// positives on short patterns that occur by chance elsewhere in the
// bytes -- the same tradeoff check_winexe already makes for its own MZ/PE
// fallback loops. Only runs when the fast primary check already missed,
// so a normal well-formed file never pays for it.
fn scan_for(contents: &[u8], pattern: &[u8]) -> bool {
    if pattern.is_empty() || contents.len() < pattern.len() {
        return false;
    }
    for i in 0..=(contents.len() - pattern.len()) {
        if &contents[i..i + pattern.len()] == pattern {
            return true;
        }
    }
    false
}

// Same idea, for RIFF-style container formats where the real signature is
// a fixed number of bytes after an anchor tag rather than at one fixed
// spot -- finds `anchor` anywhere, then checks whether `tag` sits `gap`
// bytes after wherever it was found.
fn scan_for_at_offset(contents: &[u8], anchor: &[u8], gap: usize, tag: &[u8]) -> bool {
    if anchor.is_empty() || contents.len() < anchor.len() {
        return false;
    }
    for i in 0..=(contents.len() - anchor.len()) {
        if &contents[i..i + anchor.len()] == anchor {
            let tag_start = i + gap;
            if contents.len() >= tag_start + tag.len() && &contents[tag_start..tag_start + tag.len()] == tag {
                return true;
            }
        }
    }
    false
}

const MACHO_MAGICS: [[u8; 4]; 6] = [
    [0xFE, 0xED, 0xFA, 0xCE], [0xCE, 0xFA, 0xED, 0xFE],
    [0xFE, 0xED, 0xFA, 0xCF], [0xCF, 0xFA, 0xED, 0xFE],
    [0xCA, 0xFE, 0xBA, 0xBE], [0xBE, 0xBA, 0xFE, 0xCA],
];

fn check_macho(contents: &[u8]) -> RealFileType {
    if contents.len() >= 4 {
        match [contents[0], contents[1], contents[2], contents[3]] {
            // 32-bit Mach-O, either byte order.
            [0xFE, 0xED, 0xFA, 0xCE] | [0xCE, 0xFA, 0xED, 0xFE] => return RealFileType::MacExecutable,
            // 64-bit Mach-O, either byte order.
            [0xFE, 0xED, 0xFA, 0xCF] | [0xCF, 0xFA, 0xED, 0xFE] => return RealFileType::MacExecutable,
            // Fat/universal binary. Same magic number as a Java .class file --
            // a real collision, not a bug. Telling them apart needs more than
            // just these 4 bytes.
            [0xCA, 0xFE, 0xBA, 0xBE] | [0xBE, 0xBA, 0xFE, 0xCA] => return RealFileType::MacExecutable,
            _ => {}
        }
    }
    for magic in MACHO_MAGICS.iter() {
        if scan_for(contents, magic) {
            return RealFileType::MacExecutable;
        }
    }
    RealFileType::Unknown
}

fn check_winexe(contents: &[u8]) -> Result<RealFileType, ErratasError> {
    let mut pe = false;
    let mut mz = false;

    // A normal executable has a MZ firstly so if it's there we done.
    if contents[0] == 0x4D && contents[1] == 0x5A {
        println!("MZ");
        mz = true;
    }

    if contents[0x3C] == 0x50 && contents[0x3C + 1] == 0x45 && contents[0x3C + 2] == 0x00 && contents[0x3C + 3] == 0x00 {
        println!("PE");
        pe = true;
    }

    if mz && pe {
        return Ok(RealFileType::WinExecutable);
    }
    else {
        pe = false;
        mz = false;
    }
    
    for i in 0..contents.len() - 1 {
        if contents[i] == 0x4D && contents[i + 1] == 0x5A {
            mz = true;
            break;
        }
    }
    for i in 0..contents.len() - 1 {
        if contents[i] == 0x50 && contents[i + 1] == 0x45 && contents[i + 2] == 0x00 && contents[i + 3] == 0x00 {
            pe = true;
            break;
        }
    }

    if mz && pe {
        return Ok(RealFileType::WinExecutable);
    }
    return Ok(RealFileType::Unknown);
}

fn check_dmg(contents: &[u8]) -> RealFileType {
    // DMG has no signature at the front -- the real marker is the "koly"
    // UDIF trailer block, which normally sits in the last 512 bytes.
    if contents.len() >= 512 {
        let t = contents.len() - 512;
        if contents[t] == 0x6B && contents[t + 1] == 0x6F && contents[t + 2] == 0x6C && contents[t + 3] == 0x79 {
            return RealFileType::Archive;
        }
    }
    // Extra data appended past the real trailer would hide it from the
    // check above -- fall back to a full scan for "koly" anywhere.
    if scan_for(contents, b"koly") {
        return RealFileType::Archive;
    }
    return RealFileType::Unknown;
}

fn check_ooxml(contents: &[u8]) -> RealFileType {
    // .docx/.xlsx/.pptx (Office Open XML) are ZIP archives internally, so
    // a plain PK signature alone can't tell one apart from a generic
    // .zip. Every OOXML package does, however, always carry an entry
    // named "[Content_Types].xml" -- checking for that name's bytes
    // alongside the ZIP signature recognizes the family without fully
    // parsing the archive's central directory. This still can't tell
    // Word from Excel from PowerPoint specifically; that would mean
    // looking for "word/document.xml" vs "xl/workbook.xml" vs
    // "ppt/presentation.xml" instead. Must run before check_zip in
    // identify_type, or these would already have matched as a plain
    // Archive by then.
    let is_zip = scan_for(contents, &[0x50, 0x4B, 0x03, 0x04]);
    let is_ooxml = scan_for(contents, b"[Content_Types].xml");
    if is_zip && is_ooxml {
        return RealFileType::Document;
    }
    RealFileType::Unknown
}

fn check_zip(contents: &[u8]) -> RealFileType {
    if contents.len() >= 4 {
        // Local file header.
        if contents[0] == 0x50 && contents[1] == 0x4B && contents[2] == 0x03 && contents[3] == 0x04 {
            return RealFileType::Archive;
        }
        // End-of-central-directory marker (an empty archive has only this).
        if contents[0] == 0x50 && contents[1] == 0x4B && contents[2] == 0x05 && contents[3] == 0x06 {
            return RealFileType::Archive;
        }
    }
    // A polyglot/dropper file (self-extracting installer, JAR, APK) has
    // real zip data starting well past offset 0 -- scan for it.
    if scan_for(contents, &[0x50, 0x4B, 0x03, 0x04]) || scan_for(contents, &[0x50, 0x4B, 0x05, 0x06]) {
        return RealFileType::Archive;
    }
    return RealFileType::Unknown;
}

fn check_rar(contents: &[u8]) -> RealFileType {
    // RAR 1.5-4.x and RAR5 share this 6-byte prefix.
    let sig = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07];
    if contents.len() >= 6 && contents[0] == sig[0] && contents[1] == sig[1] && contents[2] == sig[2] && contents[3] == sig[3] && contents[4] == sig[4] && contents[5] == sig[5] {
        return RealFileType::Archive;
    }
    if scan_for(contents, &sig) {
        return RealFileType::Archive;
    }
    return RealFileType::Unknown;
}

fn check_7z(contents: &[u8]) -> RealFileType {
    let sig = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
    if contents.len() >= 6 && contents[0] == sig[0] && contents[1] == sig[1] && contents[2] == sig[2] && contents[3] == sig[3] && contents[4] == sig[4] && contents[5] == sig[5] {
        return RealFileType::Archive;
    }
    if scan_for(contents, &sig) {
        return RealFileType::Archive;
    }
    return RealFileType::Unknown;
}

fn check_cab(contents: &[u8]) -> RealFileType {
    // Microsoft Cabinet format, used by installers/updates -- "MSCF" magic.
    if contents.len() >= 4 && contents[0] == b'M' && contents[1] == b'S' && contents[2] == b'C' && contents[3] == b'F' {
        return RealFileType::Archive;
    }
    if scan_for(contents, b"MSCF") {
        return RealFileType::Archive;
    }
    return RealFileType::Unknown;
}

fn check_tar(contents: &[u8]) -> RealFileType {
    // Unlike the others, tar has no signature at offset 0. The "ustar"
    // magic sits 257 bytes into the header in the POSIX variant -- old-style
    // tar has no magic at all and can't be detected this way.
    let o = 257;
    if contents.len() >= o + 5 && contents[o] == b'u' && contents[o + 1] == b's' && contents[o + 2] == b't' && contents[o + 3] == b'a' && contents[o + 4] == b'r' {
        return RealFileType::Archive;
    }
    // A tar embedded/carved inside other data shifts this whole offset --
    // fall back to a plain scan for "ustar" anywhere.
    if scan_for(contents, b"ustar") {
        return RealFileType::Archive;
    }
    return RealFileType::Unknown;
}

fn check_iso(contents: &[u8]) -> RealFileType {
    // ISO 9660's "CD001" signature sits at byte offset 0x8001, inside the
    // Primary Volume Descriptor (logical sector 16, 2048 bytes/sector).
    let o = 0x8001;
    if contents.len() >= o + 5 && contents[o] == b'C' && contents[o + 1] == b'D' && contents[o + 2] == b'0' && contents[o + 3] == b'0' && contents[o + 4] == b'1' {
        return RealFileType::Archive;
    }
    // A hybrid/appended ISO can shift this offset too -- fall back to a
    // plain scan for "CD001" anywhere.
    if scan_for(contents, b"CD001") {
        return RealFileType::Archive;
    }
    return RealFileType::Unknown;
}

fn check_pdf(contents: &[u8]) -> RealFileType {
    if contents.len() >= 5 && contents[0] == b'%' && contents[1] == b'P' && contents[2] == b'D' && contents[3] == b'F' && contents[4] == b'-' {
        return RealFileType::Document;
    }
    // Real PDF readers already tolerate junk before "%PDF-" -- a payload
    // could exploit that same leniency to dodge a fixed-offset check.
    if scan_for(contents, b"%PDF-") {
        return RealFileType::Document;
    }
    return RealFileType::Unknown;
}

fn check_ole_cfb(contents: &[u8]) -> RealFileType {
    // Legacy (pre-2007) Office formats (.doc/.xls/.ppt) all use this same
    // Compound File Binary container -- and so do non-Office Microsoft
    // formats like .msi installers and .msg Outlook messages. This magic
    // number alone can't tell any of those apart, the same kind of
    // ambiguity as check_macho's fat-binary/Java-class collision -- doing
    // that would mean parsing the CFB directory structure for the
    // specific stream names each format actually stores.
    let sig = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    if contents.len() >= 8 && contents[0] == sig[0] && contents[1] == sig[1] && contents[2] == sig[2] && contents[3] == sig[3]
        && contents[4] == sig[4] && contents[5] == sig[5] && contents[6] == sig[6] && contents[7] == sig[7] {
        return RealFileType::Document;
    }
    if scan_for(contents, &sig) {
        return RealFileType::Document;
    }
    RealFileType::Unknown
}

fn check_chm(contents: &[u8]) -> RealFileType {
    // Compiled HTML Help -- "ITSF" magic. Historically abused as a
    // malware delivery vector (CHM files can embed scripts).
    if contents.len() >= 4 && contents[0] == b'I' && contents[1] == b'T' && contents[2] == b'S' && contents[3] == b'F' {
        return RealFileType::Document;
    }
    if scan_for(contents, b"ITSF") {
        return RealFileType::Document;
    }
    RealFileType::Unknown
}

// Checks for a DLL assuming the MZ header starts at `base` rather than
// necessarily at offset 0 of the whole file -- lets check_dll re-run this
// same logic anchored at wherever a shifted MZ header turns up.
fn check_dll_at(contents: &[u8], base: usize) -> Option<RealFileType> {
    if contents.len() < base + 0x40 {
        return None;
    }
    if !(contents[base] == 0x4D && contents[base + 1] == 0x5A) {
        return None;
    }
    let e_lfanew = base + 0x3C;
    let pe_off = base + u32::from_le_bytes([contents[e_lfanew], contents[e_lfanew + 1], contents[e_lfanew + 2], contents[e_lfanew + 3]]) as usize;
    if contents.len() < pe_off + 4 {
        return None;
    }
    if !(contents[pe_off] == 0x50 && contents[pe_off + 1] == 0x45 && contents[pe_off + 2] == 0x00 && contents[pe_off + 3] == 0x00) {
        return None;
    }
    // Characteristics is a 2-byte field 22 bytes into the COFF file header,
    // which itself starts right after the 4-byte "PE\0\0" signature.
    let characteristics_off = pe_off + 4 + 18;
    if contents.len() < characteristics_off + 2 {
        return None;
    }
    let characteristics = u16::from_le_bytes([contents[characteristics_off], contents[characteristics_off + 1]]);
    const IMAGE_FILE_DLL: u16 = 0x2000;
    if characteristics & IMAGE_FILE_DLL != 0 {
        return Some(RealFileType::WinExecutable);
    }
    None
}

fn check_dll(contents: &[u8]) -> RealFileType {
    // A DLL is a PE file with the IMAGE_FILE_DLL characteristic flag set --
    // same container format as an EXE, just flagged as a library instead.
    // Unlike check_winexe (which treats offset 0x3C as the header itself),
    // this reads e_lfanew the way it's actually meant to be used: as a
    // pointer to where the real PE header lives.
    if let Some(result) = check_dll_at(contents, 0) {
        return result;
    }
    // A dropped/appended PE payload might not start at offset 0 -- scan
    // for any other "MZ" and re-check relative to it, same fallback idea
    // as check_winexe's own MZ/PE scan.
    if contents.len() >= 2 {
        for i in 1..=(contents.len() - 2) {
            if contents[i] == 0x4D && contents[i + 1] == 0x5A {
                if let Some(result) = check_dll_at(contents, i) {
                    return result;
                }
            }
        }
    }
    return RealFileType::Unknown;
}

fn check_lnk(contents: &[u8]) -> RealFileType {
    // Windows shortcut files: a fixed 20-byte header made up of a
    // HeaderSize field plus the well-known shell-link CLSID. Long and
    // specific enough that false positives are unlikely, unlike the
    // shorter magic numbers above. Categorized as WinExecutable since a
    // .lnk's whole purpose is triggering execution of a target, even
    // though it isn't itself machine code -- LNK files are also a common
    // malware delivery vector, which is why they're worth checking for
    // here at all.
    let sig = [
        0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x46,
    ];
    if contents.len() >= sig.len() {
        let mut matches = true;
        for i in 0..sig.len() {
            if contents[i] != sig[i] {
                matches = false;
                break;
            }
        }
        if matches {
            return RealFileType::WinExecutable;
        }
    }
    if scan_for(contents, &sig) {
        return RealFileType::WinExecutable;
    }
    RealFileType::Unknown
}

fn check_png(contents: &[u8]) -> RealFileType {
    let sig = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    if contents.len() >= 8 && contents[0] == sig[0] && contents[1] == sig[1] && contents[2] == sig[2] && contents[3] == sig[3]
        && contents[4] == sig[4] && contents[5] == sig[5] && contents[6] == sig[6] && contents[7] == sig[7] {
        return RealFileType::Image;
    }
    if scan_for(contents, &sig) {
        return RealFileType::Image;
    }
    return RealFileType::Unknown;
}

fn check_jpeg(contents: &[u8]) -> RealFileType {
    if contents.len() >= 3 && contents[0] == 0xFF && contents[1] == 0xD8 && contents[2] == 0xFF {
        return RealFileType::Image;
    }
    if scan_for(contents, &[0xFF, 0xD8, 0xFF]) {
        return RealFileType::Image;
    }
    return RealFileType::Unknown;
}

fn check_gif(contents: &[u8]) -> RealFileType {
    // Covers both GIF87a and GIF89a -- they only differ in that version tag.
    if contents.len() >= 6 {
        let header_ok = contents[0] == b'G' && contents[1] == b'I' && contents[2] == b'F' && contents[3] == b'8';
        let version_ok = (contents[4] == b'7' || contents[4] == b'9') && contents[5] == b'a';
        if header_ok && version_ok {
            return RealFileType::Image;
        }
    }
    if scan_for(contents, b"GIF87a") || scan_for(contents, b"GIF89a") {
        return RealFileType::Image;
    }
    return RealFileType::Unknown;
}

fn check_bmp(contents: &[u8]) -> RealFileType {
    if contents.len() >= 2 && contents[0] == b'B' && contents[1] == b'M' {
        return RealFileType::Image;
    }
    // "BM" is only 2 bytes, so this fallback scan carries a real
    // false-positive risk on incidental byte pairs elsewhere in the file --
    // accepted here for consistency with the other formats' fallback scans.
    if scan_for(contents, b"BM") {
        return RealFileType::Image;
    }
    return RealFileType::Unknown;
}

fn check_webp(contents: &[u8]) -> RealFileType {
    // Container is RIFF; the format tag "WEBP" sits at byte offset 8, not 0.
    if contents.len() >= 12 {
        let riff = contents[0] == b'R' && contents[1] == b'I' && contents[2] == b'F' && contents[3] == b'F';
        let webp = contents[8] == b'W' && contents[9] == b'E' && contents[10] == b'B' && contents[11] == b'P';
        if riff && webp {
            return RealFileType::Image;
        }
    }
    if scan_for_at_offset(contents, b"RIFF", 8, b"WEBP") {
        return RealFileType::Image;
    }
    return RealFileType::Unknown;
}

fn check_wav(contents: &[u8]) -> RealFileType {
    // Container is RIFF; the format tag "WAVE" sits at byte offset 8.
    if contents.len() >= 12 {
        let riff = contents[0] == b'R' && contents[1] == b'I' && contents[2] == b'F' && contents[3] == b'F';
        let wave = contents[8] == b'W' && contents[9] == b'A' && contents[10] == b'V' && contents[11] == b'E';
        if riff && wave {
            return RealFileType::Audio;
        }
    }
    if scan_for_at_offset(contents, b"RIFF", 8, b"WAVE") {
        return RealFileType::Audio;
    }
    return RealFileType::Unknown;
}

fn check_flac(contents: &[u8]) -> RealFileType {
    if contents.len() >= 4 && contents[0] == b'f' && contents[1] == b'L' && contents[2] == b'a' && contents[3] == b'C' {
        return RealFileType::Audio;
    }
    if scan_for(contents, b"fLaC") {
        return RealFileType::Audio;
    }
    return RealFileType::Unknown;
}

fn check_ogg(contents: &[u8]) -> RealFileType {
    if contents.len() >= 4 && contents[0] == b'O' && contents[1] == b'g' && contents[2] == b'g' && contents[3] == b'S' {
        return RealFileType::Audio;
    }
    if scan_for(contents, b"OggS") {
        return RealFileType::Audio;
    }
    return RealFileType::Unknown;
}

fn check_mp3(contents: &[u8]) -> RealFileType {
    // MP3 has no single reliable signature: it's either an ID3v2 tag up
    // front, or -- lacking a tag -- a floating frame-sync bit pattern
    // (11 set bits) at the very start of the first audio frame.
    if contents.len() >= 3 && contents[0] == b'I' && contents[1] == b'D' && contents[2] == b'3' {
        return RealFileType::Audio;
    }
    if contents.len() >= 2 && contents[0] == 0xFF && (contents[1] & 0xE0) == 0xE0 {
        return RealFileType::Audio;
    }
    if scan_for(contents, b"ID3") {
        return RealFileType::Audio;
    }
    // The frame-sync check is a bitmask, not an exact byte match, so it
    // needs its own scan rather than reusing scan_for -- and being only
    // 11 significant bits, it's the least reliable fallback of the bunch.
    if contents.len() >= 2 {
        for i in 0..=(contents.len() - 2) {
            if contents[i] == 0xFF && (contents[i + 1] & 0xE0) == 0xE0 {
                return RealFileType::Audio;
            }
        }
    }
    return RealFileType::Unknown;
}

fn check_mp4(contents: &[u8]) -> RealFileType {
    // The "ftyp" box sits at byte offset 4, not 0 -- the first 4 bytes are
    // just the box's size field.
    if contents.len() >= 8 && contents[4] == b'f' && contents[5] == b't' && contents[6] == b'y' && contents[7] == b'p' {
        return RealFileType::Video;
    }
    if scan_for(contents, b"ftyp") {
        return RealFileType::Video;
    }
    return RealFileType::Unknown;
}

fn check_webm(contents: &[u8]) -> RealFileType {
    // WebM and Matroska (.mkv) share this same EBML container magic;
    // telling them apart needs more than the first 4 bytes.
    let sig = [0x1A, 0x45, 0xDF, 0xA3];
    if contents.len() >= 4 && contents[0] == sig[0] && contents[1] == sig[1] && contents[2] == sig[2] && contents[3] == sig[3] {
        return RealFileType::Video;
    }
    if scan_for(contents, &sig) {
        return RealFileType::Video;
    }
    return RealFileType::Unknown;
}

fn check_avi(contents: &[u8]) -> RealFileType {
    // Container is RIFF; the format tag "AVI " sits at byte offset 8.
    if contents.len() >= 12 {
        let riff = contents[0] == b'R' && contents[1] == b'I' && contents[2] == b'F' && contents[3] == b'F';
        let avi = contents[8] == b'A' && contents[9] == b'V' && contents[10] == b'I' && contents[11] == b' ';
        if riff && avi {
            return RealFileType::Video;
        }
    }
    if scan_for_at_offset(contents, b"RIFF", 8, b"AVI ") {
        return RealFileType::Video;
    }
    return RealFileType::Unknown;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Builds a minimal ELF header: magic + EI_DATA (endianness) + e_type,
    // zero-padded to 64 bytes so it also clears check_winexe's length gate.
    fn elf_header(e_type: u16, big_endian: bool) -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        bytes[0] = 0x7F;
        bytes[1] = 0x45;
        bytes[2] = 0x4C;
        bytes[3] = 0x46;
        bytes[5] = if big_endian { 2 } else { 1 };
        let type_bytes = if big_endian { e_type.to_be_bytes() } else { e_type.to_le_bytes() };
        bytes[16] = type_bytes[0];
        bytes[17] = type_bytes[1];
        bytes
    }

    #[test]
    fn elf_executable_is_not_a_shared_object() {
        assert!(!is_elf_shared_object(&elf_header(2, false))); // ET_EXEC
    }

    #[test]
    fn elf_shared_object_little_endian() {
        assert!(is_elf_shared_object(&elf_header(3, false))); // ET_DYN
    }

    #[test]
    fn elf_shared_object_big_endian() {
        assert!(is_elf_shared_object(&elf_header(3, true))); // ET_DYN
    }

    #[test]
    fn contents_too_short_to_hold_e_type_are_not_a_shared_object() {
        let contents = elf_header(3, false);
        assert!(!is_elf_shared_object(&contents[..17])); // one byte short of e_type
    }

    #[test]
    fn identify_type_reports_elf_executable() {
        let result = identify_type(&elf_header(2, false));
        assert_eq!(result.file_type, RealFileType::LinuxExecutable);
        assert_eq!(result.file_sub_type, RealFileSubType::Executable(ExecutableSubType::ELF));
    }

    #[test]
    fn identify_type_reports_shared_object() {
        let result = identify_type(&elf_header(3, false));
        assert_eq!(result.file_type, RealFileType::LinuxExecutable);
        assert_eq!(result.file_sub_type, RealFileSubType::Executable(ExecutableSubType::SO));
    }
}
