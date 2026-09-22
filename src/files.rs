use std::error::Error;

use crate::types::{
    ArchiveSubType, AudioSubType, DocumentSubType, ErratasJob, ExecutableSubType, ImageSubType,
    RealFileSubType, RealFileType, VideoSubType,
};

pub fn identify_real_filetype(erratas_job: &mut ErratasJob) -> &mut ErratasJob {
    if let Some(offset) = check_elf(&erratas_job.file_info.contents) {
        let file_sub_type = if is_elf_shared_object(&erratas_job.file_info.contents, offset) {
            ExecutableSubType::SO
        } else {
            ExecutableSubType::ELF
        };
        erratas_job
            .file_info
            .file_type
            .push(RealFileType::LinuxExecutable);
        erratas_job
            .file_info
            .file_sub_type
            .push(RealFileSubType::Executable(file_sub_type));
    }

    match check_winexe(&erratas_job.file_info.contents) {
        Ok(RealFileType::WinExecutable) => {
            erratas_job
                .file_info
                .file_type
                .push(RealFileType::WinExecutable);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Executable(ExecutableSubType::PE));
        }
        Ok(_) => {}
        Err(e) => {
            println!("Error: {e}");
        }
    }

    match check_dll(&erratas_job.file_info.contents) {
        RealFileType::WinExecutable => {
            erratas_job
                .file_info
                .file_type
                .push(RealFileType::WinExecutable);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Executable(ExecutableSubType::DLL));
        }
        _ => {}
    }

    match check_lnk(&erratas_job.file_info.contents) {
        RealFileType::WinExecutable => {
            erratas_job
                .file_info
                .file_type
                .push(RealFileType::WinExecutable);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Executable(ExecutableSubType::LNK));
        }
        _ => {}
    }

    match check_macho(&erratas_job.file_info.contents) {
        RealFileType::MacExecutable => {
            erratas_job
                .file_info
                .file_type
                .push(RealFileType::MacExecutable);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Executable(ExecutableSubType::MachO));
        }
        _ => {}
    }

    match check_dmg(&erratas_job.file_info.contents) {
        RealFileType::Archive => {
            erratas_job.file_info.file_type.push(RealFileType::Archive);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Archive(ArchiveSubType::DMG));
        }
        _ => {}
    }

    // Must come before check_zip -- otherwise a .docx/.xlsx/.pptx would
    // already match as a plain Archive before we get a chance to notice
    // it's actually an OOXML document.
    match check_ooxml(&erratas_job.file_info.contents) {
        RealFileType::Document => {
            erratas_job.file_info.file_type.push(RealFileType::Document);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Document(ooxml_subtype(
                    &erratas_job.file_info.contents,
                )));
        }
        _ => {}
    }

    match check_zip(&erratas_job.file_info.contents) {
        RealFileType::Archive => {
            erratas_job.file_info.file_type.push(RealFileType::Archive);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Archive(ArchiveSubType::ZIP));
        }
        _ => {}
    }

    match check_rar(&erratas_job.file_info.contents) {
        RealFileType::Archive => {
            erratas_job.file_info.file_type.push(RealFileType::Archive);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Archive(ArchiveSubType::RAR));
        }
        _ => {}
    }
    match check_7z(&erratas_job.file_info.contents) {
        RealFileType::Archive => {
            erratas_job.file_info.file_type.push(RealFileType::Archive);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Archive(ArchiveSubType::SEVENZ));
        }
        _ => {}
    }

    match check_cab(&erratas_job.file_info.contents) {
        RealFileType::Archive => {
            erratas_job.file_info.file_type.push(RealFileType::Archive);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Archive(ArchiveSubType::CAB));
        }
        _ => {}
    }

    match check_tar(&erratas_job.file_info.contents) {
        RealFileType::Archive => {
            erratas_job.file_info.file_type.push(RealFileType::Archive);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Archive(ArchiveSubType::TAR));
        }
        _ => {}
    }

    match check_iso(&erratas_job.file_info.contents) {
        RealFileType::Archive => {
            erratas_job.file_info.file_type.push(RealFileType::Archive);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Archive(ArchiveSubType::ISO));
        }
        RealFileType::WinExecutable => {
            erratas_job
                .file_info
                .file_type
                .push(RealFileType::WinExecutable);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Executable(ExecutableSubType::PE));
        }
        _ => {}
    }

    match check_pdf(&erratas_job.file_info.contents) {
        RealFileType::Document => {
            erratas_job.file_info.file_type.push(RealFileType::Document);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Document(DocumentSubType::PDF));
        }
        _ => {}
    }

    match check_ole_cfb(&erratas_job.file_info.contents) {
        RealFileType::Document => {
            erratas_job.file_info.file_type.push(RealFileType::Document);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Document(ole_cfb_subtype(
                    &erratas_job.file_info.contents,
                )));
        }
        _ => {}
    }

    match check_chm(&erratas_job.file_info.contents) {
        RealFileType::Document => {
            erratas_job.file_info.file_type.push(RealFileType::Document);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Document(DocumentSubType::CHM));
        }
        _ => {}
    }

    match check_png(&erratas_job.file_info.contents) {
        RealFileType::Image => {
            erratas_job.file_info.file_type.push(RealFileType::Image);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Image(ImageSubType::PNG));
        }
        _ => {}
    }
    match check_jpeg(&erratas_job.file_info.contents) {
        RealFileType::Image => {
            erratas_job.file_info.file_type.push(RealFileType::Image);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Image(ImageSubType::JPEG));
        }
        _ => {}
    }
    match check_gif(&erratas_job.file_info.contents) {
        RealFileType::Image => {
            erratas_job.file_info.file_type.push(RealFileType::Image);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Image(ImageSubType::GIF));
        }
        _ => {}
    }
    match check_bmp(&erratas_job.file_info.contents) {
        RealFileType::Image => {
            erratas_job.file_info.file_type.push(RealFileType::Image);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Image(ImageSubType::BMP));
        }
        _ => {}
    }
    match check_webp(&erratas_job.file_info.contents) {
        RealFileType::Image => {
            erratas_job.file_info.file_type.push(RealFileType::Image);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Image(ImageSubType::WEBP));
        }
        _ => {}
    }

    match check_wav(&erratas_job.file_info.contents) {
        RealFileType::Audio => {
            erratas_job.file_info.file_type.push(RealFileType::Audio);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Audio(AudioSubType::WAV));
        }
        _ => {}
    }
    match check_flac(&erratas_job.file_info.contents) {
        RealFileType::Audio => {
            erratas_job.file_info.file_type.push(RealFileType::Audio);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Audio(AudioSubType::FLAC));
        }
        _ => {}
    }
    match check_ogg(&erratas_job.file_info.contents) {
        RealFileType::Audio => {
            erratas_job.file_info.file_type.push(RealFileType::Audio);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Audio(AudioSubType::OGG));
        }
        _ => {}
    }
    match check_mp3(&erratas_job.file_info.contents) {
        RealFileType::Audio => {
            erratas_job.file_info.file_type.push(RealFileType::Audio);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Audio(AudioSubType::MP3));
        }
        _ => {}
    }

    match check_mp4(&erratas_job.file_info.contents) {
        RealFileType::Video => {
            erratas_job.file_info.file_type.push(RealFileType::Video);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Video(VideoSubType::MP4));
        }
        _ => {}
    }
    match check_webm(&erratas_job.file_info.contents) {
        RealFileType::Video => {
            erratas_job.file_info.file_type.push(RealFileType::Video);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Video(VideoSubType::WEBM));
        }
        _ => {}
    }
    match check_avi(&erratas_job.file_info.contents) {
        RealFileType::Video => {
            erratas_job.file_info.file_type.push(RealFileType::Video);
            erratas_job
                .file_info
                .file_sub_type
                .push(RealFileSubType::Video(VideoSubType::AVI));
        }
        _ => {}
    }

    if erratas_job.file_info.file_type.len() == 0 {
        erratas_job.file_info.file_type.push(RealFileType::Unknown);
    }
    if erratas_job.file_info.file_sub_type.len() == 0 {
        erratas_job
            .file_info
            .file_sub_type
            .push(RealFileSubType::Unknown(
                crate::types::UnknownSubType::Unknown,
            ));
    }
    return erratas_job;
}

// Returns the byte offset where the ELF magic was found, so callers (like
// is_elf_shared_object) can read the rest of the header relative to where
// it actually starts -- not always 0, once a fallback match is involved.
fn check_elf(contents: &[u8]) -> Option<usize> {
    let elf_magic = [0x7F, 0x45, 0x4C, 0x46];
    if contents.len() >= 4 && contents[0..4] == elf_magic {
        return Some(0);
    }

    // contents.len() < 4 has no valid window to scan; guard first so the
    // range below can't underflow.
    if contents.len() < 4 {
        return None;
    }
    for i in 0..=(contents.len() - 4) {
        if contents[i..i + 4] == elf_magic {
            return Some(i);
        }
    }
    None
}

// e_type (offset 16, 2 bytes) tells ELF binaries and shared objects apart --
// ET_DYN (3) is a .so, ET_EXEC (2) is a regular executable. Byte order for
// that field follows EI_DATA at offset 5 (1 = little-endian, 2 = big-endian),
// since ELF (unlike PE) isn't always little-endian. `base` is where the ELF
// magic itself was found (see check_elf) -- every other header field is
// read relative to it, not a hardcoded 0, so a shifted/carved ELF header
// still gets its e_type read from the right place.
const ET_DYN: u16 = 3;

fn is_elf_shared_object(contents: &[u8], base: usize) -> bool {
    if contents.len() < base + 18 {
        return false;
    }
    let e_type = match contents[base + 5] {
        2 => u16::from_be_bytes([contents[base + 16], contents[base + 17]]),
        _ => u16::from_le_bytes([contents[base + 16], contents[base + 17]]),
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
            if contents.len() >= tag_start + tag.len()
                && &contents[tag_start..tag_start + tag.len()] == tag
            {
                return true;
            }
        }
    }
    false
}

const MACHO_MAGICKS: [[u8; 4]; 6] = [
    [0xFE, 0xED, 0xFA, 0xCE],
    [0xCE, 0xFA, 0xED, 0xFE],
    [0xFE, 0xED, 0xFA, 0xCF],
    [0xCF, 0xFA, 0xED, 0xFE],
    [0xCA, 0xFE, 0xBA, 0xBE],
    [0xBE, 0xBA, 0xFE, 0xCA],
];

fn check_macho(contents: &[u8]) -> RealFileType {
    if contents.len() >= 4 {
        match [contents[0], contents[1], contents[2], contents[3]] {
            // 32-bit Mach-O, either byte order.
            [0xFE, 0xED, 0xFA, 0xCE] | [0xCE, 0xFA, 0xED, 0xFE] => {
                return RealFileType::MacExecutable;
            }
            // 64-bit Mach-O, either byte order.
            [0xFE, 0xED, 0xFA, 0xCF] | [0xCF, 0xFA, 0xED, 0xFE] => {
                return RealFileType::MacExecutable;
            }
            // Fat/universal binary. Same magic number as a Java .class file --
            // a real collision, not a bug. Telling them apart needs more than
            // just these 4 bytes.
            [0xCA, 0xFE, 0xBA, 0xBE] | [0xBE, 0xBA, 0xFE, 0xCA] => {
                return RealFileType::MacExecutable;
            }
            _ => {}
        }
    }
    for magic in MACHO_MAGICKS.iter() {
        if scan_for(contents, magic) {
            return RealFileType::MacExecutable;
        }
    }
    RealFileType::Unknown
}

fn check_winexe(contents: &[u8]) -> Result<RealFileType, Box<dyn Error>> {
    if contents.len() < 64 {
        return Ok(RealFileType::Unknown);
    }
    let mut pe = false;
    let mut mz = false;

    // A normal executable has a MZ firstly so if it's there we done.
    if contents[0] == 0x4D && contents[1] == 0x5A {
        println!("MZ");
        mz = true;
    }

    if contents[0x3C] == 0x50
        && contents[0x3C + 1] == 0x45
        && contents[0x3C + 2] == 0x00
        && contents[0x3C + 3] == 0x00
    {
        println!("PE");
        pe = true;
    }

    if mz && pe {
        return Ok(RealFileType::WinExecutable);
    } else {
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
        if contents[i] == 0x50
            && contents[i + 1] == 0x45
            && contents[i + 2] == 0x00
            && contents[i + 3] == 0x00
        {
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
        if contents[t] == 0x6B
            && contents[t + 1] == 0x6F
            && contents[t + 2] == 0x6C
            && contents[t + 3] == 0x79
        {
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

// Only called once check_ooxml has already confirmed the file is some
// kind of OOXML package -- picks out which one by scanning for the entry
// name each format's package always carries at a fixed path. Falls back
// to the generic OOXML variant if none of the three match (a format this
// doesn't know about yet, or a package that's missing that entry).
fn ooxml_subtype(contents: &[u8]) -> DocumentSubType {
    if scan_for(contents, b"word/document.xml") {
        return DocumentSubType::DOCX;
    }
    if scan_for(contents, b"xl/workbook.xml") {
        return DocumentSubType::XLSX;
    }
    if scan_for(contents, b"ppt/presentation.xml") {
        return DocumentSubType::PPTX;
    }
    DocumentSubType::OOXML
}

fn check_zip(contents: &[u8]) -> RealFileType {
    if contents.len() >= 4 {
        // Local file header.
        if contents[0] == 0x50 && contents[1] == 0x4B && contents[2] == 0x03 && contents[3] == 0x04
        {
            return RealFileType::Archive;
        }
        // End-of-central-directory marker (an empty archive has only this).
        if contents[0] == 0x50 && contents[1] == 0x4B && contents[2] == 0x05 && contents[3] == 0x06
        {
            return RealFileType::Archive;
        }
    }
    // A polyglot/dropper file (self-extracting installer, JAR, APK) has
    // real zip data starting well past offset 0 -- scan for it.
    if scan_for(contents, &[0x50, 0x4B, 0x03, 0x04])
        || scan_for(contents, &[0x50, 0x4B, 0x05, 0x06])
    {
        return RealFileType::Archive;
    }
    return RealFileType::Unknown;
}

fn check_rar(contents: &[u8]) -> RealFileType {
    // RAR 1.5-4.x and RAR5 share this 6-byte prefix.
    let sig = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07];
    if contents.len() >= 6
        && contents[0] == sig[0]
        && contents[1] == sig[1]
        && contents[2] == sig[2]
        && contents[3] == sig[3]
        && contents[4] == sig[4]
        && contents[5] == sig[5]
    {
        return RealFileType::Archive;
    }
    if scan_for(contents, &sig) {
        return RealFileType::Archive;
    }
    return RealFileType::Unknown;
}

fn check_7z(contents: &[u8]) -> RealFileType {
    let sig = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
    if contents.len() >= 6
        && contents[0] == sig[0]
        && contents[1] == sig[1]
        && contents[2] == sig[2]
        && contents[3] == sig[3]
        && contents[4] == sig[4]
        && contents[5] == sig[5]
    {
        return RealFileType::Archive;
    }
    if scan_for(contents, &sig) {
        return RealFileType::Archive;
    }
    return RealFileType::Unknown;
}

fn check_cab(contents: &[u8]) -> RealFileType {
    // Microsoft Cabinet format, used by installers/updates -- "MSCF" magic.
    if contents.len() >= 4
        && contents[0] == b'M'
        && contents[1] == b'S'
        && contents[2] == b'C'
        && contents[3] == b'F'
    {
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
    if contents.len() >= o + 5
        && contents[o] == b'u'
        && contents[o + 1] == b's'
        && contents[o + 2] == b't'
        && contents[o + 3] == b'a'
        && contents[o + 4] == b'r'
    {
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
    if contents.len() >= o + 5
        && contents[o] == b'C'
        && contents[o + 1] == b'D'
        && contents[o + 2] == b'0'
        && contents[o + 3] == b'0'
        && contents[o + 4] == b'1'
    {
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
    if contents.len() >= 5
        && contents[0] == b'%'
        && contents[1] == b'P'
        && contents[2] == b'D'
        && contents[3] == b'F'
        && contents[4] == b'-'
    {
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
    if contents.len() >= 8
        && contents[0] == sig[0]
        && contents[1] == sig[1]
        && contents[2] == sig[2]
        && contents[3] == sig[3]
        && contents[4] == sig[4]
        && contents[5] == sig[5]
        && contents[6] == sig[6]
        && contents[7] == sig[7]
    {
        return RealFileType::Document;
    }
    if scan_for(contents, &sig) {
        return RealFileType::Document;
    }
    RealFileType::Unknown
}

// Only called once check_ole_cfb has already confirmed the file is some
// kind of Compound File Binary container -- walks the File Allocation
// Table (FAT) to find the directory sectors, then reads each directory
// entry's stream/storage name looking for one of the three names each
// legacy Office format always carries (MS-DOC/XLS/PPT), the way the
// module comment on check_ole_cfb already says this needs to work: real
// structure, not another magic-byte scan.
//
// Deliberately linear rather than reconstructing the directory's
// red-black tree the spec describes -- the tree only matters for
// enumerating a live filesystem-like view of the container; spotting
// whether one particular stream name exists anywhere in it doesn't need
// that.
//
// Every read here is bounds-checked (`.get()`, never a bare index) and
// every sector-chain walk is capped against cycles -- this parses
// untrusted, potentially adversarial files, so a truncated header, an
// out-of-range sector pointer, or a FAT chain someone deliberately
// looped back on itself must fail closed (fall through to the generic
// OLECFB classification) instead of panicking or hanging.
//
// Scoped to CFB v3 (512-byte sectors) only -- that's what legacy Office
// documents actually use in practice. v4 (4096-byte sectors, mainly for
// >2GB containers) places sector 0 right after a 4096-byte first block
// rather than the fixed 512-byte header this reads; rather than get that
// offset wrong, v4 containers just fall back to the generic OLECFB
// classification below.
fn ole_cfb_subtype(contents: &[u8]) -> DocumentSubType {
    const FREESECT: u32 = 0xFFFFFFFF;
    const ENDOFCHAIN: u32 = 0xFFFFFFFE;
    const HEADER_SIZE: usize = 512;
    const SECTOR_SIZE: usize = 512;
    const DIFAT_IN_HEADER: usize = 109;
    const ENTRY_SIZE: usize = 128;

    let read_u16 = |off: usize| -> Option<u16> {
        contents
            .get(off..off + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let read_u32 = |off: usize| -> Option<u32> {
        contents
            .get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };

    if contents.len() < HEADER_SIZE {
        return DocumentSubType::OLECFB;
    }
    let Some(sector_shift) = read_u16(30) else {
        return DocumentSubType::OLECFB;
    };
    if sector_shift != 9 {
        // Not a 512-byte-sector (v3) container -- see the v4 note above.
        return DocumentSubType::OLECFB;
    }
    let Some(num_fat_sectors) = read_u32(44) else {
        return DocumentSubType::OLECFB;
    };
    let Some(first_dir_sector) = read_u32(48) else {
        return DocumentSubType::OLECFB;
    };
    let Some(first_difat_sector) = read_u32(68) else {
        return DocumentSubType::OLECFB;
    };
    let Some(num_difat_sectors) = read_u32(72) else {
        return DocumentSubType::OLECFB;
    };

    // Sector `id` lives right after the fixed 512-byte header.
    let sector = |id: u32| -> Option<&[u8]> {
        let start = HEADER_SIZE.checked_add((id as usize).checked_mul(SECTOR_SIZE)?)?;
        contents.get(start..start.checked_add(SECTOR_SIZE)?)
    };

    // Collect every FAT sector's location: the first 109 come straight
    // from the header's own embedded DIFAT array, and any beyond that
    // come from chained DIFAT sectors (only needed for containers over
    // ~7MB at 512-byte sectors -- rare for legacy Office documents, but
    // real, so it's still followed rather than silently truncated).
    let mut fat_sector_ids = Vec::new();
    for i in 0..DIFAT_IN_HEADER.min(num_fat_sectors as usize) {
        match read_u32(76 + i * 4) {
            Some(id) if id != FREESECT => fat_sector_ids.push(id),
            _ => break,
        }
    }
    let mut difat_id = first_difat_sector;
    let mut difat_sectors_seen = 0usize;
    while difat_id != ENDOFCHAIN
        && difat_id != FREESECT
        && difat_sectors_seen < num_difat_sectors as usize
        && difat_sectors_seen < 4096
    {
        let Some(s) = sector(difat_id) else { break };
        // The last 4-byte slot in a DIFAT sector is the next DIFAT
        // sector's location, not a FAT sector pointer.
        let entries_per_sector = SECTOR_SIZE / 4 - 1;
        for i in 0..entries_per_sector {
            let Some(bytes) = s.get(i * 4..i * 4 + 4) else {
                break;
            };
            let id = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            if id == FREESECT {
                break;
            }
            fat_sector_ids.push(id);
        }
        let Some(next_bytes) = s.get(SECTOR_SIZE - 4..SECTOR_SIZE) else {
            break;
        };
        difat_id = u32::from_le_bytes([next_bytes[0], next_bytes[1], next_bytes[2], next_bytes[3]]);
        difat_sectors_seen += 1;
    }

    // Flatten every FAT sector's u32 entries into one lookup table:
    // fat[sector_id] gives the next sector in that sector's chain.
    let entries_per_fat_sector = SECTOR_SIZE / 4;
    let mut fat = vec![FREESECT; fat_sector_ids.len() * entries_per_fat_sector];
    for (slot, &fat_sector_id) in fat_sector_ids.iter().enumerate() {
        let Some(s) = sector(fat_sector_id) else {
            continue;
        };
        for i in 0..entries_per_fat_sector {
            let Some(bytes) = s.get(i * 4..i * 4 + 4) else {
                break;
            };
            fat[slot * entries_per_fat_sector + i] =
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
    }

    // Walk the directory sector chain. `seen.insert` doubles as both the
    // dedup and the cycle guard -- a chain that loops back on a sector it
    // already visited stops on the second visit rather than spinning.
    let mut dir_sector_ids = Vec::new();
    let mut current = first_dir_sector;
    let mut seen = std::collections::HashSet::new();
    while current != ENDOFCHAIN && current != FREESECT && seen.insert(current) {
        dir_sector_ids.push(current);
        match fat.get(current as usize) {
            Some(&next) => current = next,
            None => break,
        }
    }

    // Each 128-byte directory entry starts with a UTF-16LE name (up to 64
    // bytes) and a byte length for it at offset 64 -- read every entry in
    // every directory sector and check its name against the stream each
    // legacy Office format is known to store.
    for dir_sector_id in dir_sector_ids {
        let Some(s) = sector(dir_sector_id) else {
            continue;
        };
        for entry in s.chunks(ENTRY_SIZE) {
            if entry.len() < ENTRY_SIZE {
                continue;
            }
            let object_type = entry[66];
            // 1 = storage, 2 = stream, 5 = root storage; 0 is an
            // unused/unallocated slot with no meaningful name.
            if object_type == 0 {
                continue;
            }
            let name_len = u16::from_le_bytes([entry[64], entry[65]]) as usize;
            // name_len is a byte count that includes the trailing UTF-16
            // nul, and per spec can't exceed the 64-byte name field.
            if !(2..=64).contains(&name_len) {
                continue;
            }
            let name: String = entry[0..name_len - 2]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                .filter_map(|u| char::from_u32(u as u32))
                .collect();

            match name.as_str() {
                "WordDocument" => return DocumentSubType::DOC,
                "Workbook" | "Book" => return DocumentSubType::XLS,
                "PowerPoint Document" => return DocumentSubType::PPT,
                _ => {}
            }
        }
    }

    DocumentSubType::OLECFB
}

fn check_chm(contents: &[u8]) -> RealFileType {
    // Compiled HTML Help -- "ITSF" magic. Historically abused as a
    // malware delivery vector (CHM files can embed scripts).
    if contents.len() >= 4
        && contents[0] == b'I'
        && contents[1] == b'T'
        && contents[2] == b'S'
        && contents[3] == b'F'
    {
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
    let pe_off = base
        + u32::from_le_bytes([
            contents[e_lfanew],
            contents[e_lfanew + 1],
            contents[e_lfanew + 2],
            contents[e_lfanew + 3],
        ]) as usize;
    if contents.len() < pe_off + 4 {
        return None;
    }
    if !(contents[pe_off] == 0x50
        && contents[pe_off + 1] == 0x45
        && contents[pe_off + 2] == 0x00
        && contents[pe_off + 3] == 0x00)
    {
        return None;
    }
    // Characteristics is a 2-byte field 22 bytes into the COFF file header,
    // which itself starts right after the 4-byte "PE\0\0" signature.
    let characteristics_off = pe_off + 4 + 18;
    if contents.len() < characteristics_off + 2 {
        return None;
    }
    let characteristics = u16::from_le_bytes([
        contents[characteristics_off],
        contents[characteristics_off + 1],
    ]);
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
        0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x46,
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
    if contents.len() >= 8
        && contents[0] == sig[0]
        && contents[1] == sig[1]
        && contents[2] == sig[2]
        && contents[3] == sig[3]
        && contents[4] == sig[4]
        && contents[5] == sig[5]
        && contents[6] == sig[6]
        && contents[7] == sig[7]
    {
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
        let header_ok = contents[0] == b'G'
            && contents[1] == b'I'
            && contents[2] == b'F'
            && contents[3] == b'8';
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
        let riff = contents[0] == b'R'
            && contents[1] == b'I'
            && contents[2] == b'F'
            && contents[3] == b'F';
        let webp = contents[8] == b'W'
            && contents[9] == b'E'
            && contents[10] == b'B'
            && contents[11] == b'P';
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
        let riff = contents[0] == b'R'
            && contents[1] == b'I'
            && contents[2] == b'F'
            && contents[3] == b'F';
        let wave = contents[8] == b'W'
            && contents[9] == b'A'
            && contents[10] == b'V'
            && contents[11] == b'E';
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
    if contents.len() >= 4
        && contents[0] == b'f'
        && contents[1] == b'L'
        && contents[2] == b'a'
        && contents[3] == b'C'
    {
        return RealFileType::Audio;
    }
    if scan_for(contents, b"fLaC") {
        return RealFileType::Audio;
    }
    return RealFileType::Unknown;
}

fn check_ogg(contents: &[u8]) -> RealFileType {
    if contents.len() >= 4
        && contents[0] == b'O'
        && contents[1] == b'g'
        && contents[2] == b'g'
        && contents[3] == b'S'
    {
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
    if contents.len() >= 8
        && contents[4] == b'f'
        && contents[5] == b't'
        && contents[6] == b'y'
        && contents[7] == b'p'
    {
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
    if contents.len() >= 4
        && contents[0] == sig[0]
        && contents[1] == sig[1]
        && contents[2] == sig[2]
        && contents[3] == sig[3]
    {
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
        let riff = contents[0] == b'R'
            && contents[1] == b'I'
            && contents[2] == b'F'
            && contents[3] == b'F';
        let avi = contents[8] == b'A'
            && contents[9] == b'V'
            && contents[10] == b'I'
            && contents[11] == b' ';
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
    use crate::types::FileInfo;

    // identify_type now takes an &mut ErratasJob and mutates it in
    // place rather than taking raw bytes directly -- this builds the
    // "freshly read, not yet scanned" starting point the same way
    // lib.rs's load_file does, so tests can still just hand it bytes.
    fn result_for(contents: Vec<u8>) -> ErratasJob {
        ErratasJob {
            file_info: FileInfo {
                contents,
                bad_language: false,
                pii: false,
                zipbomb: false,
                malware: false,
                strike3: Vec::new(),
                hashmatches: Vec::new(),
                yara_finds: Vec::new(),
                file_type: Vec::new(),
                file_sub_type: Vec::new(),
            },
        }
    }

    // Builds a minimal ELF header: magic + EI_DATA (endianness) + e_type,
    // zero-padded to 64 bytes so it also clears check_winexe's length gate.
    fn elf_header(e_type: u16, big_endian: bool) -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        bytes[0] = 0x7F;
        bytes[1] = 0x45;
        bytes[2] = 0x4C;
        bytes[3] = 0x46;
        bytes[5] = if big_endian { 2 } else { 1 };
        let type_bytes = if big_endian {
            e_type.to_be_bytes()
        } else {
            e_type.to_le_bytes()
        };
        bytes[16] = type_bytes[0];
        bytes[17] = type_bytes[1];
        bytes
    }

    #[test]
    fn elf_executable_is_not_a_shared_object() {
        assert!(!is_elf_shared_object(&elf_header(2, false), 0)); // ET_EXEC
    }

    #[test]
    fn elf_shared_object_little_endian() {
        assert!(is_elf_shared_object(&elf_header(3, false), 0)); // ET_DYN
    }

    #[test]
    fn elf_shared_object_big_endian() {
        assert!(is_elf_shared_object(&elf_header(3, true), 0)); // ET_DYN
    }

    #[test]
    fn contents_too_short_to_hold_e_type_are_not_a_shared_object() {
        let contents = elf_header(3, false);
        assert!(!is_elf_shared_object(&contents[..17], 0)); // one byte short of e_type
    }

    #[test]
    fn check_elf_does_not_panic_on_files_under_4_bytes() {
        assert_eq!(check_elf(&[]), None);
        assert_eq!(check_elf(&[0x7F, 0x45]), None);
    }

    #[test]
    fn check_elf_finds_shifted_magic_via_fallback_scan() {
        let mut contents = vec![0x90; 32];
        contents.extend_from_slice(&elf_header(2, false));
        assert_eq!(check_elf(&contents), Some(32));
    }

    #[test]
    fn identify_type_reports_shared_object_when_shifted() {
        // Same ET_DYN header as identify_type_reports_shared_object, just
        // pushed behind 32 bytes of filler -- this is what check_elf's
        // fallback scan plus is_elf_shared_object's offset threading needs
        // to get right together for a shifted .so to still classify as SO
        // instead of misreading e_type from the wrong bytes.
        let mut contents = vec![0x90; 32];
        contents.extend_from_slice(&elf_header(3, false));
        let mut result = result_for(contents);
        identify_real_filetype(&mut result);
        assert_eq!(
            result.file_info.file_type,
            vec![RealFileType::LinuxExecutable]
        );
        assert_eq!(
            result.file_info.file_sub_type,
            vec![RealFileSubType::Executable(ExecutableSubType::SO)]
        );
    }

    #[test]
    fn identify_type_reports_elf_executable() {
        let mut result = result_for(elf_header(2, false));
        identify_real_filetype(&mut result);
        assert_eq!(
            result.file_info.file_type,
            vec![RealFileType::LinuxExecutable]
        );
        assert_eq!(
            result.file_info.file_sub_type,
            vec![RealFileSubType::Executable(ExecutableSubType::ELF)]
        );
    }

    #[test]
    fn identify_type_reports_shared_object() {
        let mut result = result_for(elf_header(3, false));
        identify_real_filetype(&mut result);
        assert_eq!(
            result.file_info.file_type,
            vec![RealFileType::LinuxExecutable]
        );
        assert_eq!(
            result.file_info.file_sub_type,
            vec![RealFileSubType::Executable(ExecutableSubType::SO)]
        );
    }

    // --- scan_for / scan_for_at_offset --------------------------------
    // These back nearly every format's shifted/carved fallback path, but
    // had no direct coverage of their own -- only ever exercised
    // indirectly through whichever check_* happened to call them.

    #[test]
    fn scan_for_finds_pattern_in_the_middle() {
        assert!(scan_for(b"....needle....", b"needle"));
    }

    #[test]
    fn scan_for_finds_pattern_at_the_very_end() {
        assert!(scan_for(b"....needle", b"needle"));
    }

    #[test]
    fn scan_for_false_when_pattern_absent() {
        assert!(!scan_for(b"nothing to see here", b"needle"));
    }

    #[test]
    fn scan_for_false_for_empty_pattern() {
        assert!(!scan_for(b"anything", b""));
    }

    #[test]
    fn scan_for_false_when_pattern_longer_than_contents() {
        assert!(!scan_for(b"short", b"way too long a needle"));
    }

    #[test]
    fn scan_for_at_offset_finds_anchor_and_tag_at_the_right_gap() {
        // "RIFF" at 0, "WAVE" 8 bytes later -- the real WAV layout.
        let mut contents = b"RIFF".to_vec();
        contents.extend_from_slice(&[0u8; 4]); // 4 bytes of chunk size filler
        contents.extend_from_slice(b"WAVE");
        assert!(scan_for_at_offset(&contents, b"RIFF", 8, b"WAVE"));
    }

    #[test]
    fn scan_for_at_offset_false_when_anchor_present_but_tag_is_wrong() {
        let mut contents = b"RIFF".to_vec();
        contents.extend_from_slice(&[0u8; 4]);
        contents.extend_from_slice(b"AVI ");
        assert!(!scan_for_at_offset(&contents, b"RIFF", 8, b"WAVE"));
    }

    #[test]
    fn scan_for_at_offset_false_when_anchor_absent() {
        assert!(!scan_for_at_offset(b"no anchor here", b"RIFF", 8, b"WAVE"));
    }

    #[test]
    fn scan_for_at_offset_false_when_gap_runs_past_end() {
        // Anchor matches right at the end, leaving no room for the tag.
        assert!(!scan_for_at_offset(b"....RIFF", b"RIFF", 8, b"WAVE"));
    }

    // --- check_winexe ----------------------------------------------------

    #[test]
    fn check_winexe_reports_unknown_under_64_bytes() {
        assert_eq!(check_winexe(&[0x4D, 0x5A]).unwrap(), RealFileType::Unknown);
    }

    #[test]
    fn check_winexe_detects_mz_pe_at_the_standard_offsets() {
        let mut contents = vec![0u8; 64];
        contents[0] = 0x4D;
        contents[1] = 0x5A;
        contents[0x3C] = 0x50;
        contents[0x3C + 1] = 0x45;
        contents[0x3C + 2] = 0x00;
        contents[0x3C + 3] = 0x00;
        assert_eq!(
            check_winexe(&contents).unwrap(),
            RealFileType::WinExecutable
        );
    }

    #[test]
    fn check_winexe_mz_without_pe_is_unknown() {
        let mut contents = vec![0u8; 64];
        contents[0] = 0x4D;
        contents[1] = 0x5A;
        assert_eq!(check_winexe(&contents).unwrap(), RealFileType::Unknown);
    }

    #[test]
    fn check_winexe_finds_shifted_mz_and_pe_via_fallback_scan() {
        // Neither marker sits at its normal offset -- both are pushed well
        // past where the fast path looks, so this only passes if the
        // fallback scan loops actually run and find them separately.
        let mut contents = vec![0x90; 128];
        contents[40] = 0x4D;
        contents[41] = 0x5A;
        contents[100] = 0x50;
        contents[101] = 0x45;
        contents[102] = 0x00;
        contents[103] = 0x00;
        assert_eq!(
            check_winexe(&contents).unwrap(),
            RealFileType::WinExecutable
        );
    }

    // --- check_dll / check_dll_at -----------------------------------------

    // Mirrors scripts/generate_and_scan_examples.sh's example.dll fixture:
    // MZ at 0, e_lfanew (offset 0x3C) pointing to a PE header at 0x80, with
    // `characteristics` written at the COFF header's characteristics field
    // (pe header + 4-byte "PE\0\0" sig + 18 bytes = pe_off + 22).
    fn dll_header(characteristics: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; 256];
        bytes[0] = 0x4D;
        bytes[1] = 0x5A;
        bytes[0x3C..0x3C + 4].copy_from_slice(&(0x80u32).to_le_bytes());
        let pe_off = 0x80;
        bytes[pe_off] = 0x50;
        bytes[pe_off + 1] = 0x45;
        bytes[pe_off + 2] = 0x00;
        bytes[pe_off + 3] = 0x00;
        let characteristics_off = pe_off + 4 + 18;
        bytes[characteristics_off..characteristics_off + 2]
            .copy_from_slice(&characteristics.to_le_bytes());
        bytes
    }

    #[test]
    fn check_dll_detects_the_image_file_dll_characteristic() {
        const IMAGE_FILE_DLL: u16 = 0x2000;
        assert_eq!(
            check_dll(&dll_header(IMAGE_FILE_DLL)),
            RealFileType::WinExecutable
        );
    }

    #[test]
    fn check_dll_is_unknown_without_the_dll_characteristic() {
        // IMAGE_FILE_EXECUTABLE_IMAGE, not IMAGE_FILE_DLL -- a normal EXE's
        // flag, not a library's.
        assert_eq!(check_dll(&dll_header(0x0002)), RealFileType::Unknown);
    }

    #[test]
    fn check_dll_at_none_when_too_short_for_a_header() {
        assert_eq!(check_dll_at(&[0x4D, 0x5A], 0), None);
    }

    #[test]
    fn check_dll_at_none_without_the_mz_magic() {
        let mut contents = dll_header(0x2000);
        contents[0] = 0x00; // corrupt the MZ magic
        assert_eq!(check_dll_at(&contents, 0), None);
    }

    // --- ooxml_subtype -----------------------------------------------

    // The real files are ZIP archives; scan_for only needs the entry
    // *names* to be present as bytes somewhere in the file, not a real,
    // valid ZIP central directory -- same shortcut check_ooxml itself
    // already relies on.
    fn ooxml_bytes(marker: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x50, 0x4B, 0x03, 0x04]; // ZIP local file header
        bytes.extend_from_slice(b"[Content_Types].xml");
        bytes.extend_from_slice(marker);
        bytes
    }

    #[test]
    fn ooxml_subtype_detects_docx() {
        assert_eq!(
            ooxml_subtype(&ooxml_bytes(b"word/document.xml")),
            DocumentSubType::DOCX
        );
    }

    #[test]
    fn ooxml_subtype_detects_xlsx() {
        assert_eq!(
            ooxml_subtype(&ooxml_bytes(b"xl/workbook.xml")),
            DocumentSubType::XLSX
        );
    }

    #[test]
    fn ooxml_subtype_detects_pptx() {
        assert_eq!(
            ooxml_subtype(&ooxml_bytes(b"ppt/presentation.xml")),
            DocumentSubType::PPTX
        );
    }

    #[test]
    fn ooxml_subtype_falls_back_to_generic_when_unrecognized() {
        assert_eq!(
            ooxml_subtype(&ooxml_bytes(b"some/other/entry.xml")),
            DocumentSubType::OOXML
        );
    }

    #[test]
    fn identify_type_reports_docx_end_to_end() {
        // A .docx is a real ZIP archive underneath, so with identify_real_filetype
        // no longer short-circuiting on the first match, this legitimately
        // matches both check_ooxml and check_zip -- exactly the polyglot
        // detection issue #25 asked for.
        let mut result = result_for(ooxml_bytes(b"word/document.xml"));
        identify_real_filetype(&mut result);
        assert_eq!(
            result.file_info.file_type,
            vec![RealFileType::Document, RealFileType::Archive]
        );
        assert_eq!(
            result.file_info.file_sub_type,
            vec![
                RealFileSubType::Document(DocumentSubType::DOCX),
                RealFileSubType::Archive(ArchiveSubType::ZIP)
            ]
        );
    }

    // --- ole_cfb_subtype -----------------------------------------------
    // Builds a minimal but spec-correct CFB v3 container: 512-byte
    // header, one FAT sector, one directory sector holding a root entry
    // plus a single named stream entry. Real legacy Office files carry
    // far more (SummaryInformation, CompObj, etc.) but this is enough to
    // exercise the actual mechanism -- DIFAT lookup, FAT chain walk,
    // directory sector scan, UTF-16LE name decode -- rather than just
    // the magic bytes.
    fn cfb_with_stream(stream_name: &str) -> Vec<u8> {
        const SECTOR_SIZE: usize = 512;
        let mut bytes = vec![0u8; SECTOR_SIZE]; // header, filled in below

        // Signature.
        bytes[0..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
        // Major version 3, byte order mark, sector shift 9 (512), mini
        // sector shift 6 (64) -- offsets 26, 28, 30, 32.
        bytes[26..28].copy_from_slice(&3u16.to_le_bytes());
        bytes[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes());
        bytes[30..32].copy_from_slice(&9u16.to_le_bytes());
        bytes[32..34].copy_from_slice(&6u16.to_le_bytes());
        // Number of FAT sectors = 1 (offset 44).
        bytes[44..48].copy_from_slice(&1u32.to_le_bytes());
        // First directory sector location = sector 1 (offset 48).
        bytes[48..52].copy_from_slice(&1u32.to_le_bytes());
        // No mini FAT (offset 60/64) and no extra DIFAT sectors (offset
        // 68/72) -- everything fits in the header's own 109-entry DIFAT.
        bytes[60..64].copy_from_slice(&0xFFFFFFFEu32.to_le_bytes());
        bytes[68..72].copy_from_slice(&0xFFFFFFFEu32.to_le_bytes());
        // DIFAT[0] = sector 0 is the (only) FAT sector; the rest of the
        // 109-entry array is left as FREESECT (0xFFFFFFFF) via fill.
        bytes[76..76 + 436].fill(0xFF);
        bytes[76..80].copy_from_slice(&0u32.to_le_bytes());

        // Sector 0: the FAT itself (128 u32 entries). FAT[0] marks
        // itself as a FAT sector; FAT[1] (the directory sector) is a
        // single-sector chain, so it ends immediately.
        let mut fat_sector = vec![0xFFu8; SECTOR_SIZE]; // FREESECT-filled
        fat_sector[0..4].copy_from_slice(&0xFFFFFFFDu32.to_le_bytes()); // FATSECT
        fat_sector[4..8].copy_from_slice(&0xFFFFFFFEu32.to_le_bytes()); // ENDOFCHAIN
        bytes.extend_from_slice(&fat_sector);

        // Sector 1: the directory sector, four 128-byte entries. Entry 0
        // is the mandatory root entry; entry 1 is the named stream under
        // test; entries 2-3 stay unallocated (object type 0, from the
        // zero-fill).
        let mut dir_sector = vec![0u8; SECTOR_SIZE];
        write_dir_entry(&mut dir_sector[0..128], "Root Entry", 5);
        write_dir_entry(&mut dir_sector[128..256], stream_name, 2);
        bytes.extend_from_slice(&dir_sector);

        bytes
    }

    // Writes a directory entry's name (UTF-16LE, null-terminated) and
    // object type into a 128-byte entry slice. Sibling/child IDs and
    // starting sector are left as 0xFFFFFFFF (NOSTREAM/FREESECT) --
    // ole_cfb_subtype never dereferences them, it only reads names.
    fn write_dir_entry(entry: &mut [u8], name: &str, object_type: u8) {
        let utf16: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        for (i, unit) in utf16.iter().enumerate() {
            entry[i * 2..i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
        let name_len = (utf16.len() * 2) as u16;
        entry[64..66].copy_from_slice(&name_len.to_le_bytes());
        entry[66] = object_type;
        entry[68..84].fill(0xFF); // left/right sibling + child ID
    }

    #[test]
    fn ole_cfb_subtype_detects_doc_via_worddocument_stream() {
        assert_eq!(
            ole_cfb_subtype(&cfb_with_stream("WordDocument")),
            DocumentSubType::DOC
        );
    }

    #[test]
    fn ole_cfb_subtype_detects_xls_via_workbook_stream() {
        assert_eq!(
            ole_cfb_subtype(&cfb_with_stream("Workbook")),
            DocumentSubType::XLS
        );
    }

    #[test]
    fn ole_cfb_subtype_detects_xls_via_legacy_book_stream() {
        assert_eq!(
            ole_cfb_subtype(&cfb_with_stream("Book")),
            DocumentSubType::XLS
        );
    }

    #[test]
    fn ole_cfb_subtype_detects_ppt_via_powerpoint_document_stream() {
        assert_eq!(
            ole_cfb_subtype(&cfb_with_stream("PowerPoint Document")),
            DocumentSubType::PPT
        );
    }

    #[test]
    fn ole_cfb_subtype_falls_back_to_generic_for_unrecognized_stream() {
        // e.g. an MSI/MSG container, or any other CFB-based format this
        // doesn't specifically recognize.
        assert_eq!(
            ole_cfb_subtype(&cfb_with_stream("_SomeOtherStream")),
            DocumentSubType::OLECFB
        );
    }

    #[test]
    fn identify_type_reports_doc_end_to_end() {
        // cfb_with_stream's 0xFF-filled FREESECT padding happens to trip
        // check_mp3's frame-sync fallback (0xFF followed by a byte with its
        // top 3 bits set), which is the least reliable of the fallback scans
        // by design (see its own comment) -- a known false positive on this
        // synthetic fixture, not a real audio match.
        let mut result = result_for(cfb_with_stream("WordDocument"));
        identify_real_filetype(&mut result);
        assert_eq!(
            result.file_info.file_type,
            vec![RealFileType::Document, RealFileType::Audio]
        );
        assert_eq!(
            result.file_info.file_sub_type,
            vec![
                RealFileSubType::Document(DocumentSubType::DOC),
                RealFileSubType::Audio(AudioSubType::MP3)
            ]
        );
    }

    // --- ole_cfb_subtype robustness on malformed/adversarial input -----
    // This parses untrusted files, so corrupt/truncated/cyclic input
    // must fail closed (fall back to OLECFB) rather than panic or hang.

    #[test]
    fn ole_cfb_subtype_does_not_panic_on_bare_magic_with_no_header() {
        let sig = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        assert_eq!(ole_cfb_subtype(&sig), DocumentSubType::OLECFB);
    }

    #[test]
    fn ole_cfb_subtype_does_not_panic_on_truncated_header() {
        let mut contents = cfb_with_stream("WordDocument");
        contents.truncate(300); // cuts off mid-header, before the DIFAT
        assert_eq!(ole_cfb_subtype(&contents), DocumentSubType::OLECFB);
    }

    #[test]
    fn ole_cfb_subtype_does_not_panic_when_dir_sector_pointer_is_out_of_range() {
        let mut contents = cfb_with_stream("WordDocument");
        // First directory sector location (header offset 48) points far
        // past the end of the file.
        contents[48..52].copy_from_slice(&0xFFFFFFF0u32.to_le_bytes());
        assert_eq!(ole_cfb_subtype(&contents), DocumentSubType::OLECFB);
    }

    #[test]
    fn ole_cfb_subtype_does_not_hang_on_a_self_referential_fat_chain() {
        let mut contents = cfb_with_stream("WordDocument");
        // Point the directory chain's FAT entry (FAT[1], inside sector 0
        // at header offset 512 + 4) back at itself instead of
        // ENDOFCHAIN.
        let self_ref_offset = 512 + 4;
        contents[self_ref_offset..self_ref_offset + 4].copy_from_slice(&1u32.to_le_bytes());
        // Just needs to return, not necessarily any particular value --
        // the point is the cycle guard actually stops the walk.
        let _ = ole_cfb_subtype(&contents);
    }

    #[test]
    fn ole_cfb_subtype_falls_back_for_v4_sector_shift() {
        let mut contents = cfb_with_stream("WordDocument");
        contents[30..32].copy_from_slice(&12u16.to_le_bytes()); // 4096-byte sectors
        assert_eq!(ole_cfb_subtype(&contents), DocumentSubType::OLECFB);
    }
}
