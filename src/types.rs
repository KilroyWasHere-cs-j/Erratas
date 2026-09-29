use std::fmt::{self, write};
use std::ops::Range;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct FileInfo {
    pub contents: Vec<u8>,
    pub bad_language: bool,
    pub pii: bool,
    pub malware: bool,
    pub strike3: Vec<String>,
    pub hashmatches: Vec<String>,
    pub yara_finds: Vec<RuleHit>,
    pub file_type: Vec<RealFileType>,
    pub file_sub_type: Vec<RealFileSubType>,
}

#[derive(Debug, Serialize)]
pub struct ErratasJob {
    pub file_info: FileInfo,
    //pub yara_results: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize)]
pub enum UnknownSubType {
    Unknown,
}

#[derive(Debug, PartialEq, Serialize)]
pub enum RealFileType {
    Image,
    Video,
    Audio,
    Document,
    Archive,
    WinExecutable,
    MacExecutable,
    LinuxExecutable,
    Unknown,
}

#[derive(Debug, PartialEq, Serialize)]
pub enum ImageSubType {
    PNG,
    JPEG,
    GIF,
    BMP,
    WEBP,
    TIFF,
}

#[derive(Debug, PartialEq, Serialize)]
pub enum VideoSubType {
    MP4,
    WEBM,
    AVI,
}

#[derive(Debug, PartialEq, Serialize)]
pub enum AudioSubType {
    WAV,
    FLAC,
    OGG,
    MP3,
}

#[derive(Debug, PartialEq, Serialize)]
pub enum DocumentSubType {
    DOC,
    DOCX,
    XLS,
    XLSX,
    PPT,
    PPTX,
    PDF,
    OOXML,
    OLECFB,
    CHM,
}

#[derive(Debug, PartialEq, Serialize)]
pub enum ArchiveSubType {
    ZIP,
    TAR,
    RAR,
    SEVENZ,
    CAB,
    DMG,
    ISO,
}

#[derive(Debug, PartialEq, Serialize)]
pub enum ExecutableSubType {
    ELF,
    PE,
    MachO,
    DLL,
    SO,
    LNK,
}

#[derive(Debug, PartialEq, Serialize)]
pub enum RealFileSubType {
    Unknown(UnknownSubType),
    Image(ImageSubType),
    Video(VideoSubType),
    Audio(AudioSubType),
    Document(DocumentSubType),
    Archive(ArchiveSubType),
    Executable(ExecutableSubType),
}

// Owned result types: no borrows from Scanner/Rules, so these can be
// returned, stored, or serialized after the scan is gone.
#[derive(Debug, Serialize)]
pub struct RuleHit {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub description: Option<String>,
    pub severity: Severity,
    pub targets: Vec<String>,
    pub strings: Vec<StringHit>,
}

#[derive(Debug, Serialize)]
pub struct StringHit {
    pub id: String,           // e.g. "$dl"
    pub offset: Range<usize>, // where in the file it matched
    pub preview: String,      // matched bytes, lossy UTF-8, trimmed
}

// Turning the free-text severity into an enum means a typo in a rule
// ("hihg") shows up as Unknown instead of silently passing through.
#[derive(Debug, Serialize, PartialEq, PartialOrd)]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => Self::Unknown,
        }
    }
}

// Deliberately doesn't print `contents` -- that's the raw file bytes,
// and dumping those inline is exactly what made {:?}-printing a
// FileInfo (or anything containing one) unreadable for anything but a
// tiny file.
impl fmt::Display for FileInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let file_types = self
            .file_type
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let file_sub_types = self
            .file_sub_type
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        write!(
            f,
            "{} ({}), {} bytes, PII: {}, malware: {}, hash matches: {}, YARA finds: {}, bad language: {}, strike3: {}\n yara rule hits: {:?}",
            file_types,
            file_sub_types,
            self.contents.len(),
            self.pii,
            self.malware,
            self.hashmatches.len(),
            self.yara_finds.len(),
            self.bad_language,
            self.strike3.join(", "),
            self.yara_finds
        )
    }
}

impl fmt::Display for ErratasJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.file_info)
    }
}

impl fmt::Display for RealFileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            RealFileType::Image => "image",
            RealFileType::Video => "video",
            RealFileType::Audio => "audio",
            RealFileType::Document => "document",
            RealFileType::Archive => "archive",
            RealFileType::WinExecutable => "Windows executable",
            RealFileType::MacExecutable => "macOS executable",
            RealFileType::LinuxExecutable => "Linux executable",
            RealFileType::Unknown => "unknown",
        };
        write!(f, "{label}")
    }
}

impl fmt::Display for RealFileSubType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RealFileSubType::Unknown(sub) => write!(f, "{sub}"),
            RealFileSubType::Image(sub) => write!(f, "{sub}"),
            RealFileSubType::Video(sub) => write!(f, "{sub}"),
            RealFileSubType::Audio(sub) => write!(f, "{sub}"),
            RealFileSubType::Document(sub) => write!(f, "{sub}"),
            RealFileSubType::Archive(sub) => write!(f, "{sub}"),
            RealFileSubType::Executable(sub) => write!(f, "{sub}"),
        }
    }
}

// These leaf sub-type enums are already just file-extension-style
// abbreviations (PNG, MP4, ZIP, ...) -- their Debug output is already
// exactly the right Display text, so there's no separate label to
// maintain in parallel.
impl fmt::Display for UnknownSubType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for ImageSubType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for VideoSubType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for AudioSubType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for DocumentSubType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for ArchiveSubType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for ExecutableSubType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
