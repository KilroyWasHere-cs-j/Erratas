use std::fmt;

#[derive(Debug)]
pub struct FileInfo {
    pub contents: Vec<u8>,
    pub content_flag: ErratasContentFlag,
    pub bad_language: bool,
    pub file_type: RealFileType,
    pub file_sub_type: RealFileSubType,
}

#[derive(Debug)]
pub struct ErratasJob {
    pub file_info: FileInfo,
    //pub yara_results: Vec<String>,
}

#[derive(Debug)]
pub enum ErratasContentFlag {
    AllGood,
    BandedFileType,
    PII,
    Malware,
    Archive,
    ZipBomb,
    HashMatching,
    YARA,
    Profanity,
    Scanning,
    Unknown,
}

#[derive(Debug, PartialEq)]
pub enum UnknownSubType {
    Unknown,
}

#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
pub enum ImageSubType {
    PNG,
    JPEG,
    GIF,
    BMP,
    WEBP,
}

#[derive(Debug, PartialEq)]
pub enum VideoSubType {
    MP4,
    WEBM,
    AVI,
}

#[derive(Debug, PartialEq)]
pub enum AudioSubType {
    WAV,
    FLAC,
    OGG,
    MP3,
}

#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
pub enum ArchiveSubType {
    ZIP,
    TAR,
    RAR,
    SEVENZ,
    CAB,
    DMG,
    ISO,
}

#[derive(Debug, PartialEq)]
pub enum ExecutableSubType {
    ELF,
    PE,
    MachO,
    DLL,
    SO,
    LNK,
}

#[derive(Debug, PartialEq)]
pub enum RealFileSubType {
    Unknown(UnknownSubType),
    Image(ImageSubType),
    Video(VideoSubType),
    Audio(AudioSubType),
    Document(DocumentSubType),
    Archive(ArchiveSubType),
    Executable(ExecutableSubType),
}

// Deliberately doesn't print `contents` -- that's the raw file bytes,
// and dumping those inline is exactly what made {:?}-printing a
// FileInfo (or anything containing one) unreadable for anything but a
// tiny file.
impl fmt::Display for FileInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}), {} bytes, flag: {}, bad language: {}",
            self.file_type,
            self.file_sub_type,
            self.contents.len(),
            self.content_flag,
            self.bad_language
        )
    }
}

impl fmt::Display for ErratasJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.file_info)
    }
}

impl fmt::Display for ErratasContentFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            ErratasContentFlag::AllGood => "all good",
            ErratasContentFlag::BandedFileType => "banded file type",
            ErratasContentFlag::PII => "PII",
            ErratasContentFlag::Malware => "malware",
            ErratasContentFlag::Archive => "archive",
            ErratasContentFlag::ZipBomb => "zip bomb",
            ErratasContentFlag::HashMatching => "hash matching",
            ErratasContentFlag::YARA => "YARA",
            ErratasContentFlag::Profanity => "profanity",
            ErratasContentFlag::Scanning => "scanning",
            ErratasContentFlag::Unknown => "unknown",
        };
        write!(f, "{label}")
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
