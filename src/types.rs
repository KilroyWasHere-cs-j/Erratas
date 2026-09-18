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
    Unknown
}

#[derive(Debug, PartialEq)]
pub enum UnknownSubType {
    Unknown
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
    Unknown
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

#[derive(Debug)]
pub struct ErratasResult {
    pub flags: Vec<ErratasContentFlag>,
    pub file_type: RealFileType,
    pub file_sub_type: RealFileSubType
}
