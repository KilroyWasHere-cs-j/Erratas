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
pub enum RealFileSubType {
    PNG,
    JPEG,
    GIF,
    ELF,
    PE,
    MachO,
    DLL,
    SO,
    LNK,
    DMG,
    ISO,
    PDF,
    OLECFB,
    CHM,
    BMP,
    WEBP,
    WAV,
    FLAC,
    OGG,
    MP3,
    MP4,
    WEBM,
    AVI,
    RAR,
    ZIP,
    SevenZ,
    CAB,
    TAR,
    OOXML,
    Unknown
}

pub struct ErratasResult {
    pub flags: Vec<ErratasContentFlag>,
    pub file_type: RealFileType,
    pub file_sub_type: RealFileSubType
}
