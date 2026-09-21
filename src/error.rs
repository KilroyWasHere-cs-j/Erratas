use std::fmt;

#[derive(Debug)]
pub enum ErratasError {
    Io(std::io::Error),
    ContentsTooShort,
    FileNotFound,
    YaraCompile(yara_x::errors::CompileError),
}

impl fmt::Display for ErratasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErratasError::Io(e) => write!(f, "io error: {e}"),
            ErratasError::ContentsTooShort => write!(f, "contents too short"),
            ErratasError::FileNotFound => write!(f, "file not found"),
            ErratasError::YaraCompile(e) => write!(f, "yara rule compile error: {e}"),
        }
    }
}

impl std::error::Error for ErratasError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ErratasError::Io(e) => Some(e),
            ErratasError::YaraCompile(e) => Some(e),
            _ => None,
        }
    }
}

// Lets `?` on a std::io::Error auto-convert into ErratasError (used in lib.rs's load_file).
impl From<std::io::Error> for ErratasError {
    fn from(e: std::io::Error) -> Self {
        ErratasError::Io(e)
    }
}

// Lets `?` on a yara_x::Compiler::add_source() call auto-convert into ErratasError
// (used in malware.rs's build_yara_rules).
impl From<yara_x::errors::CompileError> for ErratasError {
    fn from(e: yara_x::errors::CompileError) -> Self {
        ErratasError::YaraCompile(e)
    }
}

