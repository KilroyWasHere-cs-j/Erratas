#[derive(Debug)]
pub enum ErratasError {}

#[derive(Debug)]
pub enum ErratasResult {
    AllGood,
    PII,
    Malware,
    Archive,
    ZipBomb,
    HashMatching,
    YARA,
    Profanity
}


