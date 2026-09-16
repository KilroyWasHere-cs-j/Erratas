//! Content-side checks: simple pattern/word-list matching for PII and
//! profanity — no NLP, just regex/word-list lookups.

/// Result of running every content check against one file.
#[derive(Debug, Default)]
pub struct ContentReport {
    pub pii_hits: Vec<PiiHit>,
    pub profanity_hits: Vec<String>,
}

/// One PII pattern match — the kind of pattern found, not the matched
/// text itself, so callers don't have to handle sensitive data just to
/// read the report.
#[derive(Debug)]
pub struct PiiHit {
    pub kind: PiiKind,
    pub count: u32,
}

#[derive(Debug)]
pub enum PiiKind {
    Ssn,
    CreditCard,
    Email,
    Phone,
}

/// Runs every content check against `text` and returns the combined
/// report.
pub fn scan(text: &str) -> ContentReport {
    // TODO: call scan_pii / scan_profanity and fold their results into
    // one ContentReport.
    let _ = text;
    todo!("wire scan up to the individual content checks below")
}

/// Scans `text` for PII patterns (SSN, credit card, email, phone) via
/// regex matching.
pub fn scan_pii(text: &str) -> Vec<PiiHit> {
    // TODO: run one regex per PiiKind over text and count matches.
    let _ = text;
    todo!()
}

/// Scans `text` against a profanity word list.
pub fn scan_profanity(text: &str) -> Vec<String> {
    // TODO: tokenize text and check each token against a maintained
    // word list.
    let _ = text;
    todo!()
}
