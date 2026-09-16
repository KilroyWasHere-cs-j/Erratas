//! Erratas — a standalone file-auditing engine.
//!
//! Given a file, reports back on two independent axes: whether it looks
//! malicious (`malware`) and whether its content trips any policy checks
//! (`content`). Meant to be called as a CLI from any language/tool, not
//! linked in as a library — see main.rs for the entry point.

pub mod malware;
pub mod content;

/// The combined result of auditing one file — every check runs and
/// reports independently, rather than short-circuiting on the first hit,
/// so a caller can see the full picture in one pass.
#[derive(Debug, Default)]
pub struct AuditReport {
    pub malware: malware::MalwareReport,
    pub content: content::ContentReport,
}

/// Runs every malware and content check against the file at `path` and
/// returns the combined report.
pub fn audit_file(path: &std::path::Path) -> std::io::Result<AuditReport> {
    // TODO: read the file once (or stream it) and hand the bytes/reader to
    // both malware::scan and content::scan rather than re-reading per check.
    let _ = path;
    todo!("wire audit_file up to malware::scan and content::scan")
}
