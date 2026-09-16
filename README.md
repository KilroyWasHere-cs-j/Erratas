# Erratas

A standalone file-auditing engine, built as a CLI binary so any tool in
any language can call it via subprocess rather than linking it in as a
library. Originally split out to replace the ad-hoc validation checks in
[Dewey](https://github.com/KilroyWasHere-cs-j/Dewey)'s file uploader, but
meant to be reused across other tools too.

## What it checks

Every file audit runs two independent sets of checks:

- **Malware** — known-bad signature matching, YARA rule matching, and
  archive structure checks (compression-ratio / nesting-depth limits, to
  catch zip-bomb-style abuse before fully decompressing anything).
- **Content** — simple regex/word-list pattern matching for PII (SSN,
  credit card, email, phone) and profanity. No NLP — deliberately kept to
  cheap pattern matching for now.

## Why a separate process instead of a library

Malware scanning means parsing untrusted, adversarial bytes. A bug in
that code should crash an isolated subprocess, not the application that
called it — which is the same reason most AV/content-scanning engines
run as their own process rather than linking in as a library. It also
means Erratas ships and updates independently of whatever's calling it.

## Status

Scaffolding only right now — the module layout and type signatures are
in place, but every actual check (`src/malware.rs`, `src/content.rs`) is
a `todo!()`. Nothing here works yet.

## Layout

```
src/
  main.rs      CLI entry point — takes a file path, calls into the lib
  lib.rs       audit_file() ties malware + content checks together
  malware.rs   signature / YARA / archive-structure checks
  content.rs   PII / profanity pattern checks
```

Binary and library live in the same Cargo package (`main.rs` links to
the lib via the package's own name) — no workspace split needed yet.

## Usage

```bash
cargo run -- <file>
```

## TODO

**Core checks** (each is a `todo!()` right now):
- [ ] `malware::scan_signatures` — known-bad hash/signature lookup; needs a maintained signature database/source
- [ ] `malware::scan_yara_rules` — integrate the `yara-rust` crate (bindings to libyara), load a compiled ruleset
- [ ] `malware::check_archive_structure` — compression-ratio and nesting-depth checks on archive headers, before decompressing
- [ ] `content::scan_pii` — regex patterns for SSN, credit card, email, phone
- [ ] `content::scan_profanity` — word-list matching
- [ ] `lib::audit_file` — read the file once and wire it up to `malware::scan` + `content::scan`

**Plumbing:**
- [ ] Pick and pin exact crate versions (`yara-rust`, `regex`, a zip-parsing crate) — needs a typosquatting check before anything goes in `Cargo.toml`
- [ ] `main.rs` — output the `AuditReport` as JSON on stdout instead of `{:#?}`, so other tools can parse it over a subprocess call
- [ ] Decide whether a daemon mode (warm process behind a socket) is worth adding on top of the CLI, or if per-call startup cost is fine
- [ ] Tests for each check, once they exist
- [ ] CI (build + test on push)

**Open decisions:**
- [ ] Where this plugs into Dewey — on the synchronous upload path (blocks the request) or the async post-upload pipeline (`idAndSort`) — not decided yet
- [ ] GitHub remote — this repo is currently local-only
