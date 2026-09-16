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
