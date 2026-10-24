//! Rust port of the filesystem half of `guard/skill_document_evidence.py`.
//!
//! A primary skill document is read once, under a ceiling, through a
//! descriptor that refuses to follow a symlink. What comes back describes the
//! document — its size, hash, shape and any network capability its prose
//! documents — and never its content. The text analysis itself lives in
//! `guard_command::skill_document_text_evidence`, where the parity vectors
//! pin it.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use guard_command::skill_document_text_evidence::analyze_skill_document_text;
use guard_contracts::{SkillDocumentEvidenceV1, SkillDocumentReadabilityV1};

/// Analysis ceiling, shared with the scanner that used to do this in Python.
pub(crate) const MAX_SKILL_DOCUMENT_BYTES: usize = 256 * 1024;

fn stopped(status: SkillDocumentReadabilityV1) -> SkillDocumentEvidenceV1 {
    SkillDocumentEvidenceV1 {
        readability_status: status,
        byte_length: None,
        content_hash: None,
        line_count: None,
        heading_count: None,
        frontmatter_present: None,
        documented_network_capability: None,
    }
}

fn stopped_with_size(
    status: SkillDocumentReadabilityV1,
    byte_length: u64,
) -> SkillDocumentEvidenceV1 {
    SkillDocumentEvidenceV1 {
        byte_length: Some(byte_length),
        ..stopped(status)
    }
}

/// Anchor a relative path to the caller's directory, the way the caller's own
/// filesystem calls would have resolved it. Absolute paths are untouched, and
/// no normalization happens here.
fn anchor(path: &Path, process_directory: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        process_directory.join(path)
    }
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}

fn component_name_is(path: &Path, expected: &str) -> bool {
    path.file_name()
        .is_some_and(|name| name.to_string_lossy().to_lowercase() == expected)
}

/// The nearest ancestor directory named `skills`.
fn skills_root(document: &Path) -> Option<&Path> {
    document
        .ancestors()
        .skip(1)
        .find(|parent| component_name_is(parent, "skills"))
}

/// Whether the walk from the `skills` root down to the document crosses a
/// symlink, or leaves the root entirely.
fn crosses_a_symlink(document: &Path, root: &Path, process_directory: &Path) -> bool {
    let Ok(relative) = document.strip_prefix(root) else {
        return true;
    };
    let mut current = anchor(root, process_directory);
    if is_symlink(&current) {
        return true;
    }
    for part in relative.components() {
        current.push(part);
        if is_symlink(&current) {
            return true;
        }
    }
    false
}

/// Read one primary skill document's bounded evidence.
pub(crate) fn read_skill_document_evidence(
    document: &Path,
    process_directory: &Path,
    safe_roots: &[PathBuf],
) -> SkillDocumentEvidenceV1 {
    if !component_name_is(document, "skill.md") {
        return stopped(SkillDocumentReadabilityV1::NotPrimarySkillDocument);
    }
    let Some(root) = skills_root(document) else {
        return stopped(SkillDocumentReadabilityV1::NotPrimarySkillDocument);
    };
    let Ok(relative) = document.strip_prefix(root) else {
        return stopped(SkillDocumentReadabilityV1::NotPrimarySkillDocument);
    };
    // A document directly under the root has no skill directory of its own.
    if relative.components().count() < 2 {
        return stopped(SkillDocumentReadabilityV1::NotPrimarySkillDocument);
    }
    let anchored = anchor(document, process_directory);
    if crosses_a_symlink(document, root, process_directory) || is_symlink(&anchored) {
        return stopped(SkillDocumentReadabilityV1::SymlinkRejected);
    }
    let Ok(resolved) = fs::canonicalize(&anchored) else {
        return stopped(SkillDocumentReadabilityV1::Unreadable);
    };
    let Ok(resolved_root) = fs::canonicalize(anchor(root, process_directory)) else {
        return stopped(SkillDocumentReadabilityV1::Unreadable);
    };
    let within_a_safe_root = safe_roots
        .iter()
        .filter_map(|root| fs::canonicalize(anchor(root, process_directory)).ok())
        .any(|root| resolved_root.starts_with(root));
    if !within_a_safe_root {
        return stopped(SkillDocumentReadabilityV1::OutsideSafeRoots);
    }
    read_resolved_document(&resolved)
}

/// Open the already-resolved path and read it under the ceiling.
///
/// The path holds no symlink of its own, so `O_NOFOLLOW` here only closes the
/// window between resolving and opening.
fn read_resolved_document(resolved: &Path) -> SkillDocumentEvidenceV1 {
    let Ok(mut file) = open_without_following(resolved) else {
        return stopped(SkillDocumentReadabilityV1::Unreadable);
    };
    let Ok(metadata) = file.metadata() else {
        return stopped(SkillDocumentReadabilityV1::Unreadable);
    };
    let byte_length = metadata.len();
    if !metadata.is_file() {
        return stopped_with_size(SkillDocumentReadabilityV1::NotRegularFile, byte_length);
    }
    if byte_length > MAX_SKILL_DOCUMENT_BYTES as u64 {
        return stopped_with_size(SkillDocumentReadabilityV1::TooLarge, byte_length);
    }
    let mut content = Vec::new();
    if file
        .by_ref()
        .take(MAX_SKILL_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut content)
        .is_err()
    {
        // The size is already known, so a failed read reports it the way a
        // failed check below would.
        return stopped_with_size(SkillDocumentReadabilityV1::Unreadable, byte_length);
    }
    // A file that grew between the stat and the read is over the ceiling too.
    if content.len() > MAX_SKILL_DOCUMENT_BYTES {
        return stopped_with_size(SkillDocumentReadabilityV1::TooLarge, content.len() as u64);
    }
    let Ok(text) = std::str::from_utf8(&content) else {
        return stopped_with_size(SkillDocumentReadabilityV1::InvalidUtf8, byte_length);
    };
    let evidence = analyze_skill_document_text(text);
    SkillDocumentEvidenceV1 {
        readability_status: SkillDocumentReadabilityV1::Readable,
        byte_length: Some(byte_length),
        content_hash: Some(format!(
            "sha256:{}",
            guard_policy_snapshot::digest_bytes(&content)
        )),
        line_count: Some(evidence.line_count as u64),
        heading_count: Some(evidence.heading_count as u64),
        frontmatter_present: Some(evidence.frontmatter_present),
        documented_network_capability: evidence.documented_network_capability.map(str::to_owned),
    }
}

#[cfg(unix)]
fn open_without_following(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_without_following(path: &Path) -> std::io::Result<fs::File> {
    // Windows has no `O_NOFOLLOW`; the Python scanner fell back the same way,
    // and the path was already resolved and walked for symlinks above.
    fs::File::open(path)
}

#[cfg(all(test, unix))]
#[path = "skill_document_evidence_tests.rs"]
mod tests;
