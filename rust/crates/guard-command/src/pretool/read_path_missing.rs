//! Whether a shell read of an absolute path with nothing at it is bounded.

use super::resolved_path_allowed_for_operation;

/// `path` with its deepest existing ancestor canonicalized and the missing
/// components appended, the spelling the kernel would walk.
///
/// `std::fs::canonicalize` fails outright on a missing component, so a path
/// with nothing at it has no resolved form for the location screens to read.
fn weak_canonical_path(path: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut missing: Vec<&std::ffi::OsStr> = Vec::new();
    let mut prefix = path;
    loop {
        if let Ok(mut resolved) = std::fs::canonicalize(prefix) {
            resolved.extend(missing.iter().rev());
            return Some(resolved);
        }
        missing.push(prefix.file_name()?);
        prefix = prefix.parent()?;
    }
}

/// A shell read of an absolute path with no file at it.
///
/// The open fails with `ENOENT`, so the read returns nobody's bytes, and the
/// workspace-relative spelling of the same unresolvable path already passes
/// its own lexical floor. The path the kernel would walk still takes every
/// screen an existing file takes, so a missing name inside a credential
/// store or another guarded location keeps its review rather than answering
/// whether it is there.
pub(super) fn missing_absolute_read_allowed(
    path: &std::path::Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    weak_canonical_path(path).is_some_and(|resolved| {
        std::fs::symlink_metadata(&resolved).is_err()
            && resolved_path_allowed_for_operation(&resolved, home_dir, cwd, false, true)
    })
}

#[cfg(test)]
mod tests {
    use super::{missing_absolute_read_allowed, weak_canonical_path};
    use std::path::{Path, PathBuf};

    /// A home with a workspace below it, under a temporary root whose name is
    /// visible: a hidden component of its own would fail a different screen.
    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::Builder::new()
            .prefix("guard-missing-read")
            .tempdir()
            .expect("temporary directory");
        let home = std::fs::canonicalize(root.path()).expect("canonical root");
        let workspace = home.join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        (root, home, workspace)
    }

    #[test]
    fn resolves_the_existing_prefix_of_a_missing_path() {
        let (_root, _home, workspace) = fixture();
        let target = workspace.join("absent").join("notes.md");
        let resolved = weak_canonical_path(&target).expect("weak canonical path");
        assert_eq!(resolved, workspace.join("absent").join("notes.md"));
        assert_eq!(weak_canonical_path(&workspace), Some(workspace.clone()));
    }

    #[test]
    fn admits_a_missing_absolute_path_inside_the_workspace() {
        let (_root, home, workspace) = fixture();
        assert!(missing_absolute_read_allowed(
            &workspace.join("absent-notes.md"),
            home.to_str(),
            workspace.to_str()
        ));
        assert!(missing_absolute_read_allowed(
            &workspace.join("absent").join("notes.md"),
            home.to_str(),
            workspace.to_str()
        ));
    }

    #[test]
    fn refuses_a_file_that_is_there_and_a_guarded_location() {
        let (_root, home, workspace) = fixture();
        let present = workspace.join("present.md");
        std::fs::write(&present, "notes").expect("write");
        assert!(!missing_absolute_read_allowed(
            &present,
            home.to_str(),
            workspace.to_str()
        ));
        assert!(!missing_absolute_read_allowed(
            &workspace.join("secrets").join("absent.txt"),
            home.to_str(),
            workspace.to_str()
        ));
        assert!(!missing_absolute_read_allowed(
            Path::new("/etc/absent-9183.conf"),
            home.to_str(),
            workspace.to_str()
        ));
    }
}
