//! Syntax of a read-only fan-out over a Git name listing:
//! `git ls-files ... | xargs CHILD` and `git diff --name-only ... | xargs CHILD`.
//!
//! `read_only_fanout` models the `find` producer, and requires the NUL
//! separator there: a file named `x /abs/secret` splits into two words, so an
//! unseparated `find | xargs cat` would read a path nobody listed. Agents
//! almost never write the NUL spelling for a Git listing. `git ls-files
//! '*.rs' | xargs wc -l` and `git diff --name-only | xargs ls -la` are the
//! shapes they reach for, several times a session.
//!
//! This module admits the unseparated spelling, and pays for the split
//! another way: by bounding the child instead of the separator. Only `wc`,
//! `ls`, `stat` and `echo` are recognized. A crafted name therefore discloses
//! a path's existence, size, mode, timestamp or line count, never a byte of
//! its contents, and `xargs` hands the words to no shell. A reader of
//! contents (`cat`, `head`, `tail`, `grep`, `rg`, `od`) keeps the uncertain
//! model for these producers, because the same split hands it a secret.
//!
//! The producer prints names the working tree holds, so the child's operands
//! resolve inside the workspace unless a pathspec leaves it. Every operand is
//! therefore a relative word with no `..` component and no pathspec magic, and
//! the options are the ones that only choose which names get printed. The
//! pre-tool proof (`pretool::fanout_reads`) still requires a verified
//! workspace session and the child's own read-only proof.

use crate::parser_executables::executable_basename;
use crate::read_only_fanout::{without_stderr_merge, xargs_options, Xargs};
use crate::CommandSegmentV1;

/// Stand-in operand the child proof reads in place of the printed names.
pub(crate) const NAME_PLACEHOLDER: &str = "guard-name-fanout-result";

/// Children that report a path's metadata and never its contents.
const METADATA_ONLY: [&str; 4] = ["echo", "ls", "stat", "wc"];

/// Operands worth reading at all; a longer pathspec list keeps the old model.
const MAX_OPERANDS: usize = 16;

/// `git ls-files` options that only choose which tracked names get printed.
const LS_FILES_OPTIONS: [&str; 10] = [
    "--cached",
    "--deleted",
    "--exclude-standard",
    "--modified",
    "--others",
    "-c",
    "-d",
    "-m",
    "-o",
    "-z",
];

/// `git diff` options that only choose which changed names get printed.
const DIFF_OPTIONS: [&str; 6] = [
    "--cached",
    "--name-only",
    "--relative",
    "--staged",
    "-z",
    "--no-renames",
];

/// A pathspec or revision that cannot make the listing name a path outside
/// the directory the listing prints relative to. A revision range such as
/// `main..HEAD` holds `..` without holding it as a path component.
fn listing_operand(word: &str) -> bool {
    !word.is_empty()
        && !word.starts_with(['/', '~', ':', '\\', '-'])
        && !word.contains('\\')
        && word.split('/').all(|part| part != "..")
}

fn listing_word(word: &str, options: &[&str]) -> bool {
    if word == "--" {
        return true;
    }
    if word.starts_with('-') {
        return options.contains(&word)
            || word.strip_prefix("--diff-filter=").is_some_and(|value| {
                !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_alphabetic())
            });
    }
    listing_operand(word)
}

/// `git ls-files ...` or `git diff --name-only ...` with nothing but the
/// options and operands that choose which names get printed.
pub(crate) fn git_name_listing(segment: &CommandSegmentV1) -> bool {
    if !segment.environment_names.is_empty()
        || !segment.wrapper_chain.is_empty()
        || segment.path_overridden
        || segment.executable.as_deref() != Some("git")
    {
        return false;
    }
    let arguments = without_stderr_merge(&segment.arguments);
    let Some((subcommand, rest)) = arguments.split_first() else {
        return false;
    };
    let options: &[&str] = match subcommand.as_str() {
        "ls-files" => &LS_FILES_OPTIONS,
        // `git diff` prints a patch unless `--name-only` asks for the names.
        "diff" if rest.iter().any(|argument| argument == "--name-only") => &DIFF_OPTIONS,
        _ => return false,
    };
    rest.len() <= MAX_OPERANDS && rest.iter().all(|word| listing_word(word, options))
}

/// Whether the child only reports a path's metadata.
fn metadata_child(child: &[String]) -> bool {
    child.first().is_some_and(|name| {
        !name.contains(['/', '\\']) && METADATA_ONLY.contains(&executable_basename(name))
    })
}

/// `xargs [-0] [-r] [-n N] [-P N] CHILD ARGS` with a metadata-only child.
pub(crate) fn xargs_names(arguments: &[String]) -> Option<Xargs<'_>> {
    xargs_options(arguments).filter(|xargs| metadata_child(xargs.child))
}

/// A `xargs` segment fed directly by a Git name listing of the same pipeline.
pub(crate) fn xargs_follows_names(
    previous: &CommandSegmentV1,
    pipeline_index: usize,
    execution_context: &str,
    arguments: &[String],
) -> bool {
    previous.pipeline_index + 1 == pipeline_index
        && previous.execution_context == execution_context
        && git_name_listing(previous)
        && xargs_names(arguments).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn producer(values: &[&str]) -> CommandSegmentV1 {
        let tokens = args(values);
        CommandSegmentV1 {
            text: tokens.join(" "),
            executable: tokens.first().cloned(),
            arguments: tokens[1..].to_vec(),
            tokens,
            environment_names: Vec::new(),
            wrapper_chain: Vec::new(),
            path_overridden: false,
            execution_context: "top:0".to_owned(),
            pipeline_index: 0,
            span: crate::CommandSpanV1 {
                source: "normalized".to_owned(),
                start: 0,
                end: 1,
            },
        }
    }

    #[test]
    fn accepts_the_listings_agents_write() {
        assert!(git_name_listing(&producer(&["git", "ls-files"])));
        assert!(git_name_listing(&producer(&["git", "ls-files", "*.rs"])));
        assert!(git_name_listing(&producer(&[
            "git", "ls-files", "-z", "--", "src"
        ])));
        assert!(git_name_listing(&producer(&["git", "diff", "--name-only"])));
        assert!(git_name_listing(&producer(&[
            "git",
            "diff",
            "--name-only",
            "--cached",
            "main..HEAD"
        ])));
    }

    #[test]
    fn refuses_a_listing_that_can_name_another_tree() {
        assert!(!git_name_listing(&producer(&["git", "ls-files", "../src"])));
        assert!(!git_name_listing(&producer(&["git", "ls-files", "/etc"])));
        assert!(!git_name_listing(&producer(&[
            "git",
            "ls-files",
            ":(top)src"
        ])));
        assert!(!git_name_listing(&producer(&[
            "git",
            "ls-files",
            "--exec-path=/tmp/x"
        ])));
        // A patch is not a name listing.
        assert!(!git_name_listing(&producer(&["git", "diff"])));
        assert!(!git_name_listing(&producer(&["git", "log", "--name-only"])));
    }

    #[test]
    fn accepts_only_a_metadata_child() {
        assert!(xargs_names(&args(&["wc", "-l"])).is_some());
        assert!(xargs_names(&args(&["-n1", "echo"])).is_some());
        assert!(xargs_names(&args(&["ls", "-la"])).is_some());
        assert!(xargs_names(&args(&["stat"])).is_some());
        assert!(xargs_names(&args(&["cat"])).is_none());
        assert!(xargs_names(&args(&["grep", "-n", "x"])).is_none());
        assert!(xargs_names(&args(&["-I{}", "wc", "-l", "{}"])).is_none());
        assert!(xargs_names(&args(&["/usr/bin/wc", "-l"])).is_none());
    }

    #[test]
    fn pairs_only_with_the_next_stage_of_the_same_pipeline() {
        let listing = producer(&["git", "ls-files"]);
        let child = args(&["wc", "-l"]);
        assert!(xargs_follows_names(&listing, 1, "top:0", &child));
        assert!(!xargs_follows_names(&listing, 2, "top:0", &child));
        assert!(!xargs_follows_names(&listing, 1, "top:1", &child));
    }
}
