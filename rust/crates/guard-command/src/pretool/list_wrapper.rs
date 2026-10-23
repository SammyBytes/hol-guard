//! A leading `!` and a trailing `&` wrap a command list without changing
//! which commands it runs: `!` inverts the list's exit status and `&` runs
//! it in the background. Neither adds a program, a redirect or a word to any
//! command, so the wrapped list's commands are the unwrapped list's and the
//! ordinary proofs can decide them. Anything this recognizer does not fully
//! understand returns `None`, which keeps the existing review behavior.

use super::script_content::foreground_job;

const MAX_COMMAND_BYTES: usize = 8192;

/// The command list a `!`-negated or `&`-backgrounded command runs, or `None`
/// when the command carries neither wrapper or the text is not understood.
pub(crate) fn unwrapped(command: &str) -> Option<String> {
    let command = command.trim();
    if command.len() > MAX_COMMAND_BYTES
        || command.contains("<<")
        || command
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return None;
    }
    let foreground = foreground_job(command).map_or(command, str::trim);
    let unnegated = unnegated(foreground).unwrap_or(foreground);
    (unnegated != command).then(|| unnegated.to_owned())
}

/// The list a leading `!` negates. `!` is a reserved word only as the first
/// word of the list, so it has to stand alone: the text after it is a list in
/// its own right, and a second `!` is not a list this recognizer models.
fn unnegated(command: &str) -> Option<&str> {
    let rest = command.strip_prefix('!')?;
    if !matches!(rest.chars().next(), Some(c) if c == ' ' || c == '\t') {
        return None;
    }
    let rest = rest.trim_start();
    (!rest.is_empty() && !rest.starts_with('!')).then_some(rest)
}

#[cfg(test)]
#[path = "list_wrapper_tests.rs"]
mod tests;
