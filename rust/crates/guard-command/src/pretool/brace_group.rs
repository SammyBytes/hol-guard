//! A brace group `{ ...; }` that ends a command list groups its commands
//! without a child shell, so the words inside it are exactly the words the
//! shell runs. Nothing follows the group, so a `cd` or assignment inside it
//! changes no later command of this request, and the group inherits every
//! effect of the commands before it. Its commands are therefore the same as
//! the ungrouped list, and the ordinary proofs can decide them instead of
//! sending an unmodeled string to the user: `{ npm run build; npm test; }`
//! reached review while `npm run build && npm test` ran in the workspace
//! sandbox.
//!
//! `{` is a reserved word only at the start of a command and only when a blank
//! follows it, and the list inside has to end with the `;` or newline that
//! separates it from `}`. Both are checked here, so brace expansion
//! (`echo {a,b}`) and parameter expansion (`${HOME}`) are never read as a
//! group. Anything this recognizer does not fully understand returns `None`,
//! which keeps the existing review behavior.

const MAX_COMMAND_BYTES: usize = 8192;

/// The command text with its trailing brace group's braces and list terminator
/// replaced by spaces, or `None` unless the command has exactly one unquoted
/// `{` and one unquoted `}` that open a group at the start of the command or
/// after `&&`, `||`, `;` or a newline, hold a terminated command list, and
/// close as the last non-blank character.
pub(crate) fn unwrap(command: &str) -> Option<String> {
    let command = command.trim();
    if command.len() > MAX_COMMAND_BYTES
        || command.contains("<<")
        || command.contains("$'")
        || command.contains("$\"")
        || command
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return None;
    }
    let chars: Vec<char> = command.chars().collect();
    let (open, close) = unquoted_braces(&chars)?;
    if close + 1 != chars.len() || !super::trailing_group::opens_list_element(&chars, open) {
        return None;
    }
    // The reserved word is `{` followed by a blank; `{a,b}` is one word.
    if !matches!(chars.get(open + 1), Some(c) if c.is_whitespace()) {
        return None;
    }
    let inner = &chars[open + 1..close];
    let last = inner.iter().rposition(|c| !c.is_whitespace())?;
    // `}` is a reserved word only after a `;` or a newline, so a list that
    // runs straight into the brace is not one this recognizer understands.
    let terminator = if inner[last] == ';' {
        Some(open + 1 + last)
    } else if inner[last + 1..].contains(&'\n') {
        None
    } else {
        return None;
    };
    let mut ungrouped = chars;
    ungrouped[open] = ' ';
    ungrouped[close] = ' ';
    if let Some(index) = terminator {
        ungrouped[index] = ' ';
    }
    let ungrouped: String = ungrouped.into_iter().collect();
    let ungrouped = ungrouped.trim();
    (!ungrouped.is_empty()).then(|| ungrouped.to_owned())
}

/// The positions of the only unquoted `{` and `}`, in that order.
fn unquoted_braces(chars: &[char]) -> Option<(usize, usize)> {
    let mut open = None;
    let mut close = None;
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    for (index, &c) in chars.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if single {
            single = c != '\'';
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => double = !double,
            '\'' if !double => single = true,
            '{' | '}' if !double => {
                let slot = if c == '{' { &mut open } else { &mut close };
                if slot.replace(index).is_some() {
                    return None;
                }
            }
            _ => {}
        }
    }
    if single || double || escaped {
        return None;
    }
    let (open, close) = (open?, close?);
    (open < close).then_some((open, close))
}

#[cfg(test)]
#[path = "brace_group_tests.rs"]
mod tests;
