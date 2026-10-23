//! The labels of a `case` construct.
//!
//! `case "$f" in *.ts|*.tsx) tsc "$f";; *) exit 1;; esac` matches its labels
//! where the shell would otherwise read a program, and a label is glob-shaped
//! by design. The owner scan read `*)` as a command word the shell builds at
//! run time and refused the whole construct, so an ordinary `case` blocked
//! outright with no approval left to give it, while the same construct spelled
//! with literal labels alone reached review. Taking the labels out leaves
//! every word the shell can actually run where it stood.
//!
//! Only a plainly written construct is read this way. A `(` anywhere in the
//! text may open a subshell, a function body or an extglob rather than a label
//! list, and a label holding an expansion, a substitution or a redirect could
//! name something of its own; either keeps the refusal it had.

#[derive(Clone, Copy, PartialEq)]
enum Quote {
    None,
    Single,
    Double,
}

/// The text with every `case` label replaced by the command separator that
/// stood at its end, so the clause body keeps the command position the label
/// used to hold and nothing else moves.
pub(super) fn without_case_labels(text: &str) -> String {
    if text.contains('(') || !text.contains(')') {
        return text.to_owned();
    }
    let characters: Vec<char> = text.chars().collect();
    let mut blanked = characters.clone();
    let mut quote = Quote::None;
    let mut open = 0usize;
    let mut awaiting_in = false;
    let mut label: Option<usize> = None;
    let mut word: Option<usize> = None;
    let mut index = 0usize;
    while index <= characters.len() {
        let current = characters.get(index).copied();
        let boundary = match (quote, current) {
            (Quote::None, None) => true,
            (Quote::None, Some(character)) => {
                character.is_whitespace() || matches!(character, ';' | ')')
            }
            _ => false,
        };
        if boundary {
            if let Some(start) = word.take() {
                let keyword: String = characters[start..index].iter().collect();
                match keyword.as_str() {
                    "case" => {
                        open += 1;
                        awaiting_in = true;
                    }
                    "in" if awaiting_in => {
                        awaiting_in = false;
                        label = Some(index);
                    }
                    "esac" if open > 0 => {
                        open -= 1;
                        label = None;
                    }
                    _ => {}
                }
            }
        } else if current.is_some_and(|character| !character.is_whitespace()) && word.is_none() {
            word = Some(index);
        }
        let Some(current) = current else { break };
        match quote {
            Quote::Single => {
                if current == '\'' {
                    quote = Quote::None;
                }
            }
            Quote::Double => match current {
                '\\' => index += 1,
                '"' => quote = Quote::None,
                _ => {}
            },
            Quote::None => match current {
                '\\' => index += 1,
                '\'' => quote = Quote::Single,
                '"' => quote = Quote::Double,
                ')' => {
                    if let Some(start) = label.take() {
                        if !take_label(&mut blanked, &characters, start, index) {
                            return text.to_owned();
                        }
                    }
                }
                ';' => {
                    if open > 0 && characters.get(index + 1) == Some(&';') {
                        index += 1;
                        label = Some(index + 1);
                    }
                }
                _ => {}
            },
        }
        index += 1;
    }
    blanked.into_iter().collect()
}

/// Takes the label out, leaving a `;` where its `)` stood. The separator is
/// what keeps the clause body in command position: blanking the label away
/// entirely would join the body to the words before it, and the owner scan
/// reads only the first word of each command it finds.
///
/// A label is left alone, and the whole text with it, when it holds anything
/// the shell could read as more than a pattern.
fn take_label(blanked: &mut [char], characters: &[char], start: usize, end: usize) -> bool {
    if characters[start..end]
        .iter()
        .any(|character| matches!(character, '$' | '`' | '<' | '>'))
    {
        return false;
    }
    for slot in &mut blanked[start..end] {
        *slot = ' ';
    }
    blanked[end] = ';';
    true
}

#[cfg(test)]
#[path = "native_command_unmodeled_case_tests.rs"]
mod tests;
