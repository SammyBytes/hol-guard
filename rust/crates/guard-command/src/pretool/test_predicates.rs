//! The `test` and `[` predicates that answer from their operands alone.
//!
//! `[ -z "$DEBUG" ] && echo quiet` and `[ "$NODE_ENV" = production ] && …`
//! are how a script reads a variable it already has. The shell expands both
//! operands before `test` starts, so the predicate compares two strings in
//! memory and touches nothing: no file is opened, no directory is listed and
//! no process is started. A comparison therefore needs none of the read
//! bounds a file predicate needs, and holding one back only asks the user
//! about a branch the script takes either way.
//!
//! An operand that is itself produced by a command substitution is a command
//! of its own in the model and is judged there, so it cannot reach a verdict
//! through this proof; the substitution spellings are refused here as well,
//! because a word carrying one is not the plain string this proof stands for.
//!
//! An expansion has to be quoted. The shell splits an unquoted `$P` into
//! words and expands each as a pathname pattern, so `P=~/.ssh/id_*; [ $P = x ]`
//! lists `~/.ssh` before `test` starts, and what the directory holds decides
//! how many operands `test` receives. `"$P"` and `'$P'` reach `test` as one
//! word that nothing has expanded.

/// Operators that compare two already-expanded operands. The numeric ones
/// parse their operands as integers; neither form reads anything.
const COMPARISONS: [&str; 9] = ["=", "==", "!=", "-eq", "-ne", "-lt", "-le", "-gt", "-ge"];

/// The predicate itself, with a leading `!` removed. `[ ! -f .env ]` asks
/// the same question of the same operands as `[ -f .env ]` and reads no
/// more, so the negation changes which branch runs, not what is admitted.
pub(super) fn without_negation(arguments: &[String]) -> &[String] {
    match arguments.split_first() {
        Some((first, rest)) if first == "!" => rest,
        _ => arguments,
    }
}

/// Whether `arguments` form a predicate that answers from its operands,
/// optionally negated by a leading `!`. `text` is the segment as written,
/// with its quoting, which the arguments no longer carry.
pub(super) fn answers_from_operands(arguments: &[String], text: &str) -> bool {
    let shaped = match without_negation(arguments) {
        [word] => plain_operand(word),
        [predicate, word] => matches!(predicate.as_str(), "-n" | "-z") && plain_operand(word),
        [left, operator, right] => {
            COMPARISONS.contains(&operator.as_str()) && plain_operand(left) && plain_operand(right)
        }
        _ => false,
    };
    shaped && expansions_quoted(arguments, text)
}

/// Whether every argument that carries a `$` is written quoted, in order.
///
/// The arguments arrive with their quotes removed, so each one holding a `$`
/// is looked for as a quoted word in the text, after the previous match.
/// Matching in order keeps `[ "$P" = $P ]` from reusing the first quoted
/// spelling for the second, unquoted one.
fn expansions_quoted(arguments: &[String], text: &str) -> bool {
    let mut rest = text;
    for word in arguments.iter().filter(|word| word.contains('$')) {
        let found = ['"', '\'']
            .iter()
            .filter_map(|quote| {
                let quoted = format!("{quote}{word}{quote}");
                rest.find(&quoted).map(|start| (start, quoted.len()))
            })
            .min();
        let Some((start, length)) = found else {
            return false;
        };
        rest = &rest[start + length..];
    }
    true
}

/// A word the shell has already expanded to a plain string. A leading `-`
/// would be read as a predicate rather than as an operand, and a command
/// substitution runs a command this proof does not stand for.
///
/// A glob is refused too. The words reach this proof with their quoting
/// removed, so `*`, `?` and `[` cannot be told apart from the literal
/// characters a quoted pattern would carry; the shell expands an unquoted
/// one by listing the directory it names, and the exit status then reports
/// what that directory holds. A pattern can also change how many words
/// `test` receives, and so which form it reads.
fn plain_operand(word: &str) -> bool {
    !word.starts_with('-')
        && !word.contains('`')
        && !word.contains("$(")
        && !word.contains(['*', '?', '['])
}

#[cfg(test)]
mod tests {
    use super::answers_from_operands;

    fn arguments(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_string()).collect()
    }

    /// The segment text a quoting shell would have written for `words`.
    fn quoted_text(words: &[&str]) -> String {
        words
            .iter()
            .map(|word| {
                if word.contains('$') {
                    format!("\"{word}\"")
                } else {
                    (*word).to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn admits_string_and_numeric_comparisons() {
        for words in [
            vec!["-z", "$DEBUG"],
            vec!["-n", "$CI"],
            vec!["$NODE_ENV", "=", "production"],
            vec!["$NODE_ENV", "!=", "production"],
            vec!["$COUNT", "-gt", "0"],
            vec!["!", "-z", "$CI"],
            vec!["$CI"],
        ] {
            assert!(
                answers_from_operands(&arguments(&words), &format!("test {}", quoted_text(&words))),
                "{words:?}"
            );
        }
    }

    #[test]
    fn refuses_file_predicates_and_substituted_operands() {
        for words in [
            vec!["-f", "README.md"],
            vec!["-z", "$(cat /etc/shadow)"],
            vec!["-z", "`cat /etc/shadow`"],
            vec!["-z", "$DEBUG", "-a", "-f", ".env"],
            vec!["$NODE_ENV", "-a", "production"],
            vec!["~/.ssh/id_*", "=", "x"],
            vec!["/root/?", "=", "x"],
            vec!["-z", "/etc/[a-z]*"],
            vec![],
        ] {
            assert!(
                !answers_from_operands(
                    &arguments(&words),
                    &format!("test {}", quoted_text(&words))
                ),
                "{words:?}"
            );
        }
    }

    #[test]
    fn refuses_an_unquoted_expansion() {
        for (words, text) in [
            (vec!["$P", "=", "x"], "[ $P = x ]"),
            (vec!["-z", "$DEBUG"], "test -z $DEBUG"),
            (vec!["$P", "=", "$P"], "[ \"$P\" = $P ]"),
            (vec!["$P", "=", "$P"], "[ $P = \"$P\" ]"),
        ] {
            assert!(!answers_from_operands(&arguments(&words), text), "{text}");
        }
        for (words, text) in [
            (vec!["$P", "=", "x"], "[ \"$P\" = x ]"),
            (vec!["$P", "=", "x"], "[ '$P' = x ]"),
            (vec!["$P", "=", "$P"], "[ \"$P\" = \"$P\" ]"),
            (vec!["$P", "=", "$P"], "[ '$P' = \"$P\" ]"),
            (vec!["x", "=", "y"], "[ x = y ]"),
        ] {
            assert!(answers_from_operands(&arguments(&words), text), "{text}");
        }
    }
}
