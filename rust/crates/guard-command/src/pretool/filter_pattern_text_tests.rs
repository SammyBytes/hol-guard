use crate::pretool::search::{glob_can_select_sensitive_path, literal_glob_names_sensitive_path};
use crate::pretool::source_reads::sensitive_command_input;

/// A pattern handed to a filter that reads only standard input names no file,
/// so a listing piped into it is ordinary work rather than a sensitive read.
#[test]
fn a_stdin_filter_pattern_is_not_a_sensitive_target() {
    for command in [
        "ls -R . | grep -v .env",
        "ls -R . | grep .env",
        "ls -R . | sort | grep -v .env",
        "ls -R . | rg .env",
        "git status --short | grep -v .env",
    ] {
        assert!(
            !sensitive_command_input(command),
            "{command} still reads as a sensitive target"
        );
    }
}

/// Only the filter's own arguments are set aside. A producer that names a
/// sensitive file keeps its signal, a credential word keeps its signal
/// wherever it appears, a matcher that opens a file of its own is not a stdin
/// filter at all, and a word the shell can still act on — an attached
/// redirect, an unquoted glob — is not a pattern yet.
#[test]
fn only_a_proven_stdin_filter_sheds_its_pattern() {
    for command in [
        "cat .env | grep DATABASE",
        "ls -la | grep -i secret.txt | head -5",
        "ls -R ~/.ssh | grep -v known_hosts",
        "ls -R . | grep AWS_SECRET_ACCESS_KEY",
        "ls -R . | grep -f .env",
        "ls -R . | grep --file=.env",
        "ls -R . | grep -r .env /etc",
        "ls -R . | grep .env<.env",
        "ls -a . | grep -v .env*",
        "ls -R . | grep -v .env{,.local}",
        "ls -R . | PATTERN=.env grep $PATTERN",
    ] {
        assert!(
            sensitive_command_input(command),
            "{command} lost a signal the filter exemption must keep"
        );
    }
}

/// A word that is a marker and then an unconstrained tail is the shape
/// that does reach a credential: `grep -i credentials.*` run beside
/// `credentials.json` and `credentials.yml` expands to both, and the
/// second is the file `grep` opens. A pattern is refused on that shape,
/// unlike the two-word regexes above, whose literal tail has to match.
#[test]
fn a_bare_marker_wildcard_is_refused_as_a_pattern() {
    for expanding in [
        "credentials.*",
        "secrets.*",
        "secret.?",
        "token.*",
        "auth.*",
        "password.*",
        "id_rsa.*",
        "src/credentials.*",
    ] {
        assert!(literal_glob_names_sensitive_path(expanding), "{expanding}");
        assert!(glob_can_select_sensitive_path(expanding), "{expanding}");
    }
}

/// The same shape read end to end: a bare credential wildcard in the pattern
/// position is a sensitive read, while a regex whose literal tail has to match
/// is the ordinary search the filter proof is for.
#[test]
fn a_bare_credential_wildcard_pattern_reads_as_a_sensitive_target() {
    for command in [
        "cat app.log | grep -i credentials.*",
        "cat app.log | grep secrets.*",
        "ls -R . | rg token.*",
    ] {
        assert!(
            sensitive_command_input(command),
            "{command} should read as a sensitive target"
        );
    }
    for command in [
        "cat app.log | grep -i auth.*provider",
        "cat app.log | grep token.*expired",
    ] {
        assert!(
            !sensitive_command_input(command),
            "{command} still reads as a sensitive target"
        );
    }
}
