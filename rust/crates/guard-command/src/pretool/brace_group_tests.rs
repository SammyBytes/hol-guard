use super::unwrap;

#[test]
fn a_trailing_brace_group_reads_as_its_command_list() {
    assert_eq!(
        unwrap("{ npm run build; npm test; }").as_deref(),
        Some("npm run build; npm test")
    );
    assert_eq!(
        unwrap("cd web && { npm ci; npm test; }").as_deref(),
        Some("cd web &&   npm ci; npm test")
    );
    assert_eq!(unwrap("{\n  pytest -q\n}").as_deref(), Some("pytest -q"));
}

#[test]
fn a_group_that_does_not_end_the_command_keeps_its_review() {
    assert_eq!(unwrap("{ pytest -q; } 2>&1"), None);
    assert_eq!(unwrap("{ npm test; } && echo done"), None);
}

#[test]
fn brace_expansion_and_parameter_expansion_are_not_groups() {
    assert_eq!(unwrap("echo {a,b}"), None);
    assert_eq!(unwrap("{a,b}"), None);
    assert_eq!(unwrap("echo ${HOME}"), None);
    assert_eq!(unwrap("{ echo ${HOME}; }"), None);
}

#[test]
fn an_unterminated_list_is_not_a_group() {
    assert_eq!(unwrap("{ npm test }"), None);
    assert_eq!(unwrap("{ echo \"a;\" }"), None);
}

#[test]
fn a_quoted_or_escaped_brace_is_not_a_group() {
    assert_eq!(unwrap("echo '{ npm test; }'"), None);
    assert_eq!(unwrap("echo \"{ npm test; }\""), None);
    assert_eq!(unwrap("echo \\{ npm test; }"), None);
}

#[test]
fn a_group_that_does_not_open_a_list_element_is_not_unwrapped() {
    assert_eq!(unwrap("echo hi { npm test; }"), None);
    assert_eq!(unwrap("npm test | { tee log; }"), None);
}

#[test]
fn an_empty_or_oversized_group_is_refused() {
    assert_eq!(unwrap("{   }"), None);
    assert_eq!(unwrap(&format!("{{ echo {}; }}", "a".repeat(9000))), None);
    assert_eq!(unwrap("{ cat <<EOF; }"), None);
}
