use super::without_case_labels;

/// Every label goes, and the `)` that ended it becomes the separator that
/// keeps the clause body in command position.
#[test]
fn labels_become_separators() {
    assert_eq!(
        without_case_labels("case x in a) echo a;; *) echo b;; esac"),
        "case x in  ; echo a;;  ; echo b;; esac"
    );
    assert_eq!(
        without_case_labels("case \"$f\" in *.ts|*.tsx) tsc;; esac"),
        "case \"$f\" in           ; tsc;; esac"
    );
    assert_eq!(
        without_case_labels("case $MODE in a) $CMD;; *) echo b;; esac"),
        "case $MODE in  ; $CMD;;  ; echo b;; esac"
    );
}

/// The word the construct matches on is not a label and stays where it is, and
/// so does everything after `esac`.
#[test]
fn only_the_labels_go() {
    assert_eq!(
        without_case_labels("case $MODE in a) echo a;; esac; echo $MODE"),
        "case $MODE in  ; echo a;; esac; echo $MODE"
    );
}

/// A single `;` ends a command inside a clause body; it does not open the next
/// label list.
#[test]
fn a_single_separator_does_not_open_a_label() {
    assert_eq!(
        without_case_labels("case x in a) echo a; echo b;; esac"),
        "case x in  ; echo a; echo b;; esac"
    );
}

/// A label built at run time, a text whose `(` may open a subshell, a function
/// body or an extglob, and a text with no construct at all are left exactly as
/// they were.
#[test]
fn an_unreadable_construct_is_left_alone() {
    for text in [
        "case x in $PATTERN) echo a;; esac",
        "case x in `echo a`) echo a;; esac",
        "case x in (a) echo a;; esac",
        "greet() { echo hi; }; greet",
        "echo a; echo b",
    ] {
        assert_eq!(without_case_labels(text), text, "{text}");
    }
}

/// A `)` outside any construct is not a label either, and a nested construct
/// keeps its own labels and its outer one apart.
#[test]
fn a_nested_construct_keeps_its_own_labels() {
    assert_eq!(without_case_labels("echo a) b"), "echo a) b");
    assert_eq!(
        without_case_labels("case x in a) case y in b) echo b;; esac;; esac"),
        "case x in  ; case y in  ; echo b;; esac;; esac"
    );
}

/// A label spelled inside quotes is still a label, and a quoted `)` does not
/// end one.
#[test]
fn quoting_does_not_move_a_label() {
    assert_eq!(
        without_case_labels("case x in 'a)b') echo a;; esac"),
        "case x in      ; echo a;; esac"
    );
}
