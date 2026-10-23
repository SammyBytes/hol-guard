use super::*;

#[test]
fn harness_watch_releases_output_review_but_keeps_credentials_hidden() {
    use crate::policy_enforcement::tests::{policy, snapshot};
    let admitted = AdmittedPolicySnapshot::new(snapshot(policy("allow"))).unwrap();
    // A per-app Watch override arrives as `recording_only` on an enforce snapshot.
    let run = |payload: Value, recording_only: bool| -> Value {
        let mut watched = envelope("PostToolUse", payload);
        watched.harness = "omp".to_owned();
        watched.recording_only = recording_only;
        let guard_home = std::path::PathBuf::from(&watched.source.guard_home);
        let bytes = evaluate_envelope_with_snapshot(watched, &admitted);
        std::fs::remove_dir_all(guard_home).expect("remove edge generation fixture");
        serde_json::from_slice(&bytes.unwrap()).unwrap()
    };
    let notes = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "context_notes",
        "tool_input": {"text": "notes"},
        "tool_response": "Noted."
    });
    let protected = run(notes.clone(), false);
    assert_eq!(
        protected["result"]["reason_code"],
        "native_policy_review_required"
    );
    assert_eq!(protected["harness_response"]["decision"], "deny");
    let watched = run(notes, true);
    assert_eq!(watched["result"]["decision"], "allow");
    assert_eq!(watched["harness_response"]["decision"], "allow");
    assert_eq!(
        watched["harness_response"]["model_output_action"],
        "allow_original"
    );

    let token = format!("{}{}", ["gh", "p_"].concat(), "c".repeat(30));
    let credential = run(
        serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "bash",
            "tool_input": {"command": "cat config"},
            "tool_response": token
        }),
        true,
    );
    assert_eq!(credential["result"]["reason_code"], "output_secret_match");
    assert_eq!(credential["harness_response"]["decision"], "deny");
}
