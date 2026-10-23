//! The claim gate and the names it hands out agree with Python's.
//!
//! A verifier recognizes an attestation it has already seen by the digest of
//! the claim inside it, and that digest is only meaningful if both runtimes
//! admit the same claims in the first place. These vectors are recorded from
//! the Python oracle and replayed by `tests/test_guard_trust_claim_parity.py`
//! as well.

use guard_command::attestation_timestamp::parse_attestation_timestamp;
use guard_command::trust_claim::{trust_attestation_replay_key, trust_claim_hash};
use serde_json::Value;

const VECTORS: &str = include_str!("../../../../tests/fixtures/guard-trust-claim.v1.json");

fn vectors() -> Value {
    let parsed: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    assert_eq!(
        parsed["schema"].as_str(),
        Some("guard-trust-claim-parity.v1")
    );
    parsed
}

#[test]
fn recorded_timestamps_parse_to_their_recorded_instant() {
    let vectors = vectors();
    let cases = vectors["timestamps"].as_array().expect("timestamps array");
    assert!(cases.len() >= 500, "the fixture records too few timestamps");
    let mut accepted = 0usize;
    for case in cases {
        let input = case["input"].as_str().expect("input");
        let expected = case["epochMicroseconds"].as_i64();
        // Python raises `OverflowError` where the shift to UTC leaves
        // `datetime`'s range; neither side produces an instant.
        assert_eq!(
            parse_attestation_timestamp(input),
            expected,
            "{input:?} parsed differently"
        );
        accepted += usize::from(expected.is_some());
    }
    assert!(accepted >= 400, "the fixture records too few instants");
}

#[test]
fn recorded_claims_hash_to_their_recorded_digest() {
    let vectors = vectors();
    let cases = vectors["claims"].as_array().expect("claims array");
    assert!(cases.len() >= 20, "the fixture records too few claims");
    for case in cases {
        let require_layer_identity = case["requireLayerIdentity"]
            .as_bool()
            .expect("requireLayerIdentity");
        let expected = case["claimHash"].as_str();
        let name = case["name"].as_str().unwrap_or_default();
        let Some(claim) = case["claim"].as_object() else {
            // A claim that is not a mapping never reaches the hash.
            assert_eq!(expected, None, "{name}");
            continue;
        };
        assert_eq!(
            trust_claim_hash(claim, require_layer_identity)
                .ok()
                .as_deref(),
            expected,
            "{name}"
        );
    }
}

#[test]
fn recorded_payloads_replay_under_their_recorded_key() {
    let vectors = vectors();
    let cases = vectors["replayKeys"].as_array().expect("replayKeys array");
    assert!(cases.len() >= 6, "the fixture records too few payloads");
    for case in cases {
        let payload = case["payload"].as_object().expect("payload object");
        assert_eq!(
            trust_attestation_replay_key(payload),
            case["replayKey"].as_str().expect("replayKey"),
            "{}",
            case["name"].as_str().unwrap_or_default()
        );
    }
}
