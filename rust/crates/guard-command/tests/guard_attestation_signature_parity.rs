//! Replay recorded signature decisions through the Rust verifier.
//!
//! Every case in the fixture was produced by handing a real key, payload and
//! signature to Python's loader and `_verify_signature`, so an accepted case
//! was accepted by `cryptography` and a refusal is Python's own wording.

use base64ct::{Base64, Encoding};
use guard_command::attestation_signature::{
    load_attestation_public_key, verify_attestation_signature,
};
use serde_json::Value;

const FIXTURE: &str =
    include_str!("../../../../tests/fixtures/guard-attestation-signature.v1.json");

fn text<'a>(case: &'a Value, field: &str) -> &'a str {
    case.get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("case is missing {field}"))
}

fn bytes(case: &Value, field: &str) -> Vec<u8> {
    Base64::decode_vec(text(case, field)).expect("recorded base64")
}

/// What the Rust half decides, in the vocabulary the fixture records.
fn decide(case: &Value) -> String {
    let public_key = match load_attestation_public_key(text(case, "public_key_pem")) {
        Ok(public_key) => public_key,
        Err(error) => return error.message().to_owned(),
    };
    match verify_attestation_signature(
        &public_key,
        &bytes(case, "canonical_payload_base64"),
        &bytes(case, "signature_base64"),
        text(case, "signature_algorithm"),
    ) {
        Ok(()) => "ok".to_owned(),
        Err(error) => error.message().to_owned(),
    }
}

#[test]
fn recorded_signature_decisions_replay() {
    let document: Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    assert_eq!(
        document["schema"], "guard-attestation-signature-parity.v1",
        "fixture schema moved"
    );
    let cases = document["cases"].as_array().expect("cases");
    assert!(!cases.is_empty(), "fixture records no cases");
    let mut accepted = 0usize;
    for case in cases {
        let name = text(case, "name");
        assert_eq!(
            decide(case),
            text(case, "expected"),
            "case {name} disagrees with Python"
        );
        if text(case, "expected") == "ok" {
            accepted += 1;
        }
    }
    assert!(
        accepted >= 2,
        "the fixture must keep recording signatures that verify"
    );
}
