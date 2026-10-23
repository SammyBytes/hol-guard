use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::attestation_envelope::{public_key_fingerprint, TrustAttestationEnvelope};
use super::attestation_verification::{
    trust_attestation_under_signature, TrustAttestationVerificationKey,
    TrustAttestationVerificationPolicy,
};
use super::evidence_hash::canonical_guard_evidence_payload;

const PEM: &str = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----";

fn payload() -> Map<String, Value> {
    json!({
        "capturedAt": "2026-07-16T12:00:00Z",
        "claimHash": "sha256:claim",
        "expiresAt": "2026-07-16T12:05:00Z",
        "nonce": "nonce-1",
        "sequence": 8,
        "signedAt": "2026-07-16T12:00:00Z",
    })
    .as_object()
    .expect("object")
    .clone()
}

fn payload_hash(payload: &Map<String, Value>) -> String {
    let mut digest = Sha256::new();
    digest.update(canonical_guard_evidence_payload(payload));
    hex::encode(digest.finalize())
}

fn envelope(payload: &Map<String, Value>) -> TrustAttestationEnvelope {
    TrustAttestationEnvelope {
        payload_hash: payload_hash(payload),
        signature_algorithm: "ecdsa-p256-sha256".to_owned(),
        key_id: "active-key".to_owned(),
        public_key_pem: PEM.to_owned(),
        fingerprint_sha256: public_key_fingerprint(PEM),
        public_jwk_thumbprint: None,
        signature: "c2lnbmF0dXJl".to_owned(),
    }
}

fn trusted_key() -> TrustAttestationVerificationKey {
    TrustAttestationVerificationKey {
        key_id: "active-key".to_owned(),
        public_key_pem: PEM.to_owned(),
        fingerprint_sha256: public_key_fingerprint(PEM),
        public_jwk_thumbprint: None,
    }
}

fn named(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn listed(entries: &[&str]) -> BTreeSet<String> {
    entries.iter().map(|entry| (*entry).to_owned()).collect()
}

fn refusal(
    payload: &Map<String, Value>,
    envelope: &TrustAttestationEnvelope,
    policy: &TrustAttestationVerificationPolicy,
) -> String {
    trust_attestation_under_signature(payload, envelope, None, None, policy)
        .expect_err("refused")
        .message()
        .to_owned()
}

#[test]
fn an_attestation_nothing_objects_to_hands_back_what_the_signature_covers() {
    let payload = payload();
    let envelope = envelope(&payload);
    let verified = trust_attestation_under_signature(
        &payload,
        &envelope,
        None,
        Some(&[trusted_key()]),
        &TrustAttestationVerificationPolicy::default(),
    )
    .expect("accepted");

    assert_eq!(
        verified.canonical_payload,
        canonical_guard_evidence_payload(&payload)
    );
    assert_eq!(verified.replay_key.len(), 64);
    assert!(verified
        .replay_key
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit()));
}

#[test]
fn a_payload_that_no_longer_hashes_to_the_envelope_is_refused() {
    let mut payload = payload();
    let envelope = envelope(&payload);
    payload.insert("sequence".to_owned(), json!(9));

    assert_eq!(
        refusal(
            &payload,
            &envelope,
            &TrustAttestationVerificationPolicy::default()
        ),
        "Trust attestation payload hash mismatch"
    );
}

#[test]
fn a_public_key_is_checked_against_its_own_fingerprint_before_the_key_list() {
    let payload = payload();
    let mut envelope = envelope(&payload);
    envelope.fingerprint_sha256 = "00".repeat(32);

    assert_eq!(
        trust_attestation_under_signature(
            &payload,
            &envelope,
            None,
            Some(&[]),
            &TrustAttestationVerificationPolicy::default(),
        )
        .expect_err("refused")
        .message(),
        "Trust attestation public key fingerprint mismatch"
    );
}

#[test]
fn a_verifier_holding_no_key_list_accepts_the_key_the_envelope_ships() {
    let payload = payload();
    let envelope = envelope(&payload);

    assert!(trust_attestation_under_signature(
        &payload,
        &envelope,
        None,
        None,
        &TrustAttestationVerificationPolicy::default(),
    )
    .is_ok());
}

#[test]
fn an_empty_key_list_trusts_nothing() {
    let payload = payload();
    let envelope = envelope(&payload);

    assert_eq!(
        trust_attestation_under_signature(
            &payload,
            &envelope,
            None,
            Some(&[]),
            &TrustAttestationVerificationPolicy::default(),
        )
        .expect_err("refused")
        .message(),
        "Trust attestation key is not trusted"
    );
}

#[test]
fn a_thumbprint_the_envelope_carries_must_be_the_one_the_verifier_recorded() {
    let payload = payload();
    let mut envelope = envelope(&payload);
    envelope.public_jwk_thumbprint = Some("thumb-1".to_owned());
    let mut key = trusted_key();
    key.public_jwk_thumbprint = Some("thumb-2".to_owned());

    assert_eq!(
        trust_attestation_under_signature(
            &payload,
            &envelope,
            None,
            Some(&[key.clone()]),
            &TrustAttestationVerificationPolicy::default(),
        )
        .expect_err("refused")
        .message(),
        "Trust attestation key is not trusted"
    );

    key.public_jwk_thumbprint = Some("thumb-1".to_owned());
    assert!(trust_attestation_under_signature(
        &payload,
        &envelope,
        None,
        Some(&[key]),
        &TrustAttestationVerificationPolicy::default(),
    )
    .is_ok());
}

#[test]
fn a_verifier_that_recorded_a_thumbprint_still_accepts_an_envelope_without_one() {
    let payload = payload();
    let envelope = envelope(&payload);
    let mut key = trusted_key();
    key.public_jwk_thumbprint = Some("thumb-1".to_owned());

    assert!(trust_attestation_under_signature(
        &payload,
        &envelope,
        None,
        Some(&[key]),
        &TrustAttestationVerificationPolicy::default(),
    )
    .is_ok());
}

#[test]
fn a_revoked_key_is_refused_after_it_was_found_in_the_key_list() {
    let payload = payload();
    let envelope = envelope(&payload);
    let policy = TrustAttestationVerificationPolicy {
        revoked_key_ids: listed(&["active-key"]),
        ..TrustAttestationVerificationPolicy::default()
    };

    assert_eq!(
        trust_attestation_under_signature(
            &payload,
            &envelope,
            None,
            Some(&[trusted_key()]),
            &policy,
        )
        .expect_err("refused")
        .message(),
        "Trust attestation key is revoked"
    );
}

#[test]
fn an_attestation_signed_before_its_evidence_was_captured_is_refused() {
    let mut payload = payload();
    payload.insert("signedAt".to_owned(), json!("2026-07-16T11:59:00Z"));
    let envelope = envelope(&payload);

    assert_eq!(
        refusal(
            &payload,
            &envelope,
            &TrustAttestationVerificationPolicy::default()
        ),
        "Trust attestation timestamp ordering is invalid"
    );
}

#[test]
fn a_signing_or_capture_time_the_verifier_cannot_read_is_refused() {
    for field in ["signedAt", "capturedAt"] {
        let mut payload = payload();
        payload.insert(field.to_owned(), json!("whenever"));
        let envelope = envelope(&payload);

        assert_eq!(
            refusal(
                &payload,
                &envelope,
                &TrustAttestationVerificationPolicy::default()
            ),
            "Trust attestation timestamp ordering is invalid",
            "{field}"
        );
    }
}

#[test]
fn an_activation_time_is_read_only_for_the_key_that_signed() {
    let payload = payload();
    let envelope = envelope(&payload);
    let elsewhere = TrustAttestationVerificationPolicy {
        key_not_before: named(&[("other-key", "2027-01-01T00:00:00Z")]),
        ..TrustAttestationVerificationPolicy::default()
    };

    assert!(trust_attestation_under_signature(&payload, &envelope, None, None, &elsewhere).is_ok());

    let here = TrustAttestationVerificationPolicy {
        key_not_before: named(&[("active-key", "2026-07-16T12:00:01Z")]),
        ..TrustAttestationVerificationPolicy::default()
    };
    assert_eq!(
        refusal(&payload, &envelope, &here),
        "Trust attestation predates the trusted key activation"
    );
}

#[test]
fn an_activation_time_the_verifier_cannot_read_refuses_rather_than_passes() {
    let payload = payload();
    let envelope = envelope(&payload);
    let policy = TrustAttestationVerificationPolicy {
        key_not_before: named(&[("active-key", "whenever")]),
        ..TrustAttestationVerificationPolicy::default()
    };

    assert_eq!(
        refusal(&payload, &envelope, &policy),
        "Trust attestation predates the trusted key activation"
    );
}

#[test]
fn a_verification_clock_decides_the_future_and_the_expiry() {
    let payload = payload();
    let envelope = envelope(&payload);
    let at = |now: &str| TrustAttestationVerificationPolicy {
        now: Some(now.to_owned()),
        ..TrustAttestationVerificationPolicy::default()
    };

    assert_eq!(
        refusal(&payload, &envelope, &at("whenever")),
        "Trust attestation verification time is invalid"
    );
    assert_eq!(
        refusal(&payload, &envelope, &at("2026-07-16T11:59:59Z")),
        "Trust attestation is signed in the future"
    );
    assert_eq!(
        refusal(&payload, &envelope, &at("2026-07-16T12:05:00Z")),
        "Trust attestation is expired"
    );
    assert!(trust_attestation_under_signature(
        &payload,
        &envelope,
        None,
        None,
        &at("2026-07-16T12:04:59Z"),
    )
    .is_ok());
}

#[test]
fn an_attestation_with_no_expiry_never_expires() {
    let mut payload = payload();
    payload.remove("expiresAt");
    let envelope = envelope(&payload);
    let policy = TrustAttestationVerificationPolicy {
        now: Some("2030-01-01T00:00:00Z".to_owned()),
        ..TrustAttestationVerificationPolicy::default()
    };

    assert!(trust_attestation_under_signature(&payload, &envelope, None, None, &policy).is_ok());
}

#[test]
fn a_sequence_must_advance_past_the_one_already_seen() {
    let payload = payload();
    let envelope = envelope(&payload);
    let past = |minimum: i64| TrustAttestationVerificationPolicy {
        minimum_sequence: Some(minimum),
        ..TrustAttestationVerificationPolicy::default()
    };

    assert!(trust_attestation_under_signature(&payload, &envelope, None, None, &past(7)).is_ok());
    assert_eq!(
        refusal(&payload, &envelope, &past(8)),
        "Trust attestation sequence is not monotonic"
    );
}

#[test]
fn a_sequence_too_wide_to_hold_still_outruns_the_one_already_seen() {
    let mut payload = payload();
    payload.insert(
        "sequence".to_owned(),
        serde_json::from_str::<Value>("1000000000000000000000000000000000000000000")
            .expect("number"),
    );
    let envelope = envelope(&payload);
    let policy = TrustAttestationVerificationPolicy {
        minimum_sequence: Some(i64::MAX),
        ..TrustAttestationVerificationPolicy::default()
    };

    assert!(trust_attestation_under_signature(&payload, &envelope, None, None, &policy).is_ok());
}

#[test]
fn a_sequence_that_is_absent_or_not_a_whole_count_cannot_advance_one() {
    for sequence in [None, Some(json!("8")), Some(json!(8.5)), Some(json!(-1))] {
        let mut payload = payload();
        match sequence.clone() {
            None => {
                payload.remove("sequence");
            }
            Some(value) => {
                payload.insert("sequence".to_owned(), value);
            }
        }
        let envelope = envelope(&payload);
        let policy = TrustAttestationVerificationPolicy {
            minimum_sequence: Some(0),
            ..TrustAttestationVerificationPolicy::default()
        };

        assert_eq!(
            refusal(&payload, &envelope, &policy),
            "Trust attestation sequence is not monotonic",
            "{sequence:?}"
        );
    }
}

#[test]
fn a_verifier_that_requires_a_nonce_refuses_an_attestation_without_one() {
    let mut payload = payload();
    payload.remove("nonce");
    let envelope = envelope(&payload);
    let policy = TrustAttestationVerificationPolicy {
        require_nonce: true,
        ..TrustAttestationVerificationPolicy::default()
    };

    assert_eq!(
        refusal(&payload, &envelope, &policy),
        "Trust attestation nonce is required"
    );
}

#[test]
fn a_replay_identity_the_verifier_already_recorded_is_refused() {
    let payload = payload();
    let envelope = envelope(&payload);
    let seen = trust_attestation_under_signature(
        &payload,
        &envelope,
        None,
        None,
        &TrustAttestationVerificationPolicy::default(),
    )
    .expect("accepted")
    .replay_key;
    let policy = TrustAttestationVerificationPolicy {
        seen_replay_keys: listed(&[seen.as_str()]),
        ..TrustAttestationVerificationPolicy::default()
    };

    assert_eq!(
        refusal(&payload, &envelope, &policy),
        "Trust attestation replay detected"
    );
}

#[test]
fn a_claim_is_hashed_before_the_payload_is() {
    let mut payload = payload();
    payload.insert("claimHash".to_owned(), json!("sha256:elsewhere"));
    let mut envelope = envelope(&payload);
    envelope.payload_hash = "00".repeat(32);
    let claim = json!({"resolutionSource": "remote"})
        .as_object()
        .expect("object")
        .clone();

    assert_eq!(
        trust_attestation_under_signature(
            &payload,
            &envelope,
            Some(&claim),
            None,
            &TrustAttestationVerificationPolicy::default(),
        )
        .expect_err("refused")
        .message(),
        "Trust claim is not locally derived or has invalid evidence"
    );
}
