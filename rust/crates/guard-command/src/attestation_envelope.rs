//! The envelope that carries a trust attestation's signature.
//!
//! A verifier reads the envelope before it reads the payload: the envelope
//! names the key, the algorithm and the hash the signature covers, so a
//! malformed one has to be refused before any of it is believed. Python does
//! this inline at the top of `verify_trust_attestation`, and the wording of
//! each rejection is reproduced here so a receipt reads the same whichever
//! side refused it.
//!
//! `normalize_pem` and `public_key_fingerprint` trim with Rust's definition of
//! whitespace, which omits the four ASCII separators U+001C to U+001F that
//! Python's `str.strip` also removes. A PEM padded with one of those would
//! fingerprint differently on the two sides, and the side that computed the
//! other digest refuses the envelope, so the difference can only reject an
//! attestation, never admit one.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::attestation_payload::GUARD_TRUST_ATTESTATION_PAYLOAD_VERSION_V3;

/// The RSA-PSS algorithm a signing key uses by default.
pub const GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM: &str = "rsa-pss-sha256";
/// The elliptic-curve algorithm a headless short-lived key uses.
pub const GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256: &str = "ecdsa-p256-sha256";

const ALLOWED_FIELDS: [&str; 9] = [
    "fingerprintSha256",
    "keyId",
    "payloadHash",
    "payloadVersion",
    "publicJwkThumbprint",
    "publicKeyPem",
    "signature",
    "signatureAlgorithm",
    "signedAt",
];

const REQUIRED_STRING_FIELDS: [&str; 6] = [
    "payloadHash",
    "signatureAlgorithm",
    "keyId",
    "publicKeyPem",
    "fingerprintSha256",
    "signature",
];

/// An envelope whose shape a verifier has already accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAttestationEnvelope {
    pub payload_hash: String,
    pub signature_algorithm: String,
    pub key_id: String,
    pub public_key_pem: String,
    pub fingerprint_sha256: String,
    pub public_jwk_thumbprint: Option<String>,
    pub signature: String,
}

/// Why an envelope was refused, in the wording Python uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationEnvelopeError(String);

impl AttestationEnvelopeError {
    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AttestationEnvelopeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AttestationEnvelopeError {}

fn refuse<T>(message: impl Into<String>) -> Result<T, AttestationEnvelopeError> {
    Err(AttestationEnvelopeError(message.into()))
}

fn non_empty_text<'a>(envelope: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    envelope
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

/// Read an envelope's fields, refusing anything a verifier cannot act on.
///
/// # Errors
///
/// Returns the refusal a verifier reports when the envelope carries an unknown
/// field, leaves a required field absent or blank, announces a payload version
/// this build does not read, or names a signature algorithm it cannot verify.
pub fn validated_trust_attestation_envelope(
    envelope: &Map<String, Value>,
) -> Result<TrustAttestationEnvelope, AttestationEnvelopeError> {
    let mut unknown: Vec<&str> = envelope
        .keys()
        .map(String::as_str)
        .filter(|field| !ALLOWED_FIELDS.contains(field))
        .collect();
    unknown.sort_unstable();
    if !unknown.is_empty() {
        return refuse(format!(
            "Unknown trust attestation envelope fields: {}",
            unknown.join(", ")
        ));
    }

    for field in REQUIRED_STRING_FIELDS {
        if non_empty_text(envelope, field).is_none() {
            return refuse("Trust attestation envelope is incomplete");
        }
    }

    if envelope.get("payloadVersion").and_then(Value::as_str)
        != Some(GUARD_TRUST_ATTESTATION_PAYLOAD_VERSION_V3)
    {
        return refuse("Unsupported trust attestation envelope version");
    }

    let text = |field: &str| {
        non_empty_text(envelope, field)
            .unwrap_or_default()
            .to_owned()
    };
    let signature_algorithm = text("signatureAlgorithm");
    if signature_algorithm != GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM
        && signature_algorithm != GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256
    {
        return refuse("Unsupported trust attestation signature algorithm");
    }

    Ok(TrustAttestationEnvelope {
        payload_hash: text("payloadHash"),
        signature_algorithm,
        key_id: text("keyId"),
        public_key_pem: text("publicKeyPem"),
        fingerprint_sha256: text("fingerprintSha256"),
        // A thumbprint that is not a string is read as absent rather than
        // refused, so an envelope from a newer writer still verifies.
        public_jwk_thumbprint: envelope
            .get("publicJwkThumbprint")
            .and_then(Value::as_str)
            .map(str::to_owned),
        signature: text("signature"),
    })
}

/// Carry the envelope's signing time into the payload the signature covers.
#[must_use]
pub fn payload_with_signed_at(
    payload: &Map<String, Value>,
    signed_at: Option<&Value>,
) -> Map<String, Value> {
    let mut enriched = payload.clone();
    if let Some(text) = signed_at
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
    {
        enriched.insert("signedAt".to_owned(), Value::String(text.to_owned()));
    }
    enriched
}

/// Read a PEM the way both sides hash it: Unix line endings, no outer blanks.
#[must_use]
pub fn normalize_pem(value: &str) -> String {
    value.replace("\r\n", "\n").trim().to_owned()
}

/// The digest an envelope has to carry for the public key it ships.
#[must_use]
pub fn public_key_fingerprint(public_key_pem: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(normalize_pem(public_key_pem).as_bytes());
    hex::encode(digest.finalize())
}
