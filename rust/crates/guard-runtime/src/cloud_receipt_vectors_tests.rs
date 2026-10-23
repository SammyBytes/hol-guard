//! Replays vectors recorded from the retired Python receipt payload builder
//! (`tests/fixtures/cloud_receipt_payload/vectors.json`).

use super::cloud_request_vectors_tests::first_difference;
use super::runner_authority_op::dispatch;
use super::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] =
    include_bytes!("../../../../tests/fixtures/cloud_receipt_payload/vectors.json.gz");

#[test]
fn recorded_python_receipts_match_the_resident() {
    let document = gunzip_json(VECTORS);
    assert_eq!(document["version"], 1);
    let vectors = document["vectors"].as_array().unwrap();
    assert!(vectors.len() > 600);
    let mut failures = Vec::new();
    for vector in vectors {
        let kind = vector["kind"].as_str().unwrap();
        let result = dispatch(kind, &vector["args"]);
        let matches = match (&result, vector.get("expected_error")) {
            (Err(code), Some(expected)) => expected == code,
            (Ok(actual), None) => *actual == vector["expected"],
            _ => false,
        };
        if !matches {
            let name = vector["name"].as_str().unwrap();
            eprintln!(
                "ARM|{name}|ok={}|error_key={}",
                result.is_ok(),
                vector.get("expected_error").is_some()
            );
            if let Ok(actual) = &result {
                match first_difference(actual, &vector["expected"], String::new()) {
                    Some((path, recomputed, recorded)) => {
                        eprintln!("DIFF|{name}|{path}|{recomputed}|{recorded}")
                    }
                    None => eprintln!("DIFF|{name}|<equal>||"),
                }
            }
            failures.push(name.to_owned());
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches: {:?}",
        failures.len(),
        &failures[..failures.len().min(20)]
    );
}
