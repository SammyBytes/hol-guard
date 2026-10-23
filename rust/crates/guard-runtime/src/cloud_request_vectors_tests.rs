//! Replays vectors recorded from the retired Python cloud-request projections
//! (`tests/fixtures/cloud_request_authority/vectors.json`).

use serde_json::{json, Value};

use super::cloud_request_text::py_json_len;
use super::runner_authority_op::dispatch;
use super::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] =
    include_bytes!("../../../../tests/fixtures/cloud_request_authority/vectors.json.gz");

fn expand(value: &Value) -> Value {
    match value {
        Value::Object(map) if map.len() == 1 && map.contains_key("$repeat") => {
            let spec = map["$repeat"].as_array().unwrap();
            Value::String(
                spec[0]
                    .as_str()
                    .unwrap()
                    .repeat(spec[1].as_u64().unwrap() as usize),
            )
        }
        Value::Object(map) => {
            Value::Object(map.iter().map(|(k, v)| (k.clone(), expand(v))).collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(expand).collect()),
        other => other.clone(),
    }
}

fn summary(result: &Value) -> Value {
    let requests = result["requests"].as_array().unwrap();
    json!({
        "ids": requests.iter().map(|r| r["localRequestId"].clone()).collect::<Vec<_>>(),
        "flags": [result["pendingComplete"], result["resolvedComplete"], result["pendingCount"], result["resolvedCount"]],
        "request_bytes": requests.iter().map(py_json_len).collect::<Vec<_>>(),
        "key_counts": requests.iter().map(|r| r.as_object().unwrap().len()).collect::<Vec<_>>(),
    })
}

/// The first place two recorded values disagree, as a JSON pointer plus both
/// debug forms. Printing the whole value hides a disagreement that survives
/// serialisation, so the walk reports the exact element instead.
pub(super) fn first_difference(
    left: &Value,
    right: &Value,
    path: String,
) -> Option<(String, String, String)> {
    match (left, right) {
        (Value::Object(left_map), Value::Object(right_map)) => {
            let mut keys: Vec<&String> = left_map.keys().chain(right_map.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                match (left_map.get(key), right_map.get(key)) {
                    (Some(left_value), Some(right_value)) => {
                        if let Some(found) =
                            first_difference(left_value, right_value, format!("{path}/{key}"))
                        {
                            return Some(found);
                        }
                    }
                    (left_value, right_value) => {
                        return Some((
                            format!("{path}/{key}"),
                            format!("{left_value:?}"),
                            format!("{right_value:?}"),
                        ))
                    }
                }
            }
            None
        }
        (Value::Array(left_items), Value::Array(right_items)) => {
            for index in 0..left_items.len().max(right_items.len()) {
                match (left_items.get(index), right_items.get(index)) {
                    (Some(left_value), Some(right_value)) => {
                        if let Some(found) =
                            first_difference(left_value, right_value, format!("{path}/{index}"))
                        {
                            return Some(found);
                        }
                    }
                    (left_value, right_value) => {
                        return Some((
                            format!("{path}/{index}"),
                            format!("{left_value:?}"),
                            format!("{right_value:?}"),
                        ))
                    }
                }
            }
            None
        }
        _ if left == right => None,
        _ => Some((path, format!("{left:?}"), format!("{right:?}"))),
    }
}

#[test]
fn recorded_python_vectors_match_the_resident() {
    let document = gunzip_json(VECTORS);
    assert_eq!(document["version"], 1);
    let vectors = document["vectors"].as_array().unwrap();
    assert!(vectors.len() > 500);
    let mut failures = Vec::new();
    for vector in vectors {
        let kind = vector["kind"].as_str().unwrap();
        let name = vector["name"].as_str().unwrap();
        let result = dispatch(kind, &expand(&vector["args"]));
        let matches = match (&result, vector.get("expected_error")) {
            (Err(code), Some(expected)) => expected == code,
            (Ok(actual), None) if vector["summary"] == true => {
                summary(actual) == vector["expected"]
            }
            (Ok(actual), None) => *actual == vector["expected"],
            _ => false,
        };
        if !matches {
            eprintln!(
                "ARM|{kind}/{name}|ok={}|error_key={}|summary={}",
                result.is_ok(),
                vector.get("expected_error").is_some(),
                vector["summary"]
            );
            if let Ok(actual) = &result {
                let recorded = if vector["summary"] == true {
                    summary(actual)
                } else {
                    actual.clone()
                };
                match first_difference(&recorded, &vector["expected"], String::new()) {
                    Some((path, recomputed, recorded_value)) => {
                        eprintln!("DIFF|{kind}/{name}|{path}|{recomputed}|{recorded_value}")
                    }
                    None => eprintln!("DIFF|{kind}/{name}|<equal>||"),
                }
            }
            failures.push(format!("{kind} / {name}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches: {:?}",
        failures.len(),
        &failures[..failures.len().min(20)]
    );
}

#[test]
fn malformed_arguments_are_typed_refusals() {
    for kind in [
        "cloud_scrub_texts",
        "cloud_sync_texts",
        "cloud_sync_scrub_envelope",
        "cloud_review_event_display",
        "cloud_request_payload",
        "local_request_snapshot",
    ] {
        assert!(
            dispatch(kind, &json!([])).is_err(),
            "{kind} accepted a non-object"
        );
        assert!(
            dispatch(kind, &json!({})).is_err(),
            "{kind} accepted empty args"
        );
    }
    assert!(dispatch("cloud_scrub_texts", &json!({"texts": [1]})).is_err());
    assert!(dispatch(
        "cloud_sync_texts",
        &json!({"items": [{"value": "x", "mode": "other"}]})
    )
    .is_err());
}
