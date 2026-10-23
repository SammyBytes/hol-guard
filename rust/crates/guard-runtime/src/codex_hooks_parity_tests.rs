//! Replays `tests/fixtures/codex-hook-inventory.v1.json`, recorded from
//! `codex_hook_inventory.py`. The CLI install path reads that Python inventory
//! and detection reads this one, so the shapes each refuses, the coordinates it
//! names and the repair wording it uses have to stay identical on both routes.
//!
//! The fixture pins the issues each shape produces and, for every record the
//! walk keeps, its coordinate and the two flags that decide whether the hook
//! runs. It records no identity: a record carries the identity the resident
//! derives for it, which no fixture can replay, while the shape walk that
//! produces these coordinates is ordinary code on both sides.

use serde_json::Value;

use crate::codex_hooks::{enumerate, Source};
use crate::codex_value::HookVal;
use crate::pyjson;

const FIXTURE: &str = include_str!("../../../../tests/fixtures/codex-hook-inventory.v1.json");

fn payload(value: &Value) -> HookVal {
    let text = serde_json::to_string(value).expect("payload json");
    let parsed = pyjson::parse(&text).expect("payload parses as python json");
    HookVal::from_py(&parsed)
}

fn format_of(name: &str) -> &'static str {
    match name {
        "json" => "json",
        "toml" => "toml",
        other => panic!("unsupported source format {other}"),
    }
}

fn bindings(case: &Value, key: &str) -> Vec<Value> {
    case[key].as_array().expect("bindings array").clone()
}

#[test]
fn recorded_shape_issues_still_describe_the_source() {
    let document: Value = serde_json::from_str(FIXTURE).expect("fixture json");
    assert_eq!(document["schema"], "codex-hook-inventory-parity.v1");
    let cases = document["cases"].as_array().expect("cases");
    assert!(!cases.is_empty(), "the fixture records no cases");
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let source = &case["source"];
        let authenticated = bindings(case, "authenticated");
        let legacy = bindings(case, "legacy");
        let inventory = enumerate(
            &payload(&case["payload"]),
            Source {
                path: source["path"].as_str().expect("path"),
                scope: source["scope"].as_str().expect("scope"),
                format: format_of(source["format"].as_str().expect("format")),
                hooks_enabled: source["hooks_enabled"].as_bool().expect("hooks_enabled"),
            },
            &authenticated,
            &legacy,
        );
        let expected: Vec<&str> = case["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .map(|warning| warning.as_str().expect("warning"))
            .collect();
        assert_eq!(inventory.warnings, expected, "{name}");

        let recorded: Vec<Value> = inventory
            .records
            .iter()
            .map(|record| {
                serde_json::json!({
                    "coordinate": record.coordinate(),
                    "active": record.active,
                    "executable": record.executable,
                })
            })
            .collect();
        let expected_records = case["records"].as_array().expect("records");
        assert_eq!(&recorded, expected_records, "{name}");
    }
}
