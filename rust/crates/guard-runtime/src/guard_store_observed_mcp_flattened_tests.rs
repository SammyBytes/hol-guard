//! Oh My Pi presents an MCP tool under one flattened name, so the connector it
//! was catalogued under is the only thing that says where the server ends.
//! `src/codex_plugin_scanner/guard/runtime/observed_mcp_tools.py::_flattened_tool`
//! parses the same shape from the harness's configured server list, and
//! `tests/test_guard_omp_observed_mcp_tools.py` is its contract.

use rusqlite::Connection;
use serde_json::{json, Value};

use super::{flattened_tool, observed_mcp_tool_actions, ObservedTool};

const NAMESPACE: &str = "mcp__truenas-pilot__";
const CLI_ID: &str = "local-cli.mcp-omp";
const SEEN_AT: &str = "2026-10-11T10:00:00+00:00";

fn parse(tool_name: &str) -> Option<ObservedTool> {
    flattened_tool("omp", tool_name, NAMESPACE)
}

#[test]
fn a_flattened_name_takes_its_boundary_from_the_connector() {
    let tool = parse("mcp__truenas_pilot_status").expect("the connector names the server");
    assert_eq!(tool.namespace, NAMESPACE);
    assert_eq!(tool.qualified_name, "mcp__truenas_pilot_status");
    assert_eq!(tool.harness, "omp");
}

#[test]
fn only_a_harness_that_flattens_reads_a_name_this_way() {
    for harness in ["claude-code", "codex", "opencode", "cursor"] {
        assert!(
            flattened_tool(harness, "mcp__truenas_pilot_status", NAMESPACE).is_none(),
            "{harness} does not flatten MCP tool names"
        );
    }
}

#[test]
fn a_name_that_already_carries_its_boundary_is_not_read_as_flattened() {
    // The two parses stay disjoint: this one belongs to `observed_mcp_tool`.
    assert!(parse("mcp__truenas-pilot__status").is_none());
    assert!(parse("mcp__truenas_pilot__status").is_none());
}

#[test]
fn a_name_that_is_only_the_server_leaves_no_tool() {
    assert!(parse("mcp__truenas_pilot").is_none());
    assert!(parse("mcp__truenas_pilot_").is_none());
}

#[test]
fn a_name_under_another_server_is_refused() {
    assert!(parse("mcp__other_status").is_none());
    assert!(parse("mcp__truenas_pilotstatus").is_none());
    assert!(parse("status").is_none());
}

#[test]
fn a_server_whose_flattened_form_ends_in_an_underscore_captures_nothing() {
    // `foo_` joined to `bar` and `foo` joined to `_bar` are the same text.
    assert!(flattened_tool("omp", "mcp__foo__bar", "mcp__foo___").is_none());
    assert!(flattened_tool("omp", "mcp__foo_bar", "mcp__foo-__").is_none());
}

fn seed(connection: &Connection, grant_state: &str, command_states: &[(&str, &str)]) {
    let recorded: Value = serde_json::from_str(include_str!(
        "../testdata/local_mcp/observed_mcp_tool_actions_vectors.json"
    ))
    .unwrap();
    for statement in recorded["schema"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    let hash = ObservedTool {
        namespace: NAMESPACE.to_owned(),
        qualified_name: String::new(),
        harness: "omp".to_owned(),
    }
    .server_identity_hash();
    connection
        .execute(
            "insert into local_cli_schema_migration values (1, 11, 'test')",
            [],
        )
        .unwrap();
    connection
        .execute(
            "insert into local_cli_observation \
             (cli_id, identity_hash, kind, name, example_label, observed_count, last_seen_at, \
              surface, server_command, server_identity_hash) \
             values (?1, ?2, 'executable', 'truenas-pilot', ?3, 1, ?4, 'mcp', ?5, ?2)",
            rusqlite::params![
                CLI_ID,
                hash,
                NAMESPACE,
                SEEN_AT,
                format!("observed-mcp:omp:{NAMESPACE}"),
            ],
        )
        .unwrap();
    connection
        .execute(
            "insert into local_cli_grant values (?1, ?2, ?3, 1, ?4)",
            rusqlite::params![CLI_ID, hash, grant_state, SEEN_AT],
        )
        .unwrap();
    for (index, (usage, state)) in command_states.iter().enumerate() {
        let command_id = ObservedTool {
            namespace: NAMESPACE.to_owned(),
            qualified_name: (*usage).to_owned(),
            harness: "omp".to_owned(),
        }
        .command_id();
        connection
            .execute(
                "insert into local_cli_command \
                 (cli_id, command_id, name, usage, description, sort_index) \
                 values (?1, ?2, 'tool', ?3, 'Observed tool', ?4)",
                rusqlite::params![CLI_ID, command_id, usage, index as i64],
            )
            .unwrap();
        connection
            .execute(
                "insert into local_cli_command_grant values (?1, ?2, ?3)",
                rusqlite::params![CLI_ID, command_id, state],
            )
            .unwrap();
    }
}

#[test]
fn an_exact_choice_on_a_flattened_tool_reaches_the_snapshot() {
    let connection = Connection::open_in_memory().unwrap();
    seed(
        &connection,
        "allowed",
        &[
            ("mcp__truenas_pilot_status", "allow"),
            ("mcp__truenas_pilot_restart", "block"),
        ],
    );
    assert_eq!(
        observed_mcp_tool_actions(&connection).unwrap(),
        json!({
            "omp:mcp__truenas_pilot_restart": "block",
            "omp:mcp__truenas_pilot_status": "allow",
        })
    );
}

#[test]
fn blocking_the_connector_blocks_every_flattened_tool_it_was_blocked_over() {
    let connection = Connection::open_in_memory().unwrap();
    seed(
        &connection,
        "blocked",
        &[
            ("mcp__truenas_pilot_status", "allow"),
            ("mcp__truenas_pilot_restart", "inherit"),
        ],
    );
    // The connector's own selector never matches a flattened name, so each
    // catalogued tool has to carry the block itself.
    assert_eq!(
        observed_mcp_tool_actions(&connection).unwrap(),
        json!({
            "omp:mcp__truenas-pilot__*": "block",
            "omp:mcp__truenas_pilot_restart": "block",
            "omp:mcp__truenas_pilot_status": "block",
        })
    );
}
