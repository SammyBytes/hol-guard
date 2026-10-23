use super::*;

const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CLI_ID: &str = "local-cli.acme@1+x";

fn connector_value(surface: &str) -> Value {
    json!({
        "cli_id": CLI_ID,
        "identity_hash": HASH,
        "name": " acme ",
        "surface": surface,
        "queue_group_id": format!("connector:{HASH}:0123456789abcdef"),
    })
}

fn connector(surface: &str) -> Connector {
    Connector::parse(&connector_value(surface)).expect("a connector")
}

/// An MCP connector, which the lookup never names but the reason and link
/// rules still cover.
fn mcp_connector() -> Connector {
    Connector {
        surface: "mcp".to_owned(),
        ..connector("cli")
    }
}

fn setup(connector: Connector) -> Setup {
    Setup {
        hint: setup_hint(&connector, &["destructive".to_owned()]),
        connector,
        cause: "unrecognised_tool",
        harness: Some("omp".to_owned()),
        workspace_label: Some("work".to_owned()),
    }
}

#[test]
fn only_the_connector_shape_the_daemon_accepts_parses() {
    assert_eq!(connector("cli").surface, "cli");
    assert_eq!(connector("package-scripts").surface, "package-scripts");
    let mut extra = connector_value("cli");
    extra["extra"] = json!("x");
    let mut missing = connector_value("cli");
    missing.as_object_mut().unwrap().remove("name");
    let mut empty = connector_value("cli");
    empty["name"] = json!("");
    let mut number = connector_value("cli");
    number["cli_id"] = json!(1);
    let mut other_group = connector_value("cli");
    other_group["queue_group_id"] = json!(format!("connector:{}:0123", "b".repeat(64)));
    let mut bare_group = connector_value("cli");
    bare_group["queue_group_id"] = json!(format!("connector:{HASH}"));
    for (tag, value) in [
        ("extra field", extra),
        ("missing field", missing),
        ("empty field", empty),
        ("non-string field", number),
        ("mcp surface", connector_value("mcp")),
        ("unknown surface", connector_value("shell")),
        ("another identity's group", other_group),
        ("group without its prefix", bare_group),
        ("not an object", json!("connector")),
    ] {
        assert_eq!(Connector::parse(&value), None, "{tag}");
    }
}

#[test]
fn the_display_name_is_the_stripped_plain_name_or_a_generic_one() {
    for (name, shown) in [
        (" acme ", "acme"),
        ("@scope/pkg-1.2+b_c", "@scope/pkg-1.2+b_c"),
        ("two words", FALLBACK_NAME),
        ("-leading", FALLBACK_NAME),
        ("rm;id", FALLBACK_NAME),
        ("é", FALLBACK_NAME),
    ] {
        let connector = Connector {
            name: name.to_owned(),
            ..connector("cli")
        };
        assert_eq!(connector.display_name(), shown, "{name}");
    }
    let long = Connector {
        name: "a".repeat(MAX_NAME_CHARS + 1),
        ..connector("cli")
    };
    assert_eq!(long.display_name(), FALLBACK_NAME);
    let longest = Connector {
        name: "a".repeat(MAX_NAME_CHARS),
        ..connector("cli")
    };
    assert_eq!(longest.display_name(), "a".repeat(MAX_NAME_CHARS));
}

#[test]
fn a_setup_row_is_grouped_under_its_connector_with_only_the_setup_hint() {
    let setup = setup(connector("cli"));
    let request = json!({
        "request_id": "r-1",
        "queue_group_id": null,
        "extension_allow_hint": {"schema": "guard.extension-coverage-hint.v1"},
        "risk_summary": "Review this command.",
    });
    let applied = setup.apply(request.clone());
    assert_eq!(
        applied["queue_group_id"],
        json!(format!("connector:{HASH}:0123456789abcdef"))
    );
    assert_eq!(applied["extension_allow_hint"], setup.hint);
    for key in ["request_id", "risk_summary"] {
        assert_eq!(applied[key], request[key], "{key}");
    }
}

#[test]
fn the_setup_hint_is_the_daemon_connector_hint() {
    let hint = setup_hint(
        &connector("cli"),
        &["destructive".to_owned(), "network".to_owned()],
    );
    assert_eq!(
        hint,
        json!({
            "schema": "guard.connector-setup-hint.v1",
            "identity_hash": HASH,
            "cli_id": CLI_ID,
            "surface": "cli",
            "display_name": "acme",
            "deep_link": "/extensions/local-cli/local-cli.acme%401%2Bx",
            "card_recommendation": {"state": "allowed", "capabilities": []},
            "risk_classes": ["destructive", "network"],
        })
    );
}

#[test]
fn a_connector_the_hint_cannot_name_records_no_hint() {
    let base = connector("cli");
    for (tag, connector) in [
        (
            "upper-case identity",
            Connector {
                identity_hash: HASH.to_uppercase(),
                ..base.clone()
            },
        ),
        (
            "short identity",
            Connector {
                identity_hash: "a".repeat(63),
                ..base.clone()
            },
        ),
        (
            "unprefixed cli id",
            Connector {
                cli_id: "acme".to_owned(),
                ..base.clone()
            },
        ),
        (
            "cli id with a slash",
            Connector {
                cli_id: "local-cli.a/b".to_owned(),
                ..base.clone()
            },
        ),
        (
            "unknown surface",
            Connector {
                surface: "shell".to_owned(),
                ..base.clone()
            },
        ),
    ] {
        assert_eq!(setup_hint(&connector, &[]), Value::Null, "{tag}");
    }
    // The generic name is a valid display name, so the hint keeps it.
    let generic = Connector {
        name: "two words".to_owned(),
        ..base
    };
    assert_eq!(
        setup_hint(&generic, &[])["display_name"],
        json!(FALLBACK_NAME)
    );
}

#[test]
fn the_deep_link_quotes_every_byte_python_quotes() {
    assert_eq!(
        hint::deep_link("local-cli.a_b.c-d~e"),
        "/extensions/local-cli/local-cli.a_b.c-d~e"
    );
    assert_eq!(
        hint::deep_link("local-cli.@+/ é"),
        "/extensions/local-cli/local-cli.%40%2B%2F%20%C3%A9"
    );
}

#[test]
fn risk_classes_are_the_ones_python_keeps() {
    for (class, kept) in [
        ("destructive", true),
        ("network_write", true),
        ("a1", true),
        ("Upper", false),
        ("1lead", false),
        ("has-dash", false),
        ("", false),
    ] {
        assert_eq!(hint::risk_class(class), kept, "{class}");
    }
    assert!(hint::risk_class(&"a".repeat(64)));
    assert!(!hint::risk_class(&"a".repeat(65)));
    let result = Object::new();
    assert_eq!(
        observed_risk_classes(&result).unwrap(),
        Vec::<String>::new()
    );
    // Python's `strip` removes a file separator that Rust's `trim` keeps.
    let separator = json!({"command_extensions": {"observations": [{"rule_id": "rule\u{1c}"}]}});
    assert!(matches!(
        observed_risk_classes(separator.as_object().unwrap()),
        Err(HookDirectDefer::ReviewQueue)
    ));
}

#[test]
fn the_agent_sees_the_setup_reason_the_daemon_writes() {
    let local = connector("cli");
    // Bound: an ordinary approvable review in either mode.
    let approvable = connector_setup_reason("acme", "cli", true, &[], true);
    assert_eq!(
        local.reason(true, true, true).as_deref(),
        Some(approvable.as_str())
    );
    assert_eq!(
        local.reason(false, true, false).as_deref(),
        Some(approvable.as_str())
    );
    // Unbound with no exact action: approval cannot release it.
    assert_eq!(
        local.reason(true, false, false),
        Some(connector_setup_reason("acme", "cli", false, &[], false))
    );
    assert_eq!(
        local.reason(false, false, false),
        Some(connector_setup_reason("acme", "cli", false, &[], false))
    );
    // Unbound with an exact action: the ordinary review text says it.
    assert_eq!(local.reason(true, false, true), None);
    assert_eq!(local.reason(false, false, true), None);
    // An MCP setup review asks to set the server up, and only in ask mode.
    let mcp = mcp_connector();
    assert_eq!(
        mcp.reason(true, false, true),
        Some(connector_setup_reason("acme", "mcp", true, &[], false))
    );
    assert_eq!(
        mcp.reason(false, false, true),
        Some(connector_setup_reason("acme", "mcp", false, &[], false))
    );
    assert!(mcp
        .reason(true, true, true)
        .unwrap()
        .starts_with("HOL Guard has not been set up for `acme` (MCP server) on this device."));
}

#[test]
fn the_link_follows_whether_approval_can_release_the_row() {
    let local = connector("cli");
    let mcp = mcp_connector();
    for ask in [false, true] {
        for bound in [false, true] {
            for exact in [false, true] {
                let unblock = bound || exact;
                assert_eq!(
                    links_connector(None, None, ask, bound, exact),
                    unblock,
                    "no connector {ask} {bound} {exact}"
                );
                let reason = local.reason(ask, bound, exact);
                assert_eq!(
                    links_connector(Some(&local), reason.as_deref(), ask, bound, exact),
                    unblock,
                    "local {ask} {bound} {exact}"
                );
                let reason = mcp.reason(ask, bound, exact);
                assert_eq!(
                    links_connector(Some(&mcp), reason.as_deref(), ask, bound, exact),
                    unblock && ask,
                    "mcp {ask} {bound} {exact}"
                );
            }
        }
    }
    let local = setup(connector("cli"));
    assert!(links(Some(&local), false, true, false));
    assert!(!links(Some(&local), false, false, false));
    assert!(links(None, false, false, true));
    assert!(!links(None, true, false, false));
}

#[test]
fn the_longest_reason_bounds_every_reason_a_connector_can_give() {
    for ask in [false, true] {
        for bound in [false, true] {
            for exact in [false, true] {
                let longest = longest_reason(ask, bound, exact);
                assert_eq!(longest.is_none(), !bound && exact, "{ask} {bound} {exact}");
                for surface in LOCAL_SURFACES {
                    let longest_name = "a".repeat(MAX_NAME_CHARS);
                    for name in ["acme", longest_name.as_str(), "two words"] {
                        let connector = Connector {
                            name: name.to_owned(),
                            ..connector(surface)
                        };
                        let reason = connector.reason(ask, bound, exact);
                        assert_eq!(reason.is_none(), longest.is_none());
                        if let (Some(reason), Some(longest)) = (reason, &longest) {
                            assert!(reason.len() <= longest.len(), "{surface} {name}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn a_lookup_that_fails_defers_and_one_that_names_no_review_connector_does_not() {
    assert!(matches!(
        from_refined(Err("local_cli_hook_failed")),
        Err(HookDirectDefer::ReviewQueue)
    ));
    assert_eq!(from_refined(Ok(named())).unwrap(), Some(connector("cli")));
    let allowed = Refined {
        action: "allow".to_owned(),
        ..named()
    };
    assert_eq!(from_refined(Ok(allowed)).unwrap(), None);
    let granted = Refined {
        contained_grant: Some(json!({"grant": true})),
        ..named()
    };
    assert_eq!(from_refined(Ok(granted)).unwrap(), None);
    let invalid = Refined {
        connector: Some(connector_value("mcp")),
        ..named()
    };
    assert_eq!(from_refined(Ok(invalid)).unwrap(), None);
    assert_eq!(from_refined(Ok(Refined::default())).unwrap(), None);
}

/// A `review` reply that names a local CLI connector.
fn named() -> Refined {
    Refined {
        action: REVIEW_ACTION.to_owned(),
        connector: Some(connector_value("cli")),
        contained_grant: None,
    }
}

#[test]
fn the_first_blocked_cause_is_the_daemon_map() {
    assert_eq!(
        first_blocked_cause(Some("native_command_review_required")),
        Some("unrecognised_tool")
    );
    assert_eq!(
        first_blocked_cause(Some(
            "native_workspace_containment_executable_outside_roots"
        )),
        Some("exec_outside_roots")
    );
    assert_eq!(first_blocked_cause(Some("native_review")), None);
    assert_eq!(first_blocked_cause(None), None);
}

#[test]
fn only_printable_ascii_labels_are_scrubbed_here() {
    assert_eq!(label("omp").unwrap().as_deref(), Some("omp"));
    assert!(matches!(label("café"), Err(HookDirectDefer::ReviewQueue)));
    assert!(matches!(label("a\tb"), Err(HookDirectDefer::ReviewQueue)));
}

#[cfg(unix)]
#[test]
fn only_paths_pathlib_spells_as_given_are_sent() {
    for (path, normal) in [
        ("/", true),
        ("/a/b", true),
        ("/a/b c", true),
        ("/a/", false),
        ("/a//b", false),
        ("/a/./b", false),
        ("//a", false),
        ("a/b", false),
        ("", false),
    ] {
        assert_eq!(pathlib_normal(path), normal, "{path}");
    }
    assert_eq!(pathlib_name("/a/work"), "work");
    assert_eq!(pathlib_name("/"), "");
}

#[cfg(unix)]
fn with_context<T>(tag: &str, payload: Value, run: impl FnOnce(&Context<'_>, &str) -> T) -> T {
    let binding = super::super::super::tests::binding();
    let workspace = super::super::super::tests::workspace(tag);
    let mut payload = payload;
    if payload.get("cwd").is_none() {
        payload["cwd"] = json!(workspace);
    }
    let payload = payload.as_object().unwrap().clone();
    let context = Context {
        harness: "omp",
        payload: &payload,
        recorded_payload: &payload,
        workspace: &workspace,
        home_dir: "/home/user",
        guard_home: "/guard-home",
        binding: &binding,
        hint: None,
    };
    let answer = run(&context, &workspace);
    std::fs::remove_dir_all(&workspace).ok();
    answer
}

#[cfg(unix)]
fn environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("HOME".to_owned(), "/home/user/".to_owned()),
        ("PATH".to_owned(), "/daemon/bin".to_owned()),
        ("LANG".to_owned(), "C".to_owned()),
    ])
}

#[cfg(unix)]
#[test]
fn a_non_recognition_review_prepares_the_daemon_lookup() {
    let payload = json!({
        "tool_name": "Bash",
        "tool_input": {"command": "acme sync"},
        "guard_execution_environment": {"path": "/agent/bin"},
    });
    let result = json!({"reason_code": "native_command_review_required"});
    with_context("connector-prepare", payload, |context, workspace| {
        let lookup = prepare(
            context,
            result.as_object().unwrap(),
            &environment(),
            "oauth",
        )
        .unwrap()
        .expect("a lookup");
        let request = &lookup.request;
        assert_eq!(request.schema, LOCAL_CLI_HOOK_REQUEST_SCHEMA);
        assert!(request.request_id.starts_with("local-cli-hook-"));
        assert_eq!(request.request_id.len(), "local-cli-hook-".len() + 32);
        assert_eq!(request.store_path, "/guard-home/guard.db");
        assert_eq!(request.guard_home, "/guard-home");
        assert_eq!(request.source, "oauth");
        assert_eq!(request.busy_timeout_ms, BUSY_TIMEOUT_MS);
        assert_eq!(request.command, "acme sync");
        assert_eq!(request.cwd, workspace);
        assert_eq!(request.home_dir.as_deref(), Some("/home/user"));
        assert_eq!(request.user_home, "/home/user");
        assert_eq!(request.env["PATH"], "/agent/bin");
        assert_eq!(request.env["LANG"], "C");
        assert_eq!(request.current_action, REVIEW_ACTION);
        assert_eq!(request.current_reason_code, None);
        assert!(request.grant_allowed);
        assert_eq!(lookup.cause, "unrecognised_tool");
        assert_eq!(lookup.harness.as_deref(), Some("omp"));
        assert_eq!(
            lookup.workspace_label,
            scrub_context_text(pathlib_name(workspace), MAX_LABEL_CHARS)
        );
        assert!(lookup.risk_classes.is_empty());
    });
}

#[cfg(unix)]
#[test]
fn a_review_without_a_connector_candidate_looks_nothing_up() {
    let payload = json!({"tool_name": "Bash", "tool_input": {"command": "acme sync"}});
    with_context("connector-ordinary", payload, |context, _| {
        for result in [
            json!({"reason_code": "native_review"}),
            json!({}),
            json!({"reason_code": null}),
        ] {
            assert!(prepare(
                context,
                result.as_object().unwrap(),
                &environment(),
                "oauth"
            )
            .unwrap()
            .is_none());
        }
    });
    let no_command = json!({"tool_name": "Read", "tool_input": {"file_path": "/a"}});
    with_context("connector-no-command", no_command, |context, _| {
        let result = json!({"reason_code": "native_command_review_required"});
        assert!(prepare(
            context,
            result.as_object().unwrap(),
            &environment(),
            "oauth"
        )
        .unwrap()
        .is_none());
    });
    let relative = json!({"tool_name": "Bash", "tool_input": {"command": "acme"}, "cwd": "rel"});
    with_context("connector-relative", relative, |context, _| {
        let result = json!({"reason_code": "native_command_review_required"});
        assert!(prepare(
            context,
            result.as_object().unwrap(),
            &environment(),
            "oauth"
        )
        .unwrap()
        .is_none());
    });
}

#[cfg(unix)]
#[test]
fn a_lookup_the_resident_cannot_spell_as_the_daemon_defers() {
    let payload = json!({"tool_name": "Bash", "tool_input": {"command": "acme sync"}});
    with_context("connector-defer", payload.clone(), |context, _| {
        let unhashable = json!({"reason_code": ["native_command_review_required"]});
        assert!(matches!(
            prepare(
                context,
                unhashable.as_object().unwrap(),
                &environment(),
                "oauth"
            ),
            Err(HookDirectDefer::ReviewQueue)
        ));
        let result = json!({"reason_code": "native_command_review_required"});
        let mut homeless = environment();
        homeless.remove("HOME");
        assert!(matches!(
            prepare(context, result.as_object().unwrap(), &homeless, "oauth"),
            Err(HookDirectDefer::ReviewQueue)
        ));
    });
    let mut nul = payload;
    nul["cwd"] = json!("/tmp/a\u{0}b");
    with_context("connector-nul", nul, |context, _| {
        let result = json!({"reason_code": "native_command_review_required"});
        assert!(matches!(
            prepare(
                context,
                result.as_object().unwrap(),
                &environment(),
                "oauth"
            ),
            Err(HookDirectDefer::ReviewQueue)
        ));
    });
}
