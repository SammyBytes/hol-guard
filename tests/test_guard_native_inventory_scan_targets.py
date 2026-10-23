"""The inventory scan-target bridge carries context and keeps no fallback.

Which configurations a pass opens is the resident's answer. These tests pin
what reaches it, what comes back, and that a resident that cannot answer leaves
the caller with nothing to scan rather than a selection made here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_inventory_scan_targets as bridge
from codex_plugin_scanner.guard.adapters.base import GuardArtifact


def _resident(monkeypatch: pytest.MonkeyPatch, reply) -> list[dict[str, object]]:
    """Stub the transport; the returned list records every request wire sent."""

    sent: list[dict[str, object]] = []
    monkeypatch.setattr(bridge, "_resolve_digest_home", lambda _home: Path("/tmp/scan-targets-home"))
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: True)

    def fake(*, request, **_kwargs):
        sent.append(request)
        return reply(request)

    monkeypatch.setattr(bridge, "_resident_request", fake)
    monkeypatch.setattr(bridge, "_payload", lambda response, _request, _home: response)
    return sent


def _empty(_request: dict[str, object]) -> dict[str, object]:
    return {"mcp_targets": [], "skill_roots": []}


def _ask(**kwargs):
    arguments: dict[str, object] = {
        "harness": "codex",
        "home_dir": Path("/h"),
        "workspace_dir": Path("/w"),
        "artifacts": (),
        "cwd": Path("/c"),
    }
    arguments.update(kwargs)
    return bridge.native_inventory_scan_targets(**arguments)


def _skill(config_path: str, *, skill_root: str | None = None) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=f"codex:skill:{config_path}",
        name="reviewer",
        harness="codex",
        artifact_type="skill",
        source_scope="global",
        config_path=config_path,
        metadata={} if skill_root is None else {"skill_root": skill_root},
    )


def test_the_wire_carries_the_directories_the_selection_is_made_against(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = _resident(monkeypatch, _empty)
    _ask()
    (wire,) = sent
    assert wire["schema"] == "guard-inventory-scan-targets-request.v1"
    assert wire["harness"] == "codex"
    assert wire["home_dir"] == "/h"
    assert wire["workspace_dir"] == "/w"
    assert wire["cwd"] == "/c"
    assert wire["artifacts"] == []


def test_the_callers_own_directory_travels_so_relative_paths_mean_what_it_meant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = _resident(monkeypatch, _empty)
    _ask(cwd=None)
    assert sent[0]["cwd"] == str(Path.cwd())


def test_a_workspace_the_caller_does_not_have_is_left_out(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _empty)
    _ask(workspace_dir=None)
    assert "workspace_dir" not in sent[0]


def test_a_skill_artifact_ships_its_path_and_its_recorded_collection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = _resident(monkeypatch, _empty)
    _ask(artifacts=(_skill("/w/skills/reviewer/SKILL.md", skill_root="/w/skills"),))
    assert sent[0]["artifacts"] == [
        {
            "artifact_type": "skill",
            "config_path": "/w/skills/reviewer/SKILL.md",
            "skill_root": "/w/skills",
        }
    ]


def test_an_mcp_artifact_ships_no_skill_root(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _empty)
    artifact = GuardArtifact(
        artifact_id="cursor:project:mcp:demo",
        name="demo",
        harness="cursor",
        artifact_type="mcp_server",
        source_scope="project",
        config_path="/w/.cursor/mcp.json",
        metadata={"skill_root": "/w/skills"},
    )
    _ask(artifacts=(artifact,))
    assert sent[0]["artifacts"] == [
        {"artifact_type": "mcp_server", "config_path": "/w/.cursor/mcp.json"}
    ]


def test_an_artifact_the_selection_never_reads_is_not_carried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The request is bounded; a package would spend that bound for nothing."""

    sent = _resident(monkeypatch, _empty)
    artifact = GuardArtifact(
        artifact_id="codex:package:left-pad",
        name="left-pad",
        harness="codex",
        artifact_type="package",
        source_scope="global",
        config_path="/w/package.json",
    )
    _ask(artifacts=(artifact,))
    assert sent[0]["artifacts"] == []


def test_an_artifact_without_a_configuration_path_omits_the_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = _resident(monkeypatch, _empty)
    artifact = GuardArtifact(
        artifact_id="codex:skill:unknown",
        name="unknown",
        harness="codex",
        artifact_type="skill",
        source_scope="global",
        config_path=None,
    )
    _ask(artifacts=(artifact,))
    assert sent[0]["artifacts"] == [{"artifact_type": "skill"}]


def test_the_answer_comes_back_in_the_residents_own_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _resident(
        monkeypatch,
        lambda _request: {
            "mcp_targets": [
                {"root": "/w", "config_path": "/w/.mcp.json", "label": ".mcp.json"},
                {
                    "root": "/h/other",
                    "config_path": "/h/other/.mcp.json",
                    "label": ".mcp.json",
                },
            ],
            "skill_roots": ["/w/skills", "/h/.agents/skills"],
        },
    )
    targets = _ask()
    assert [target.root for target in targets.mcp_targets] == [Path("/w"), Path("/h/other")]
    assert [target.config_path for target in targets.mcp_targets] == [
        Path("/w/.mcp.json"),
        Path("/h/other/.mcp.json"),
    ]
    assert [target.label for target in targets.mcp_targets] == [".mcp.json", ".mcp.json"]
    assert targets.skill_roots == (Path("/w/skills"), Path("/h/.agents/skills"))


def test_the_deadline_grows_with_the_detection_and_stops_at_the_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert bridge._request_timeout_seconds(0) == 15.0
    assert bridge._request_timeout_seconds(100) == 17.0
    assert bridge._request_timeout_seconds(1_000_000) == 60.0


@pytest.mark.parametrize(
    "payload",
    [
        {"mcp_targets": "all", "skill_roots": []},
        {"mcp_targets": ["/w/.mcp.json"], "skill_roots": []},
        {"mcp_targets": [{"root": "/w", "config_path": "/w/.mcp.json"}], "skill_roots": []},
        {"mcp_targets": [], "skill_roots": "all"},
        {"mcp_targets": [], "skill_roots": [{"root": "/w/skills"}]},
        {"mcp_targets": [], "skill_roots": [None]},
    ],
)
def test_a_malformed_answer_is_no_selection_at_all(
    monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]
) -> None:
    _resident(monkeypatch, lambda _request: payload)
    with pytest.raises(bridge.InventoryScanTargetsUnavailableError):
        _ask()


def test_a_resident_that_cannot_answer_leaves_the_caller_with_no_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bridge, "_resolve_digest_home", lambda _home: Path("/tmp/scan-targets-home"))
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(bridge.InventoryScanTargetsUnavailableError):
        _ask()


def test_a_transport_failure_is_not_turned_into_an_empty_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(_request: dict[str, object]) -> dict[str, object]:
        raise RuntimeError("resident gone")

    _resident(monkeypatch, fail)
    with pytest.raises(bridge.InventoryScanTargetsUnavailableError):
        _ask()
