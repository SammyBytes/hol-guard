"""Regression coverage for nested sensitive metadata in the serializer."""

from __future__ import annotations

import copy
import json

import pytest

from codex_plugin_scanner.guard.inventory_contract_redaction import _safe_json


@pytest.mark.security_critical
@pytest.mark.parametrize("sensitive_parent", [False, True])
def test_nested_sensitive_metadata_keeps_all_sibling_keys(sensitive_parent: bool) -> None:
    """Keep every nested field while redacting its sensitive values without modifying the input."""
    source = {
        "tokenInfo": {
            "primary": {"value": "first-private-value", "note": "first-private-note"},
            "secondary": {"value": "second-private-value", "note": "second-private-note"},
            "history": [{"left": "third-private-value", "right": "fourth-private-value"}],
        }
    }
    original = copy.deepcopy(source)
    result = _safe_json(source, parent_sensitive=sensitive_parent)
    assert result == {
        "tokenInfo": {
            "primary": {"value": "[REDACTED]", "note": "[REDACTED]"},
            "secondary": {"value": "[REDACTED]", "note": "[REDACTED]"},
            "history": [{"left": "[REDACTED]", "right": "[REDACTED]"}],
        }
    }
    assert source == original
    assert "private-value" not in json.dumps(result)
    assert "private-note" not in json.dumps(result)


def test_sensitive_ancestor_does_not_disable_unsafe_key_redaction() -> None:
    """Preserve structural names, not literal secrets embedded in a key itself."""
    result = _safe_json({"safeField": "private-value", "sk-secret-key": "another-private-value"}, parent_sensitive=True)
    assert result == {"safeField": "[REDACTED]", "[REDACTED]": "[REDACTED]"}


def test_an_export_asks_for_every_metadata_value_in_the_prefetched_batch(monkeypatch, tmp_path) -> None:
    """Pin that the batch covers the walk: one request, then no further asks."""
    from dataclasses import dataclass, field
    from pathlib import Path

    from codex_plugin_scanner.guard import native_inventory_url_redaction as native_url
    from codex_plugin_scanner.guard.inventory_contract_redaction import (
        _prefetch_artifact_redactions,
        _safe_artifact_metadata,
    )

    requests: list[list[dict[str, object]]] = []

    def answers(tasks, *, guard_home=None, timeout_seconds=10.0):
        requests.append(list(tasks))
        return ["redacted" for _ in tasks]

    monkeypatch.setattr(native_url, "_answers", answers)

    @dataclass
    class Artifact:
        artifact_type: str = "mcp_server"
        config_path: str | None = None
        command: str | None = None
        url: str | None = None
        transport: str | None = None
        metadata: dict[str, object] = field(default_factory=dict)

    home = tmp_path / "home"
    artifacts = (
        Artifact(
            config_path=f"{home}/.config/one.json",
            command="npx server --root /private/root",
            url="https://one.example.test/path?token=abc",
            metadata={
                "entry": f"{home}/.config/entry.py",
                "nested": {"path": Path(f"{home}/.config/nested.py"), "endpoint": "https://two.example.test"},
                "items": [f"{home}/.config/list.py", "https://three.example.test"],
                "apiToken": "private-value",
            },
        ),
        Artifact(artifact_type="skill", config_path=f"{home}/.config/two.json"),
    )
    with native_url.redaction_pass():
        _prefetch_artifact_redactions(artifacts, home_dir=home, workspace_dir=None)
        prefetched = len(requests)
        for artifact in artifacts:
            _safe_artifact_metadata(artifact, home_dir=home, workspace_dir=None)
    assert prefetched == 1
    assert len(requests) == prefetched
