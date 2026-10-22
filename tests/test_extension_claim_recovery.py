"""Recovery survives transient reads and runs independently of pack publication."""

from __future__ import annotations

import io
import json
import sys
import urllib.error
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.extension_claim_notice_harness import MODULE, listing

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
try:
    import plan_extension_claim_recovery as recovery
finally:
    sys.path.pop(0)


@dataclass(frozen=True)
class Claimant:
    github_id: str = "100"
    pull_request: int = 7


@pytest.mark.parametrize("failure", [500, 502, 503, 504, 429, "connection"])
def test_transient_read_is_retried(monkeypatch, failure):
    calls, waits = [], []

    def request(*args, **kwargs):
        calls.append(args[0].method)
        if len(calls) == 1:
            if failure == "connection":
                raise OSError("connection reset")
            raise urllib.error.HTTPError(args[0].full_url, failure, "unavailable", {}, io.BytesIO(b"retry"))
        return io.BytesIO(b'{"default_branch":"main"}')

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", request)
    monkeypatch.setattr(MODULE.time, "sleep", waits.append)
    client = MODULE.GitHubApi("test-token", "example/repo")
    assert client.repo_metadata() == {"default_branch": "main"}
    assert calls == ["GET", "GET"]
    assert waits == [1]


@pytest.mark.parametrize(
    "method,status,expected_calls", [("GET", 503, 3), ("GET", 403, 1), ("POST", 503, 1), ("PATCH", 503, 1)],
)
def test_retries_are_bounded_and_never_repeat_writes(monkeypatch, method, status, expected_calls):
    calls = []

    def request(*args, **kwargs):
        calls.append(1)
        raise urllib.error.HTTPError(args[0].full_url, status, "unavailable", {}, io.BytesIO(b"failure"))

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", request)
    monkeypatch.setattr(MODULE.time, "sleep", lambda _: None)
    client = MODULE.GitHubApi("test-token", "example/repo")
    with pytest.raises(MODULE.ClaimNoticeError, match=f"GitHub API {status}"):
        client._request(client.base_url, method=method)
    assert len(calls) == expected_calls


def test_inventory_groups_authored_and_descriptor_paths_and_excludes_first_party(tmp_path):
    for folder, identity in [("command-sources", "command.example"), ("extensions", "command.example"),
                             ("mcp-servers", "mcp.example"), ("extensions", "command.core")]:
        path = tmp_path / "contributions" / folder / f"{identity}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}")
    for identity, trust in [
        ("command.example", "external"), ("command.mcp-example", "external"), ("command.core", "first-party"),
    ]:
        path = tmp_path / "contracts/extensions/trust" / f"{identity}.v1.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "schemaVersion": "guard.extension-trust-binding.v1", "extension": identity, "trustClass": trust,
        }))
    assert recovery.external_sources(tmp_path) == {
        "command.example": [
            "contributions/extensions/command.example.json", "contributions/command-sources/command.example.json",
        ],
        "mcp.example": ["contributions/mcp-servers/mcp.example.json"],
    }


def test_plan_uses_original_owner_and_respects_explicit_revocation(tmp_path, monkeypatch):
    sources = {"command.original": ["source"], "command.revoked": ["source"], "command.reassigned": ["source"]}
    for identity, ids in [("command.revoked", []), ("command.reassigned", ["200"])]:
        path = tmp_path / "contributions/extension-listings" / f"{identity}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(listing(identity, ids)))
    monkeypatch.setattr(
        recovery, "resolve_initial_contribution", lambda *args: Claimant(),
    )
    assert recovery.invitation_entries(object(), tmp_path, sources, "a" * 40) == [
        {"extensionId": "command.original", "githubId": "100", "pullRequest": 7}
    ]


def test_ambiguous_history_does_not_block_unrelated_recovery(tmp_path, monkeypatch, capsys):
    def resolve(history, paths, sha):
        if paths == ["ambiguous"]:
            raise recovery.ClaimProvenanceError("reused path")
        return Claimant()

    monkeypatch.setattr(recovery, "resolve_initial_contribution", resolve)
    rows = recovery.invitation_entries(
        object(), tmp_path, {"command.bad": ["ambiguous"], "command.good": ["source"]}, "a" * 40,
    )
    assert [row["extensionId"] for row in rows] == ["command.good"]
    assert "recovery needs provenance review" in capsys.readouterr().err


def test_recovery_workflow_is_independent_and_shares_delivery_lock():
    workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/extension-claim-recovery.yml").read_text()
    assert "schedule:" in workflow
    assert "workflow_dispatch:" in workflow
    assert "needs: regen" not in workflow
    assert "plan_extension_claim_recovery.py" in workflow
    assert "fetch-depth: 0" in workflow
    assert "group: extension-claim-notice-${{ matrix.pr_number }}" in workflow
    assert "--refresh-existing" in workflow
