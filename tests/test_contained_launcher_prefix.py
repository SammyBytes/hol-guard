"""`nice` and `stdbuf` run the program they name; the sink plans that program."""

from __future__ import annotations

import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_restricted_pytest
from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime.contained_command_prefix import peel_run_prefixes
from codex_plugin_scanner.guard.runtime.contained_launcher_prefix import peel_launcher
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import (
    PYTEST_INVALID_COMMAND_REASON_CODE,
    RestrictedPytestError,
)

# The same vectors the native parser is held to.
_READ = [
    ("nice npm run build", 1),
    ("nice -n 10 npm run build", 3),
    ("nice -n -5 cargo build", 3),
    ("nice -n10 cargo build", 2),
    ("nice -10 cargo build", 2),
    ("nice --adjustment=19 pytest -q", 2),
    ("nice --adjustment 19 pytest -q", 3),
    ("nice -- npm test", 2),
    ("stdbuf -oL pytest -q", 2),
    ("stdbuf -o L pytest -q", 3),
    ("stdbuf -i0 -oL -e0 cargo test", 4),
    ("stdbuf --output=L --error=0 npm test", 3),
    ("stdbuf -o 4K npm test", 3),
    # GNU `nice` reads only `-N` as an adjustment, so `+10` is the program.
    ("nice +10 npm test", 1),
]
_LEFT = [
    "./nice -n 10 npm test",
    "/tmp/tools/stdbuf -oL npm test",
    "C:\\tools\\nice -n 10 npm test",
    "nice",
    "nice -n 10",
    "nice --version",
    "nice --help",
    "nice -",
    "nice -x npm test",
    "nice -n 300 npm test",
    "nice -n L npm test",
    "nice --adjustment=nineteen npm test",
    "nohup npm run dev",
    "setsid npm run dev",
    "stdbuf npm test",
    "stdbuf -oL",
    "stdbuf -o /dev/null npm test",
    "stdbuf -oQ npm test",
    "stdbuf -n0 npm test",
    "stdbuf --buffer=L npm test",
    "nice -n 10 FOO=bar npm test",
    "nice -n 10 -- -q",
]


def test_a_documented_launcher_is_peeled_to_its_program() -> None:
    for text, offset in _READ:
        command = shlex.split(text)
        assert peel_launcher(command) == command[offset:], text


def test_an_undocumented_word_leaves_the_launcher_in_place() -> None:
    for text in _LEFT:
        command = shlex.split(text, posix="\\" not in text)
        assert peel_launcher(command) == command, text


def test_launchers_and_clocks_peel_in_either_order() -> None:
    assert peel_run_prefixes(shlex.split("nice -n 10 timeout 20 pytest -q")) == (["pytest", "-q"], 20)
    assert peel_run_prefixes(shlex.split("timeout 20 stdbuf -oL pytest -q")) == (["pytest", "-q"], 20)
    assert peel_run_prefixes(shlex.split("stdbuf -oL env CI=1 pytest -q")) == (["pytest", "-q"], None)
    assert peel_run_prefixes(shlex.split("nohup pytest -q")) == (["nohup", "pytest", "-q"], None)


def _required() -> dict[str, object]:
    return {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_pytest_readonly_containment_required",
        "required_execution_profile": "pytest-readonly-v2",
    }


def _pytest_kind(monkeypatch: pytest.MonkeyPatch) -> None:
    kinds = dict.fromkeys(("inline_eval", "node_test", "vitest", "git", "node_tool"), False)
    monkeypatch.setattr(native_restricted_pytest, "restricted_native", lambda *args: dict(kinds))


def _plan_only_pytest(command: list[str], **_: object) -> None:
    if command[0] != "pytest":
        raise RestrictedPytestError(PYTEST_INVALID_COMMAND_REASON_CODE, "accepts only a pytest executable")


@pytest.mark.parametrize("text", ["nice -n 10 pytest -q", "nice pytest -q", "stdbuf -oL pytest -q"])
def test_the_sink_runs_the_program_the_receipt_authorized(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str
) -> None:
    executed: list[list[str]] = []
    asked: list[str] = []
    _pytest_kind(monkeypatch)
    monkeypatch.setattr(sink, "prepare_restricted_pytest", _plan_only_pytest)
    monkeypatch.setattr(sink, "run_restricted_pytest", lambda command, **_: executed.append(command) or 0)

    def authorize(original: dict[str, object]) -> dict[str, object]:
        asked.append(original["tool_input"]["command"])  # type: ignore[index]
        return _required()

    payload = {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": text}}
    assert sink.run_authorized_contained_test(payload, workspace=tmp_path, timeout_seconds=20, authorize=authorize) == 0
    # The receipt is drawn for the command as issued; only its program runs.
    assert asked == [text]
    assert executed == [["pytest", "-q"]]


@pytest.mark.parametrize("text", ["./nice -n 10 pytest -q", "stdbuf pytest -q", "nohup pytest -q"])
def test_the_sink_still_refuses_a_launcher_native_authority_does_not_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str
) -> None:
    _pytest_kind(monkeypatch)
    monkeypatch.setattr(sink, "prepare_restricted_pytest", _plan_only_pytest)
    monkeypatch.setattr(sink, "run_restricted_pytest", lambda *args, **kwargs: pytest.fail("ran"))
    monkeypatch.setattr(sink, "run_workspace_contained", lambda *args, **kwargs: pytest.fail("ran"))
    payload = {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": text}}
    with pytest.raises(RestrictedPytestError) as refused:
        sink.run_authorized_contained_test(
            payload, workspace=tmp_path, timeout_seconds=20, authorize=lambda _: _required()
        )
    assert refused.value.reason_code == "contained_run_authorization_failed"
