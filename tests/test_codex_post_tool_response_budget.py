"""The whole tool response travels to the resident only when it fits beside the flattened text."""

from __future__ import annotations

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import (
    _CODEX_TOOL_RESPONSE_WIRE_BUDGET,
    _codex_tool_response_within_budget,
)


def test_a_small_response_travels_whole() -> None:
    response = {"output": "token=abc"}
    assert _codex_tool_response_within_budget(response, "token=abc") is response


def test_an_absent_response_sends_nothing() -> None:
    assert _codex_tool_response_within_budget(None, "") is None


def test_a_response_over_the_budget_is_left_behind() -> None:
    response = {"output": "x" * (_CODEX_TOOL_RESPONSE_WIRE_BUDGET + 1)}
    assert _codex_tool_response_within_budget(response, "") is None


def test_the_flattened_text_counts_against_the_budget() -> None:
    half = "x" * (_CODEX_TOOL_RESPONSE_WIRE_BUDGET // 2)
    response = {"output": half}
    assert _codex_tool_response_within_budget(response, "") is response
    assert _codex_tool_response_within_budget(response, half) is None


def test_a_response_that_will_not_serialize_is_left_behind() -> None:
    assert _codex_tool_response_within_budget({"output": object()}, "") is None
