"""Guard the recorded shadow rollout decisions the Rust twin replays.

``rust/crates/guard-command/tests/guard_command_shadow_parity.rs`` reads the
same fixture. Both halves must agree on every row, so a change to either set of
controls that this file does not also record is caught here first.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.runtime.command_shadow_evaluation import (
    CommandShadowCohort,
    _comparison,
    _disposition_matches,
    _sample_bucket,
    load_command_shadow_control,
)
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition

FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/guard-command-shadow.v1.json"


def _document() -> dict[str, Any]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert document["schema"] == "guard-command-shadow-parity.v1"
    return document


def _rows(field: str) -> list[dict[str, Any]]:
    rows = _document()[field]
    assert rows, f"the fixture records no {field}"
    return rows


@pytest.mark.parametrize("row", _rows("buckets"), ids=lambda row: f"{row['cohort']}-{len(row['activity_id'])}")
def test_recorded_sample_bucket_still_holds(row: dict[str, Any]) -> None:
    cohort = CommandShadowCohort(row["cohort"])
    assert _sample_bucket(cohort, row["activity_id"]) == row["bucket"]


@pytest.mark.parametrize("row", _rows("rejected_activity_ids"))
def test_recorded_activity_id_is_still_refused(row: dict[str, Any]) -> None:
    with pytest.raises(ValueError) as caught:
        _sample_bucket(CommandShadowCohort.BASELINE, row["activity_id"])
    assert str(caught.value) == row["error"]


@pytest.mark.parametrize("row", _rows("controls"))
def test_recorded_control_still_resolves(row: dict[str, Any]) -> None:
    control = load_command_shadow_control(row["env"])
    assert control.enabled == row["enabled"]
    assert control.kill_switch == row["kill_switch"]
    assert sorted(cohort.value for cohort in control.release_cohorts) == row["release_cohorts"]
    assert sorted(cohort.value for cohort in control.disabled_cohorts) == row["disabled_cohorts"]
    assert control.sample_basis_points == row["sample_basis_points"]
    assert control.generation == row["generation"]
    assert control.schema_version == row["schema_version"]


@pytest.mark.parametrize("row", _rows("selections"))
def test_recorded_selection_still_holds(row: dict[str, Any]) -> None:
    control = load_command_shadow_control(row["env"])
    selected = control.selected_cohorts(
        proposal_cohorts=frozenset(CommandShadowCohort(value) for value in row["proposal_cohorts"]),
        activity_id=row["activity_id"],
    )
    assert [cohort.value for cohort in selected] == row["selected"]


@pytest.mark.parametrize("row", _rows("comparisons"), ids=lambda row: f"{row['current']}-to-{row['proposed']}")
def test_recorded_comparison_still_holds(row: dict[str, Any]) -> None:
    assert _comparison(row["current"], row["proposed"]).value == row["comparison"]


@pytest.mark.parametrize("row", _rows("dispositions"), ids=lambda row: f"{row['action']}-{row['disposition']}")
def test_recorded_disposition_match_still_holds(row: dict[str, Any]) -> None:
    disposition = FinalDisposition(row["disposition"])
    assert _disposition_matches(row["action"], disposition) is row["matches"]


def test_the_fixture_keeps_recording_selections_that_sample_in() -> None:
    assert any(row["selected"] for row in _rows("selections"))
