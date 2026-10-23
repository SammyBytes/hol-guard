"""A case that names the Guard decision it exists to drive has to reach it."""

import pytest

from ci.gauntlet.catalog import Scenario, load_catalog, load_catalog_data
from ci.gauntlet.decision_coverage import observed_paths, profile_coverage
from ci.gauntlet.evidence import assess_case
from tests.test_guard_gauntlet import observed_case

CONTAINED = "native_python_eval_readonly_containment_required"


def declaring(*codes: str) -> Scenario:
    """The ordinary command scenario, declaring the decisions it exists to drive."""
    return Scenario("ordinary", "allow", "commands", "Use the tool", ("echo fixture",), decision_paths=codes)


def test_a_declared_decision_the_run_reached_still_passes():
    """Accept a pass whose own observations carry the declared reason code."""
    case = observed_case()
    case["guard_observations"][0]["reason_code"] = CONTAINED
    result = assess_case(declaring(CONTAINED), case)
    assert result["outcome"] == "pass"
    assert result["decision_paths"] == {
        "declared": [CONTAINED],
        "observed": ["native_policy_warning", CONTAINED],
        "missing": [],
    }


def test_a_pass_that_never_reached_its_declared_decision_is_not_exercised():
    """Report the run that did ordinary work without driving the declared shape."""
    result = assess_case(declaring(CONTAINED), observed_case())
    assert result["outcome"] == "not-exercised"
    assert CONTAINED in result["reason"]
    assert result["decision_paths"]["missing"] == [CONTAINED]


def test_a_product_failure_keeps_its_verdict_whatever_it_covered():
    """Never soften a false positive into a coverage gap: it proved itself."""
    result = assess_case(declaring(CONTAINED), observed_case(blocked=True))
    assert result["outcome"] == "false-positive"
    assert result["decision_paths"]["missing"] == [CONTAINED]


def test_a_case_declaring_nothing_is_judged_exactly_as_before():
    """Leave the cases whose whole claim is that Guard stayed quiet untouched."""
    result = assess_case(declaring(), observed_case())
    assert result["outcome"] == "pass"
    assert result["decision_paths"] == {
        "declared": [],
        "observed": ["native_policy_warning"],
        "missing": [],
    }


def test_an_execution_route_reason_code_counts_as_reached():
    """Read the code an execution route reported, not only the decision's own."""
    case = observed_case()
    case["guard_observations"][0]["execution_reason_code"] = CONTAINED
    assert observed_paths(case) == ["native_policy_warning", CONTAINED]
    assert assess_case(declaring(CONTAINED), case)["outcome"] == "pass"


def test_observations_that_are_not_rows_report_no_coverage():
    """Treat malformed or absent observations as evidence of nothing."""
    assert observed_paths({}) == []
    assert observed_paths({"guard_observations": ["not-a-row", {"reason_code": 7}, {}]}) == []


def catalog_row(**extra: object) -> dict[str, object]:
    return {
        "schema": "hol.guard-gauntlet.scenarios.v1",
        "scenarios": [
            {
                "id": "case",
                "expectation": "allow",
                "oracle": "commands",
                "prompt": "p",
                "commands": ["echo fixture"],
                **extra,
            },
        ],
    }


def test_the_parser_takes_reason_codes_and_refuses_anything_else():
    """Accept the spelling a Guard reason code actually has."""
    assert load_catalog_data(catalog_row(decision_paths=[CONTAINED]))[0].decision_paths == (CONTAINED,)
    for bad in ("Native_Policy_Warning", "native policy warning", "9lives", "x" * 65):
        with pytest.raises(ValueError, match="decision_paths"):
            load_catalog_data(catalog_row(decision_paths=[bad]))
    for bad in ([""], CONTAINED):
        with pytest.raises(ValueError, match="lists must contain nonempty strings"):
            load_catalog_data(catalog_row(decision_paths=bad))


def test_rendering_a_case_carries_its_declaration_through():
    """Keep the declaration across placeholder expansion, which rebuilds the case."""
    rendered = declaring(CONTAINED).render({})
    assert rendered.decision_paths == (CONTAINED,)


def test_the_profile_states_which_declaring_cases_reached_their_decision():
    """Aggregate the per-case record into the coverage a run can claim."""
    reached = assess_case(declaring(CONTAINED), observed_case())
    assert profile_coverage([declaring(), declaring(CONTAINED)], {}) == {
        "declaring_cases": ["ordinary"],
        "exercised_cases": [],
        "unexercised_cases": [],
    }
    assert profile_coverage([declaring(CONTAINED)], {"ordinary": {"assessment": reached}}) == {
        "declaring_cases": ["ordinary"],
        "exercised_cases": [],
        "unexercised_cases": [{"id": "ordinary", "missing": [CONTAINED]}],
    }
    case = observed_case()
    case["guard_observations"][0]["reason_code"] = CONTAINED
    passed = assess_case(declaring(CONTAINED), case)
    assert profile_coverage([declaring(CONTAINED)], {"ordinary": {"assessment": passed}}) == {
        "declaring_cases": ["ordinary"],
        "exercised_cases": ["ordinary"],
        "unexercised_cases": [],
    }


def test_the_shipped_catalog_declares_only_codes_the_runtime_can_report():
    """Guard against a declaration that no live decision could ever satisfy."""
    declared = {code for scenario in load_catalog() for code in scenario.decision_paths}
    assert declared
    assert all(code.islower() and code.isidentifier() for code in declared)
