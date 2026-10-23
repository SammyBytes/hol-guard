"""The envelope shape Python refuses is the one the resident has to refuse.

``verify_trust_attestation`` reads the signature envelope before it reads the
payload, and ``guard_command::attestation_envelope`` repeats those checks for
the resident. Both sides read
``tests/fixtures/guard-attestation-envelope.v1.json``: each case records the
envelope, and either the refusal Python raises or the fields it goes on to
read. A check that drifts on one side fails here and in the companion Rust
test for the same file.

Each case is replayed against an empty payload, so an envelope that passes
fails at the first payload check instead and proves the envelope was accepted.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.trust_attestation import (
    _normalize_pem,
    _public_key_fingerprint,
    verify_trust_attestation,
)

_VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "guard-attestation-envelope.v1.json").read_text(encoding="utf-8")
)
_PAST_ENVELOPE = "Missing trust attestation payload fields:"


def _refusal(envelope: dict[str, object]) -> str:
    with pytest.raises(ValueError) as raised:
        verify_trust_attestation(payload={}, envelope=envelope)
    return str(raised.value)


def test_the_fixture_covers_both_verdicts() -> None:
    assert _VECTORS["schema"] == "guard-attestation-envelope-parity.v1"
    cases = _VECTORS["cases"]
    assert len(cases) >= 25
    assert len({case["name"] for case in cases}) == len(cases)
    assert sum(1 for case in cases if "accepted" in case) >= 5
    assert sum(1 for case in cases if "error" in case) >= 20


@pytest.mark.parametrize("case", _VECTORS["cases"], ids=lambda case: case["name"])
def test_a_recorded_envelope_is_accepted_or_refused_as_recorded(case: dict[str, object]) -> None:
    message = _refusal(dict(case["envelope"]))

    if "accepted" in case:
        assert message.startswith(_PAST_ENVELOPE)
    else:
        assert message == case["error"]


@pytest.mark.parametrize("recorded", _VECTORS["fingerprints"], ids=lambda recorded: repr(recorded["pem"]))
def test_a_recorded_public_key_fingerprints_as_recorded(recorded: dict[str, str]) -> None:
    assert _normalize_pem(recorded["pem"]) == recorded["normalized"]
    assert _public_key_fingerprint(recorded["pem"]) == recorded["fingerprint"]
