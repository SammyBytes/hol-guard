from __future__ import annotations

import re
from pathlib import Path

from scripts.native_resident_stop_bound import RESIDENT_STOP_TIMEOUT_SECONDS

_ROOT = Path(__file__).resolve().parents[1]
_RUST_STOP_BOUND = re.compile(r"const MANAGED_STOP_TIMEOUT: Duration = Duration::from_secs\((\d+)\);")
_LITERAL_STOP_TIMEOUT = re.compile(r'"resident-stop"[^\n]*\n(?:[^\n]*\n){0,4}?\s*timeout=(\d+(?:\.\d+)?),')
# Process start and the runtime self-digest happen before the runtime's own
# stop bound begins, so a caller needs real headroom beyond that bound.
_STARTUP_HEADROOM_SECONDS = 2.0


def _runtime_stop_bound_seconds() -> float:
    source = (_ROOT / "rust/crates/guard-runtime/src/managed_resident.rs").read_text(encoding="utf-8")
    match = _RUST_STOP_BOUND.search(source)
    assert match is not None, "MANAGED_STOP_TIMEOUT moved; update this check"
    return float(match.group(1))


def test_harness_stop_timeout_outlasts_the_runtime_stop_bound() -> None:
    assert _runtime_stop_bound_seconds() + _STARTUP_HEADROOM_SECONDS <= RESIDENT_STOP_TIMEOUT_SECONDS


def test_no_harness_gives_resident_stop_less_than_the_runtime_bound_needs() -> None:
    minimum = _runtime_stop_bound_seconds() + _STARTUP_HEADROOM_SECONDS
    short: list[str] = []
    for directory in ("ci", "scripts"):
        for path in sorted((_ROOT / directory).rglob("*.py")):
            for match in _LITERAL_STOP_TIMEOUT.finditer(path.read_text(encoding="utf-8")):
                if float(match.group(1)) < minimum:
                    short.append(f"{path.relative_to(_ROOT)}: timeout={match.group(1)}")
    assert not short, short
