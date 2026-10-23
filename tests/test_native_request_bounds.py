"""No bridge offers the resident a request its own transport will refuse."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_GUARD = Path(__file__).resolve().parent.parent / "src" / "codex_plugin_scanner" / "guard"
# The client measures the bytes it is about to frame and the resident measures
# the frame it received, so this one name is the ceiling every other bound
# answers to.
_CEILING_MODULE = "native_resident_client.py"
_CEILING_NAME = "_MAX_REQUEST_BYTES"
_BOUND_NAMES = ("_MAX_REQUEST_BYTES", "_MAX_POST_TOOL_REQUEST_BYTES")


def _module_bounds(path: Path) -> dict[str, int]:
    """The request bounds one module declares, read without importing it."""

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    bounds: dict[str, int] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id not in _BOUND_NAMES:
            continue
        value = _literal_int(node.value)
        if value is not None:
            bounds[target.id] = value
    return bounds


def _literal_int(node: ast.expr) -> int | None:
    """The integer an expression spells out, or ``None`` if it needs running.

    These bounds are written the way the Rust side writes them -- as a count of
    kibibytes, sometimes with a frame's slack taken off -- so the arithmetic is
    read here rather than the module imported for it.
    """

    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, int) else None
    if not isinstance(node, ast.BinOp):
        return None
    left, right = _literal_int(node.left), _literal_int(node.right)
    if left is None or right is None:
        return None
    if isinstance(node.op, ast.Mult):
        return left * right
    if isinstance(node.op, ast.Add):
        return left + right
    if isinstance(node.op, ast.Sub):
        return left - right
    return None


def _ceiling() -> int:
    bound = _module_bounds(_GUARD / _CEILING_MODULE).get(_CEILING_NAME)
    assert bound is not None, f"{_CEILING_MODULE} no longer declares {_CEILING_NAME}"
    return bound


def _declared() -> list[tuple[str, str, int]]:
    return [
        (path.name, name, value) for path in sorted(_GUARD.glob("*.py")) for name, value in _module_bounds(path).items()
    ]


def test_the_transport_ceiling_is_readable() -> None:
    """The scan is worth nothing if it cannot find what it compares against."""

    assert _ceiling() > 0
    assert len(_declared()) > 1


@pytest.mark.parametrize(("module", "name", "value"), _declared(), ids=lambda item: str(item))
def test_a_bridge_never_offers_more_than_one_frame(module: str, name: str, value: int) -> None:
    """A bound above the ceiling is one no request can ever reach.

    The client refuses anything larger before it frames it, and the resident
    refuses the frame itself, so a request between the two bounds comes back as
    a broken runtime rather than as a request that asked for too much.
    """

    assert value <= _ceiling(), f"{module} declares {name} above what the transport will carry"
