"""Scheduling and buffering prefixes the contained planners read through.

Native authority reads `nice` and `stdbuf` through to the program they run:
`nice -n 10 pytest -q` runs `pytest -q` with one scheduling number changed, and
`stdbuf -oL pytest -q` only changes how its streams are buffered. The receipt
for either names the profile of the program behind the prefix, so the planners
here must be handed that same program, or they refuse the very run the receipt
authorized.

This walk mirrors the native grammar word for word. A prefix spelled as a path,
an option the prefix does not document, a value outside the shape it takes,
`stdbuf` with no buffering mode, or no program at all leaves the command as it
arrived, and the planners refuse it as they did before. `nohup` and `setsid`
are not read through, because native authority does not read them either.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class _Grammar:
    short_values: str
    long_values: frozenset[str]
    numeric_flag: bool
    option_required: bool


_GRAMMARS = {
    # `nice -10 cargo build` is the adjustment spelled on its own.
    "nice": _Grammar("n", frozenset({"adjustment"}), numeric_flag=True, option_required=False),
    # `stdbuf npm test` is an error, not a run of `npm test`.
    "stdbuf": _Grammar("ioe", frozenset({"input", "output", "error"}), numeric_flag=False, option_required=True),
}
_ADJUSTMENT = re.compile(r"[0-9]{1,2}")
_BUFFERING = re.compile(r"(?:L|0|[0-9]{1,10}(?:K|KB|M|MB|G|GB)?)")
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*", re.DOTALL)


def peel_launcher(command: list[str]) -> list[str]:
    """The program a leading `nice` or `stdbuf` runs, or `command` unchanged."""
    if not command or "/" in command[0] or "\\" in command[0]:
        return command
    grammar = _GRAMMARS.get(command[0])
    if grammar is None:
        return command
    index, options = 1, 0
    while index < len(command):
        word = command[index]
        if word == "--":
            index += 1
            break
        if not word.startswith("-"):
            break
        if word == "-":
            return command
        carried = _option_words(command[0], grammar, command, index)
        if carried is None:
            return command
        index += 1 + carried
        options += 1
    if grammar.option_required and options == 0:
        return command
    if index >= len(command):
        return command
    program = command[index]
    if not program or program.startswith("-") or _ASSIGNMENT.fullmatch(program):
        return command
    return command[index:]


def _option_words(prefix: str, grammar: _Grammar, command: list[str], index: int) -> int | None:
    """How many further words this option carries, or None when it is not documented."""
    word = command[index]
    following = command[index + 1] if index + 1 < len(command) else None
    if word.startswith("--"):
        name, separator, inline = word[2:].partition("=")
        if name not in grammar.long_values:
            return None
        if separator:
            return 0 if _value_safe(prefix, inline) else None
        return 1 if following is not None and _value_safe(prefix, following) else None
    cluster = word[1:]
    if grammar.numeric_flag and _ADJUSTMENT.fullmatch(cluster):
        return 0
    letter, glued = cluster[:1], cluster[1:]
    if not letter or letter not in grammar.short_values:
        return None
    if not glued:
        return 1 if following is not None and _value_safe(prefix, following) else None
    return 0 if _value_safe(prefix, glued) else None


def _value_safe(prefix: str, value: str) -> bool:
    if prefix == "nice":
        return _ADJUSTMENT.fullmatch(value[1:] if value[:1] in ("-", "+") else value) is not None
    return _BUFFERING.fullmatch(value) is not None
