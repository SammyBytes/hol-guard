"""Canonical, serialization-independent identities for Codex hooks.

The canonical form and its digest live in the native runtime. A hook's
identity decides whether an approval the user already gave still covers the
hook in front of us, so a second implementation here would be a second answer
to that question: this module only names what is being identified and hands
the resident's answer back.
"""

from __future__ import annotations

from collections.abc import Mapping

from .native_codex_hook_identity import (
    CodexHookIdentityUnavailableError,
    native_codex_hook_identity,
)

CODEX_HOOK_IDENTITY_SCHEMA = "codex-hook-identity-v1"


def canonical_codex_hook_identity(
    *,
    source_scope: str,
    source_hooks_enabled: bool,
    event_name: str,
    group: Mapping[str, object],
    handler: Mapping[str, object],
) -> str:
    """Return one format- and coordinate-independent handler identity."""

    return _digest(
        {
            "kind": "handler",
            "source_scope": source_scope,
            "source_hooks_enabled": source_hooks_enabled,
            "event_name": event_name,
            "group": group,
            "handler": handler,
        }
    )


def canonical_codex_hook_group_identity(
    *,
    source_scope: str,
    source_hooks_enabled: bool,
    event_name: str,
    group: Mapping[str, object],
) -> str:
    """Return a canonical identity for one complete matcher group."""

    return _digest(
        {
            "kind": "group",
            "source_scope": source_scope,
            "source_hooks_enabled": source_hooks_enabled,
            "event_name": event_name,
            "group": group,
        }
    )


def canonical_codex_hook_conflict_keys(
    *,
    source_scope: str,
    source_hooks_enabled: bool,
    event_name: str,
    group: Mapping[str, object],
) -> tuple[str, ...]:
    """Identify handler slots whose differing definitions must not be collapsed."""

    answer = _answer(
        {
            "kind": "conflict",
            "source_scope": source_scope,
            "source_hooks_enabled": source_hooks_enabled,
            "event_name": event_name,
            "group": group,
        }
    )
    digests = answer.get("digests")
    if not isinstance(digests, list) or not all(isinstance(item, str) for item in digests):
        raise CodexHookIdentityUnavailableError
    return tuple(digests)


def canonical_codex_command_argv(command: str | None) -> tuple[str, ...] | None:
    """Normalize only commands whose shell tokenization is provably uncomplicated."""

    entry: dict[str, object] = {"kind": "argv"}
    if command is not None:
        entry["command"] = command
    argv = _answer(entry).get("argv")
    if argv is None:
        return None
    if not isinstance(argv, list) or not all(isinstance(token, str) for token in argv):
        raise CodexHookIdentityUnavailableError
    return tuple(argv)


def _digest(entry: Mapping[str, object]) -> str:
    """The one digest an entry asking for a single identity answers with."""

    digest = _answer(entry).get("digest")
    if not isinstance(digest, str) or not digest:
        raise CodexHookIdentityUnavailableError
    return digest


def _answer(entry: Mapping[str, object]) -> dict[str, object]:
    """Ask the resident about one entry and return its answer."""

    return native_codex_hook_identity([entry])[0]


__all__ = [
    "CODEX_HOOK_IDENTITY_SCHEMA",
    "CodexHookIdentityUnavailableError",
    "canonical_codex_command_argv",
    "canonical_codex_hook_conflict_keys",
    "canonical_codex_hook_group_identity",
    "canonical_codex_hook_identity",
]
