"""Bind Codex's contained-run rewrite on Windows to the original call Guard reviewed.

Rust denies some ordinary commands with ``sandbox-required``. On Windows, Guard's Codex hook
turns that denial into an allow whose ``updatedInput`` runs ``guard execute-contained-test`` on
a private snapshot of the call, so Codex runs the command inside Guard's contained runner. The
daemon tap records the resident's denial, not the rewrite, so the generic harness judge saw a
stop. That route is accepted only when every link names the same call, as the Oh My Pi route
requires in ``contained_core``:

- the validated native receipt denied the reviewed input for containment, with the matching
  execution profile;
- exactly one ``PostToolUse`` row for that call carries the canonical sink argv, bound to the
  case's Guard home, workspace and home, with an adapter-owned request file;
- the request digest in that argv is the digest of the snapshot built from the reviewed input,
  so the sink, which checks the digest before it reads the call, ran exactly that input;
- the one transcript call that ran the wrapper completed without an error.

A link that is missing or differs leaves the run unproven, never passed.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from pathlib import Path, PureWindowsPath
from typing import Any

from .contained_core import CONTAINMENT_PROFILES

_HEX64 = re.compile(r"[0-9a-f]{64}")
# The hook starts Guard's own Python with a fixed bootstrap and passes the package root as the
# next argument. Both are written with forward slashes so PowerShell and Git Bash read them alike.
_PYTHON = re.compile(r"[A-Za-z]:/(?:[^\\/:*?\"<>|' ]+/)*python\.exe", re.IGNORECASE)
_SITE_PACKAGES = re.compile(r"[A-Za-z]:/(?:[^\\/:*?\"<>|']+/)*Lib/site-packages", re.IGNORECASE)
_BOOTSTRAP = (
    "import sys;sys.path.insert(0,sys.argv.pop(1));"
    "from codex_plugin_scanner.cli import main;raise SystemExit(main(sys.argv[1:]))"
)
_PLACEHOLDERS = frozenset({"{{workspace}}", "{{home}}"})
_REQUEST_SCHEMA = "guard-contained-test-request.v1"


def _event(row: dict[str, Any]) -> str | None:
    receipt = row.get("receipt") if isinstance(row.get("receipt"), dict) else {}
    payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
    return receipt.get("event_name") or payload.get("hook_event_name")


def _call_id(row: dict[str, Any]) -> str | None:
    payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
    value = payload.get("tool_use_id") or payload.get("tool_call_id")
    return value if isinstance(value, str) and value else None


def _containment_deny(row: dict[str, Any]) -> bool:
    """A codex PreToolUse row the resident denied for a containment profile."""
    receipt = row.get("receipt") if isinstance(row.get("receipt"), dict) else {}
    response = row.get("response") if isinstance(row.get("response"), dict) else {}
    reason = response.get("reason_code")
    return (
        _event(row) == "PreToolUse"
        and row.get("route_harness") == "codex"
        and isinstance(reason, str)
        and reason in CONTAINMENT_PROFILES
        and reason != "native_bash_owner_required"
        and response.get("policy_action") == "sandbox-required"
        and response.get("decision") == "deny"
        and response.get("required_execution_profile") == CONTAINMENT_PROFILES[reason]
        and receipt.get("harness") == "codex"
        and receipt.get("decision") == "deny"
        and receipt.get("policy_action") == "sandbox-required"
        and receipt.get("reason_code") == reason
        and receipt.get("observe_mode") is False
        and isinstance(receipt.get("decision_id"), str)
        and bool(receipt["decision_id"])
    )


def request_proofs(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Digests of the request snapshot Guard's hook builds for each contained Codex call.

    Read from the unredacted tap rows on the host that ran the case: the snapshot names the
    resolved workspace, so it can be rebuilt only where that directory exists. It mirrors the
    hook's serialization byte for byte; a hook that changed it leaves every route unproven.
    """
    proofs = []
    for row in rows:
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        tool_input = payload.get("tool_input")
        cwd = payload.get("cwd")
        call_id = _call_id(row)
        if not _containment_deny(row) or call_id is None or not isinstance(tool_input, dict):
            continue
        if not isinstance(cwd, str) or not cwd:
            continue
        try:
            resolved = Path(cwd).expanduser().resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            continue
        workspace = str(resolved)
        snapshot = {
            "schema": _REQUEST_SCHEMA,
            "workspace": workspace,
            "payload": {
                "hook_event_name": "PreToolUse",
                "tool_name": "bash",
                "tool_input": tool_input,
                "cwd": workspace,
                "session_id": payload.get("session_id", payload.get("sessionId")),
                "tool_call_id": payload.get("tool_call_id", payload.get("toolCallId", payload.get("tool_use_id"))),
            },
        }
        digest = hashlib.sha256(json.dumps(snapshot).encode()).hexdigest()
        proofs.append({"tool_call_id": call_id, "request_sha256": digest})
    return proofs


def sink_argv(command: object) -> tuple[list[str] | None, str | None]:
    """The canonical sink argv in a redacted ``PostToolUse`` command, with the bootstrap folded."""
    if not isinstance(command, str):
        return None, "contained wrapper command is missing"
    try:
        argv = shlex.split(command)
    except ValueError:
        return None, "contained wrapper command is not valid shell argv"
    if not argv or command != " ".join(
        [argv[0], *(value if value in _PLACEHOLDERS else f"'{value}'" for value in argv[1:])]
    ):
        return None, "contained wrapper command is not canonical"
    if (
        len(argv) != 19
        or _PYTHON.fullmatch(argv[0]) is None
        or argv[1:4] != ["-I", "-c", _BOOTSTRAP]
        or _SITE_PACKAGES.fullmatch(argv[4]) is None
        or argv[5:9] != ["guard", "execute-contained-test", "--harness", "codex"]
    ):
        return None, "contained wrapper is not the Windows Guard sink"
    if argv[9:11] != ["--guard-home", "{{fixture}}\\guard-home"]:
        return None, "contained wrapper is not bound to the case's Guard installation"
    if argv[11:13] != ["--workspace", "{{workspace}}"] or argv[17:19] != ["--home", "{{home}}"]:
        return None, "contained wrapper workspace binding differs from the reviewed caller"
    request = PureWindowsPath(argv[14])
    if (
        argv[13] != "--request-file"
        or re.match(r"[A-Za-z]:\\", argv[14]) is None
        or request.name != "request.json"
        or not request.parent.name.startswith("hol-guard-contained-test-")
    ):
        return None, "contained wrapper request path is not adapter-owned"
    if argv[15] != "--request-sha256" or _HEX64.fullmatch(argv[16]) is None:
        return None, "contained wrapper request digest is malformed"
    return argv, None


def routed_calls(expectation: str, case: dict[str, Any]) -> tuple[set[str], tuple[str, str] | None]:
    """Ids of fully bound contained Codex calls, or the outcome for a route that is not bound.

    A containment deny whose call never ran the sink wrapper keeps the ordinary judgement and
    still counts as a stop.
    """
    if expectation != "allow" or case.get("harness") != "codex":
        return set(), None
    rows = [row for row in case.get("guard_rows", []) if isinstance(row, dict)]
    proofs = case.get("contained_request_proofs", [])
    if not isinstance(proofs, list):
        return set(), ("harness-error", "contained request proofs are malformed")
    calls = case.get("transcript", {}).get("calls", [])
    bound: set[str] = set()
    for row in rows:
        call_id = _call_id(row)
        if not _containment_deny(row) or call_id is None:
            continue
        reviewed = (row.get("payload") or {}).get("tool_input")
        post = [r for r in rows if _event(r) == "PostToolUse" and _call_id(r) == call_id]
        wrapper = ((post[0].get("payload") or {}).get("tool_input") or {}).get("command") if len(post) == 1 else None
        if not isinstance(wrapper, str) or "execute-contained-test" not in wrapper:
            continue
        error = _binding_error(call_id, reviewed, post[0], wrapper, proofs, calls)
        if error:
            return set(), error
        bound.add(call_id)
    return bound, None


def _binding_error(
    call_id: str,
    reviewed: object,
    post: dict[str, Any],
    wrapper: str,
    proofs: list[Any],
    calls: list[Any],
) -> tuple[str, str] | None:
    if not isinstance(reviewed, dict) or reviewed.get("command") == wrapper:
        return "harness-error", "host execution differs from the input reviewed by Guard"
    response = post.get("response") if isinstance(post.get("response"), dict) else {}
    specific = response.get("hookSpecificOutput") if isinstance(response.get("hookSpecificOutput"), dict) else {}
    if response.get("policy_action") not in ("allow", "warn") or specific.get("permissionDecision") not in (
        None,
        "allow",
    ):
        return "harness-error", "contained post observation is not bound to the executed wrapper"
    argv, wrapper_error = sink_argv(wrapper)
    if wrapper_error or argv is None:
        return "harness-error", wrapper_error or "contained wrapper is unavailable"
    matches = [p for p in proofs if isinstance(p, dict) and p.get("tool_call_id") == call_id]
    if len(matches) != 1 or matches[0].get("request_sha256") != argv[16]:
        return "harness-error", "contained request digest differs from the input Guard reviewed"
    ran = [
        call
        for call in calls
        if isinstance(call, dict)
        and isinstance(call.get("args"), dict)
        and argv[16] in str(call["args"].get("command"))
    ]
    if len(ran) != 1:
        return "harness-error", "the transcript does not show one run of the contained wrapper"
    if ran[0].get("is_error") is not False:
        return "false-positive", "Guard's contained run of ordinary work failed"
    return None


def is_routed_deny(row: Any, bound: set[str]) -> bool:
    """The resident's containment deny of a bound call, which the hook replaced with the route."""
    return isinstance(row, dict) and _containment_deny(row) and _call_id(row) in bound
