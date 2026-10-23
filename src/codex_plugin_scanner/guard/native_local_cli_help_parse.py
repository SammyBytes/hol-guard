"""Resident bridge for the ``local_cli_help_parse`` op.

Python probes an unlisted CLI with ``--help`` -- that is where the process
isolation lives -- and hands the text here for the parse. The text is whatever
a third-party program printed, so nothing in it is trusted: the op reports only
the command names Rust recognized, and an answer that is not bound to this
request is discarded. When the resident cannot answer, the caller sees nothing
and the CLI's commands stay undiscovered.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from uuid import uuid4

from .native_context import ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

LOCAL_CLI_HELP_PARSE_FEATURE = "local-cli-help-parse-v1"
_REQUEST_SCHEMA = "guard-local-cli-help-parse-request.v1"
_RESULT_SCHEMA = "guard-local-cli-help-parse-result.v1"
_TIMEOUT_SECONDS = 5.0
_MAX_REQUEST_BYTES = 256 * 1024

_FIELDS = ("command_id", "name", "usage", "description", "parent_id")


def native_local_cli_help_commands(
    *,
    guard_home: Path,
    text: str,
    parent_id: str | None,
    invocation: Sequence[str],
) -> tuple[dict[str, object], ...] | None:
    """The commands the resident read out of ``text``; None when it cannot say."""

    home = Path(guard_home)
    try:
        if not ensure_resident_prerequisite(home):
            return None
    except (OSError, RuntimeError, ValueError):
        return None
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"local-cli-help-parse-{uuid4().hex}",
        "text": text,
        "parent_id": parent_id,
        "invocation": [str(word) for word in invocation],
    }
    try:
        response = _resident_request(
            operation="local_cli_help_parse",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=LOCAL_CLI_HELP_PARSE_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError):
        return None
    payload = _payload(response, wire, home)
    if not isinstance(payload, dict):
        return None
    commands = payload.get("commands")
    if not isinstance(commands, list):
        return None
    read: list[dict[str, object]] = []
    for entry in commands:
        if not isinstance(entry, dict) or any(field not in entry for field in _FIELDS):
            return None
        row = {field: entry[field] for field in _FIELDS}
        if any(not isinstance(row[field], str) for field in _FIELDS[:4]):
            return None
        if not isinstance(row["parent_id"], (str, type(None))):
            return None
        read.append(row)
    return tuple(read)
