"""Typed client for the native inventory URL redaction; no Python composition."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import native_execution
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

if TYPE_CHECKING:
    from .native_runtime_values import NativeRuntimeIdentity

_FEATURE = "inventory-url-redaction-v1"
_REQUEST_SCHEMA = "guard-inventory-url-redaction-request.v1"
_RESULT_SCHEMA = "guard-inventory-url-redaction-result.v1"
_RESULT_KEYS = frozenset({"schema", "request_id", "request_sha256", "status", "code", "answers"})
_MAX_TASKS = 4096
# The resident accepts a canonical request up to 4 MiB; the wire envelope
# carries the same material plus framing, so leave room for both.
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
_MAX_WIRE_BYTES = 2 * _MAX_REQUEST_BYTES + 4096


class NativeInventoryUrlRedactionError(RuntimeError):
    """The native owner could not supply a complete, request-bound redaction."""


def redact_url(value: str, *, guard_home: Path | None = None) -> str:
    """Return the exported form of one URL."""

    return _answers([{"kind": "redact_url", "value": value}], guard_home=guard_home)[0]


def redact_headers(header_names: list[str], *, guard_home: Path | None = None) -> dict[str, str]:
    """Return presence per header name, lowercased, in the order they were given."""

    return _answers(
        [{"kind": "redact_headers", "header_names": header_names}],
        guard_home=guard_home,
    )[0]


def classify_endpoint_host(value: str | None, *, guard_home: Path | None = None) -> str:
    """Return where an endpoint points, decided without a network request."""

    return _answers(
        [{"kind": "classify_endpoint_host", "value": value}],
        guard_home=guard_home,
    )[0]


def _unusable() -> NativeInventoryUrlRedactionError:
    return NativeInventoryUrlRedactionError("native_inventory_url_redaction_invalid_result")


def _headers(answer: dict[str, Any]) -> dict[str, str]:
    """Read a header answer as the presence it reports per name."""

    pairs = answer.get("headers")
    if not isinstance(pairs, list):
        raise _unusable()
    redacted: dict[str, str] = {}
    for pair in pairs:
        if not isinstance(pair, list) or len(pair) != 2:
            raise _unusable()
        name, presence = pair
        if not isinstance(name, str) or not isinstance(presence, str):
            raise _unusable()
        redacted[name] = presence
    return redacted


def _text(answer: dict[str, Any], field: str) -> str:
    """Read the one string a non-header answer carries."""

    value = answer.get(field)
    if not isinstance(value, str):
        raise _unusable()
    return value


def _answer(answer: object, task: dict[str, object]) -> Any:
    """Read the answer the resident gave for this task, or refuse the reply.

    The shape is checked before the reply counts as usable, so an answer the
    caller cannot read records the resident as failing rather than succeeding.
    """

    kind = task["kind"]
    if not isinstance(answer, dict) or answer.get("kind") != kind:
        raise _unusable()
    if kind == "redact_headers":
        return _headers(answer)
    return _text(answer, "value" if kind == "redact_url" else "host_class")


def _answers(
    tasks: list[dict[str, object]],
    *,
    guard_home: Path | None,
    timeout_seconds: float = 10.0,
) -> list[Any]:
    """Ask the resident for one redaction pass and verify it answers this request.

    The redaction is what keeps an operator's credentials and private hosts out
    of an exported inventory, so it has exactly one composition and the resident
    owns it. Every outcome other than a well-formed, request-bound ``ok`` reply
    raises ``NativeInventoryUrlRedactionError``; a caller must not fall back to
    a local redaction, which would be a second place an export can be declared
    safe.
    """

    if len(tasks) > _MAX_TASKS:
        raise NativeInventoryUrlRedactionError("native_inventory_url_redaction_invalid")
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": native_execution._request_id("inventory_url_redaction"),
        "tasks": tasks,
    }
    try:
        home = _resolve_digest_home(guard_home)
        if not ensure_resident_prerequisite(home):
            raise NativeInventoryUrlRedactionError("native_inventory_url_redaction_unavailable")
        request_sha256 = _canonical_request_sha256(wire)
        # Resolved once: the transport and the health record below must name
        # the same binary, and the lookup walks the runtime on disk.
        status = native_runtime_status()
        decoded = native_execution._resident_request(
            operation="inventory_url_redaction",
            request=wire,
            guard_home=home,
            timeout_seconds=timeout_seconds,
            required_feature=_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_WIRE_BYTES,
            # Success is recorded below, once the reply is known to be usable.
            record_success=False,
            status=status,
        )
    except (OSError, TypeError, ValueError) as error:
        raise NativeInventoryUrlRedactionError("native_inventory_url_redaction_unavailable") from error
    if decoded is None:
        raise NativeInventoryUrlRedactionError("native_inventory_url_redaction_unavailable")
    try:
        answers = _validated_answers(decoded, wire, request_sha256, tasks)
    except NativeInventoryUrlRedactionError:
        _record(home, status.identity, success=False)
        raise
    _record(home, status.identity, success=True)
    return answers


def _validated_answers(
    decoded: dict[str, Any],
    wire: dict[str, object],
    request_sha256: str,
    tasks: list[dict[str, object]],
) -> list[Any]:
    if set(decoded) != _RESULT_KEYS or decoded.get("code") != "ok" or decoded.get("status") != "ok":
        raise _unusable()
    if decoded.get("request_id") != wire["request_id"] or decoded.get("request_sha256") != request_sha256:
        raise NativeInventoryUrlRedactionError("native_inventory_url_redaction_request_mismatch")
    answers: Any = decoded.get("answers")
    # One answer per task, or the caller cannot tell which string it holds.
    if not isinstance(answers, list) or len(answers) != len(tasks):
        raise _unusable()
    return [_answer(answer, task) for answer, task in zip(answers, tasks, strict=True)]


def _record(home: Path, identity: NativeRuntimeIdentity | None, *, success: bool) -> None:
    if identity is None:
        return
    if success:
        native_record_resident_success(identity.sha256, home)
    else:
        native_record_resident_failure(identity.sha256, home, reason="native_inventory_url_redaction_result")
