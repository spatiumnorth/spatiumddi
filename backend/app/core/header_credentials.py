"""Validation for operator-typed credentials that end up in an HTTP header.

httpx encodes header values as ASCII and raises ``UnicodeEncodeError`` while
*building* a client from one that is not, and ``h11`` refuses a value carrying
a space, CR or LF. Integration probes build their ``Authorization`` /
``X-API-Key`` header straight from what the operator pasted, so a token with a
smart quote, an accented letter, a trailing newline or an embedded space used
to escape every ``except httpx.HTTPError`` in the probe as a 500 (#1913).

A bearer / API token is printable ASCII with no whitespace by construction, so
the boundary strips surrounding whitespace, refuses anything else with a
message that names the problem, and the probes themselves never let a
client-build error escape. Validation runs on input only: a response model
must never carry this validator, or a stored value that predates it would
turn a read into a 500.
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationInfo


def header_credential_problem(value: str | None, label: str = "token") -> str | None:
    """Why *value* cannot be sent as a header credential, or None if it can.

    Empty / None is not a problem here: "required" and "keep the stored one"
    are each endpoint's own decision.
    """
    if not value:
        return None
    for ch in value:
        if ch.isspace():
            return (
                f"The {label} contains whitespace or a line break. Re-copy it "
                "without surrounding or embedded spaces."
            )
        if not ch.isascii() or not ch.isprintable():
            return (
                f"The {label} contains a character ({ch!r}) that cannot appear "
                "in an HTTP header (only printable ASCII is allowed). Re-copy "
                "it from the source, avoiding word-processor quotes and dashes."
            )
    return None


def header_value_problem(value: str, label: str) -> str | None:
    """Why *value* cannot be a general header value, or None if it can.

    Looser than :func:`header_credential_problem`: an inner space is legal
    in a header value (``Bearer abc``, ``ApiKey x y``), only non-ASCII and
    control characters are not. Callers strip surrounding whitespace first.
    """
    for ch in value:
        if not ch.isascii() or not ch.isprintable():
            return (
                f"The {label} contains a character ({ch!r}) that cannot appear "
                "in an HTTP header (only printable ASCII is allowed)."
            )
    return None


def header_secret(value: Any, info: ValidationInfo) -> Any:
    """Pydantic ``field_validator`` body. Use as
    ``_check = field_validator("token")(header_secret)``.

    Surrounding whitespace is stripped, not refused: a token pasted with its
    trailing newline is the commonest way one arrives, and no real token
    starts or ends with a space. What is left must be printable ASCII with
    no whitespace, or it raises ValueError (a 422).

    None and "" pass through untouched, because on an update they mean "keep
    the stored credential". A value that was only whitespace is refused
    rather than turned into "": the caller typed something, and silently
    keeping the old secret (update) or storing an empty one (create) would
    both be a surprise.
    """
    if not isinstance(value, str) or not value:
        return value
    label = (info.field_name or "token").replace("_", " ")
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"The {label} is blank.")
    problem = header_credential_problem(stripped, label)
    if problem:
        raise ValueError(problem)
    return stripped
