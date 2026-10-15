"""Validation for operator-typed credentials that end up in an HTTP header.

httpx encodes header values as ASCII and raises ``UnicodeEncodeError`` while
*building* a client from one that is not, and ``h11`` refuses a value carrying
a space, CR or LF. Integration probes build their ``Authorization`` /
``X-API-Key`` header straight from what the operator pasted, so a token with a
smart quote, an accented letter, a trailing newline or an embedded space used
to escape every ``except httpx.HTTPError`` in the probe as a 500 (#1913).

A bearer / API token is printable ASCII with no whitespace by construction, so
the boundary refuses anything else with a message that names the problem, and
the probes themselves never let a client-build error escape.
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


def header_secret(value: Any, info: ValidationInfo) -> Any:
    """Pydantic ``field_validator`` body: raises ValueError (a 422) on a bad
    credential. Use as ``_check = field_validator("token")(header_secret)``."""
    problem = header_credential_problem(value, (info.field_name or "token").replace("_", " "))
    if problem:
        raise ValueError(problem)
    return value
