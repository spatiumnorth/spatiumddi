"""Classify a Postgres integrity error as the CLIENT's fault or OURS (#922).

``POST /dhcp/servers`` with a well-formed but nonexistent ``server_group_id``
answered an unhandled 500: #861's global handler maps unique violations
(23505) to 409 and deliberately re-raises everything else, on the reasoning
that a NOT NULL / foreign-key / CHECK violation means the server sent
something it shouldn't and a 4xx would both blame the client and *hide* the
bug from the conformance fuzz's no-5xx assertion.

That reasoning is right about the general case and wrong about one arm of it.
A foreign-key violation on a value **the client supplied** — a stale group id
in a request body — is an ordinary client error; a foreign-key violation on a
value the *server* computed is exactly the bug #861 wanted to keep visible.
The constraint alone cannot tell those apart, so this module uses the
discriminator that can: Postgres names the offending column and value in the
error's ``DETAIL``, and we answer 4xx only when that value is one the request
actually carried.

Everything else — including a foreign-key violation whose value appears
nowhere in the request — re-raises to the 500 path unchanged, so the class of
bug #861 was protecting stays as loud as it was.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote_plus

# SQLSTATEs this module speaks. 23505 stays with #861's own handler.
FOREIGN_KEY_VIOLATION = "23503"

# ``Key (server_group_id)=(abf64806-…) is not present in table "dhcp_server_group".``
# ``Key (id)=(…) is still referenced from table "dhcp_scope".``
# Composite keys render as ``Key (a, b)=(1, 2)``.
_DETAIL_RE = re.compile(
    r"Key \((?P<cols>[^)]*)\)=\((?P<vals>.*)\) "
    r"is (?P<kind>not present in|still referenced from) table \"(?P<table>[^\"]+)\"",
)


@dataclass(frozen=True)
class ForeignKeyViolation:
    """The parsed shape of a 23503 ``DETAIL``."""

    columns: tuple[str, ...]
    values: tuple[str, ...]
    table: str
    #: True for "not present in" (a dangling reference the request supplied),
    #: False for "still referenced from" (a delete of a row still in use).
    dangling: bool


def parse_foreign_key_detail(detail: str) -> ForeignKeyViolation | None:
    """Parse Postgres' ``DETAIL`` line, or None if it isn't one we know.

    Returning None is the safe answer: the caller then re-raises, so an
    unrecognised message can never be silently downgraded to a 4xx.
    """
    match = _DETAIL_RE.search(detail or "")
    if match is None:
        return None
    columns = tuple(c.strip() for c in match.group("cols").split(",") if c.strip())
    values = tuple(v.strip() for v in match.group("vals").split(",") if v.strip())
    if not columns or not values:
        return None
    return ForeignKeyViolation(
        columns=columns,
        values=values,
        table=match.group("table"),
        dangling=match.group("kind") == "not present in",
    )


# ``Key (name)=(Acme) already exists.`` / ``Key (customer_id, name)=(…, Acme) already exists.``
_UNIQUE_DETAIL_RE = re.compile(r"Key \((?P<cols>[^)]*)\)=\(.*\) already exists")


def unique_violation_message(detail: str) -> str:
    """The 409 text for a 23505, naming the conflicting field(s) (#2738).

    Only the column names are echoed, never the values: they are the caller's
    own input at best, and at worst a column the caller should not be reading
    back. An unparseable DETAIL keeps the generic sentence.
    """
    generic = "The request conflicts with existing data."
    match = _UNIQUE_DETAIL_RE.search(detail or "")
    if match is None:
        return generic
    cols = [c.strip() for c in match.group("cols").split(",") if c.strip()]
    if not cols:
        return generic
    fields = ", ".join(f"'{c}'" for c in cols)
    noun = "value" if len(cols) == 1 else "combination of values"
    return f"{generic[:-1]}: the {noun} of {fields} is already in use."


def extract_detail(exc: Any) -> str:
    """The Postgres ``DETAIL`` text for a DBAPI error, from wherever it lives.

    ``IntegrityError.orig`` is **not** the asyncpg exception — it is
    SQLAlchemy's ``AsyncAdapt_asyncpg_dbapi.IntegrityError`` wrapper, which
    re-exports ``sqlstate`` but not ``detail``. The real asyncpg error, and
    the DETAIL line naming the offending column and value, hangs off its
    ``__cause__``. Reading ``orig.detail`` alone returns "" for every error,
    which classifies every violation as unrecognised and re-raises — the
    handler then looks wired up and changes nothing.

    Falls back to ``str(exc.orig)``, which embeds the same DETAIL line, so a
    driver that arranges the chain differently still classifies.
    """
    orig = getattr(exc, "orig", None)
    for candidate in (getattr(orig, "__cause__", None), orig):
        detail = getattr(candidate, "detail", None)
        if detail:
            return str(detail)
    return str(orig) if orig is not None else str(exc)


def _walk_scalars(node: Any, out: set[str]) -> None:
    if isinstance(node, dict):
        for value in node.values():
            _walk_scalars(value, out)
    elif isinstance(node, list):
        for value in node:
            _walk_scalars(value, out)
    elif isinstance(node, bool) or node is None:
        # JSON booleans/null never render as a Postgres key value we'd match,
        # and ``str(True)`` == "True" could collide with a real string value.
        return
    else:
        out.add(str(node).casefold())


def client_supplied_values(body: bytes | None, path_params: dict[str, Any], query: str) -> set[str]:
    """Every scalar the request carried, **casefolded**, for comparison with
    DETAIL.

    Compared as whole tokens rather than by substring: a foreign key whose
    value is ``1`` would otherwise match any body containing the digit, which
    would hand a 4xx to precisely the server-side bug this is careful not to
    mask.

    Casefolded because Postgres renders a ``uuid`` in its own canonical
    lowercase regardless of how it arrived, while .NET and PowerShell clients
    emit uppercase GUIDs as a matter of course. A case-sensitive compare
    therefore answered 422 for one client and 500 for another sending the
    same id.
    """
    supplied: set[str] = {str(v).casefold() for v in path_params.values()}
    for pair in (query or "").split("&"):
        if not pair:
            continue
        _, _, raw = pair.partition("=")
        if raw:
            supplied.add(unquote_plus(raw).casefold())
    if body:
        try:
            _walk_scalars(json.loads(body), supplied)
        except (ValueError, TypeError):
            # A non-JSON body (multipart upload, raw bytes). Nothing to
            # match against, so the violation reads as server-side and
            # re-raises — the conservative direction.
            pass
    return supplied


def classify_foreign_key_violation(
    detail: str,
    body: bytes | None,
    path_params: dict[str, Any],
    query: str,
) -> tuple[int, str] | None:
    """``(status, message)`` for a client-caused 23503, else None.

    None means "re-raise" — either the DETAIL was unparseable, or none of the
    offending values came from this request, which makes it our bug.
    """
    violation = parse_foreign_key_detail(detail)
    if violation is None:
        return None

    supplied = client_supplied_values(body, path_params, query)
    # EVERY offending value must be one the request carried. On a composite
    # key where the server filled half of it, the half we got wrong is still
    # our bug, and answering 4xx would bury it.
    if not all(value.casefold() in supplied for value in violation.values):
        return None

    columns = ", ".join(violation.columns)
    if violation.dangling:
        return (
            422,
            f"{columns} references a {violation.table} row that does not exist.",
        )
    return (
        409,
        f"This row is still referenced by {violation.table} and cannot be removed.",
    )


__all__ = [
    "FOREIGN_KEY_VIOLATION",
    "ForeignKeyViolation",
    "classify_foreign_key_violation",
    "client_supplied_values",
    "extract_detail",
    "parse_foreign_key_detail",
]
