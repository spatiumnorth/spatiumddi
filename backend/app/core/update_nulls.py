"""Shared explicit-null semantics for PUT update handlers (#1563, #1564).

Update schemas type every field ``T | None`` so a partial body can omit
what it isn't changing — which makes ``None`` ambiguous between "not
sent", "clear this nullable column" and "null for a NOT NULL column".
Handlers historically resolved that ambiguity in one of two broken
ways:

* ``model_dump(exclude_unset=True)`` + blanket ``setattr`` let an
  explicit null reach a NOT NULL column, where Postgres answered with
  an unhandled 500 (#1564);
* ``model_dump(exclude_none=True)`` silently dropped an explicit null
  for a *nullable* column, so the UI's "clear" action returned 200 and
  changed nothing (#1563, the #1458 defect).

``dhcp/device_policies.py`` (#1564's reference) and ``dhcp/scopes.py``
each solved one half locally. This helper is the shared version both
issues ask for: the caller names, per resource, the fields an explicit
null may CLEAR and the fields it must REJECT, and every other null is
dropped (the old ``exclude_none`` behaviour — a partial-body client
that serialises unmanaged optionals as null must not silently wipe
them, per the scopes rationale).

Contract for ``resolve_update_changes(body, clearable, non_nullable)``:

* field omitted from the body → absent from the result (untouched);
* field sent non-null → present with its value;
* field sent null and in ``clearable`` → present with ``None`` (the
  column is set to NULL);
* field sent null and in ``non_nullable`` → 422 naming the fields,
  mirroring ``device_policies.py``'s message;
* field sent null and in neither set → absent (dropped, not cleared).
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping
from datetime import datetime
from decimal import Decimal
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel


def resolve_update_changes(
    body: BaseModel,
    *,
    clearable: Collection[str] = (),
    non_nullable: Collection[str] = (),
    exclude: Collection[str] | None = None,
) -> dict[str, Any]:
    """Turn an update body into the ``setattr`` changes dict.

    ``exclude`` names schema fields the handler routes elsewhere than
    the generic setattr loop (credentials, group moves, …); they are
    left out of the result exactly as a ``model_dump(exclude=…)``
    would leave them, and a null sent for one is that other path's
    business, not this helper's.
    """
    changes = body.model_dump(
        exclude_unset=True,
        exclude=set(exclude) if exclude else None,
    )
    clearable_set = set(clearable)
    non_nullable_set = set(non_nullable)
    nulled = sorted(k for k, v in changes.items() if v is None and k in non_nullable_set)
    if nulled:
        raise HTTPException(
            status_code=422,
            detail=(
                f"{', '.join(nulled)} cannot be null. Omit the field to leave it "
                "unchanged, or send a value."
            ),
        )
    return {k: v for k, v in changes.items() if v is not None or k in clearable_set}


class _Empty:
    """The one value an empty list and an empty mapping both normalise to."""

    def __repr__(self) -> str:
        return "<empty>"


_EMPTY = _Empty()


def _norm(value: Any) -> Any:
    """A comparable form of ``value``: empty text is NULL, rich types are text.

    A stored NULL and the empty string a dialog posts back for it are the same
    value: every text field an update dialog shows reads both as "not set".
    An empty list and an empty mapping are the same as each other (a dialog
    posts ``[]`` for an options column the row stores as ``{}``) but NOT the
    same as NULL, because for some columns they mean different things: a DNS
    zone's ``allow_transfer`` of NULL inherits the server's list while ``[]``
    narrows transfers to the group's keys, and ``allow_recursion`` /
    ``allow_query_cache`` render ``none`` for ``[]`` but a default for NULL.
    Merging them would leave a real change out of the audit row.

    Mappings and lists are normalised member by member (a dialog posts options
    as the same nested structure the row stores), and anything that is not a
    plain JSON scalar (UUID, ipaddress, Enum, ...) is compared by its text,
    since the row and the request body hold the same value as different types.
    """
    if value is None or value == "":
        return None
    if isinstance(value, (Mapping, list, tuple)) and not value:
        return _EMPTY
    if isinstance(value, Mapping):
        return {str(k): _norm(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_norm(v) for v in value]
    if isinstance(value, (str, int, float, bool, Decimal, datetime)):
        return value
    return str(value)


def _same(old: Any, new: Any, *, unordered: bool) -> bool:
    a, b = _norm(old), _norm(new)
    if unordered and isinstance(a, list) and isinstance(b, list):
        return sorted(map(repr, a)) == sorted(map(repr, b))
    return bool(a == b)


def snapshot(obj: Any, keys: Iterable[str]) -> dict[str, Any]:
    """``{key: current value}`` for each key that is a real attribute of ``obj``.

    Taken just before a handler's ``setattr`` loop, it is the ``before`` that
    ``changed_keys`` compares against. A key that is not an attribute (a
    handler-computed marker) is left out so it counts as changed.
    """
    return {k: getattr(obj, k) for k in keys if hasattr(obj, k)}


def changed_keys(
    before: Mapping[str, Any],
    changes: Mapping[str, Any],
    *,
    unordered: Collection[str] = (),
) -> list[str]:
    """The keys of ``changes`` whose value differs from ``before`` (#2463, #3086).

    An update dialog sends every field it shows, so ``changes`` holds keys the
    operator never touched; the audit row names only those that moved. Values
    are compared normalised (see ``_norm``): NULL and empty are the same, and a
    list named in ``unordered`` is compared as a multiset. A key absent from
    ``before`` was added by the handler itself and counts.
    """
    return [
        k
        for k, v in changes.items()
        if k not in before or not _same(before[k], v, unordered=k in unordered)
    ]


__all__ = ["changed_keys", "resolve_update_changes", "snapshot"]
