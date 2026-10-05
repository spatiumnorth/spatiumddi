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

from collections.abc import Collection
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
    nulled = sorted(
        k for k, v in changes.items() if v is None and k in non_nullable_set
    )
    if nulled:
        raise HTTPException(
            status_code=422,
            detail=(
                f"{', '.join(nulled)} cannot be null. Omit the field to leave it "
                "unchanged, or send a value."
            ),
        )
    return {
        k: v
        for k, v in changes.items()
        if v is not None or k in clearable_set
    }


__all__ = ["resolve_update_changes"]
