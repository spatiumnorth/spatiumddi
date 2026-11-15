"""One rule for rows that keep a write-only credential next to an editable
destination.

The API never returns such a credential, so an editor who changes only the
destination (URL, host, port) would otherwise have the stored credential sent
to the new place without ever being asked for it. The edit is refused with a
422 naming the changed field unless the same request supplies the credential
again (or clears it).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from fastapi import HTTPException


def _present(value: Any) -> bool:
    """A stored or supplied credential is "there" when it is non-empty."""
    return bool(value)


def require_secret_with_destination_change(
    row: Any,
    changes: Mapping[str, Any],
    *,
    destination: Iterable[str],
    secrets: Mapping[str, Any],
    replaced: Iterable[str] = (),
) -> None:
    """422 when a destination field changes and a stored credential is kept.

    ``changes`` is the request's set fields (``exclude_unset``). ``destination``
    names the fields that decide where the credential is sent; a field counts
    as changed when its value differs from ``getattr(row, field)``. ``secrets``
    maps each request field that carries a credential to what is stored now
    (the encrypted column's value). Every stored credential must be present in
    ``changes`` for the edit to go through; a credential sent as ``""`` clears
    it, which also satisfies the rule since nothing is left to forward.

    ``replaced`` names destinations that are themselves stored encrypted (so
    they cannot be compared with the row): a non-empty value in ``changes``
    counts as a move.
    """
    moved = [f for f in replaced if changes.get(f)]
    for field in destination:
        if field not in changes:
            continue
        # Compared as text: an INET column reads back as a string while the
        # request may carry an ``IPv4Address``.
        if str(getattr(row, field, None)) != str(changes[field]):
            moved.append(field)
    if not moved:
        return
    for name, stored in secrets.items():
        if _present(stored) and changes.get(name) is None:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"{moved[0]} changed: re-enter {name} in the same request "
                    "(stored credentials are not re-sent to a different destination)"
                ),
            )


def sent_server_credential(windows_credentials: Any, cloud_credentials: Any) -> str | None:
    """What an agentless server edit says about its stored credential blob.

    ``None`` when the request does not re-supply it, ``""`` when it clears
    the blob, otherwise the new secret (the WinRM password or the REST API
    token). A request that carries only transport / port / TLS settings
    keeps the stored secret and so returns ``None``.
    """
    for blob, secret_key in ((windows_credentials, "password"), (cloud_credentials, "api_token")):
        if blob is None:
            continue
        if isinstance(blob, Mapping):
            if not blob:
                return ""
            value = blob.get(secret_key)
        else:
            value = getattr(blob, secret_key, None)
        if value:
            return str(value)
    return None
