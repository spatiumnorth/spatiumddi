"""One rule for rows that keep a write-only credential next to an editable
destination.

The API never returns such a credential, so an editor who changes only the
destination (URL, host, port) would otherwise have the stored credential sent
to the new place without ever being asked for it. The edit is refused with a
422 naming the changed field unless the same request supplies the credential
again (or clears it). The same rule covers a connection test that names a
stored row but overrides where it connects.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from fastapi import HTTPException


def _present(value: Any) -> bool:
    """A stored or supplied credential is "there" when it is non-empty."""
    return bool(value)


def moved_destinations(
    row: Any,
    changes: Mapping[str, Any],
    destination: Iterable[str],
    replaced: Iterable[str] = (),
) -> list[str]:
    """The destination fields ``changes`` moves away from what ``row`` holds."""
    moved = [f for f in replaced if changes.get(f)]
    for field in destination:
        if field not in changes:
            continue
        # Compared as text: an INET column reads back as a string while the
        # request may carry an ``IPv4Address``.
        if str(getattr(row, field, None)) != str(changes[field]):
            moved.append(field)
    return moved


def release_block_sync_credentials(
    row: Any,
    changes: Mapping[str, Any],
    *,
    destination: Iterable[str],
    credentials: Mapping[str, Any],
    label: str,
) -> bool:
    """Drop the stored block-sync write credentials when the target moves.

    The write credential is set from the block-sync page, not from the
    integration form, so an edit that moves the destination cannot carry it
    again. It belonged to the old destination: it is cleared here (the
    operator enters it again for the new one), and an armed target is refused
    rather than left pushing with nothing, since disarming lifts what was
    pushed to the old destination. ``credentials`` maps each column to its
    empty value. Returns True when something was cleared.
    """
    if not moved_destinations(row, changes, destination):
        return False
    if not any(getattr(row, col) for col in credentials):
        return False
    if getattr(row, "block_sync_enabled", False):
        raise HTTPException(
            status_code=422,
            detail=(
                f"{label} changed while block sync is armed: disarm block sync first, "
                "then enter its write credentials again for the new destination "
                "(stored credentials are not re-sent to a different destination)"
            ),
        )
    for col, empty in credentials.items():
        setattr(row, col, empty)
    return True


def require_secret_with_destination_change(
    row: Any,
    changes: Mapping[str, Any],
    *,
    destination: Iterable[str],
    secrets: Mapping[str, Any],
    replaced: Iterable[str] = (),
    transport: Iterable[str] = (),
    blank_keeps: Iterable[str] = (),
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

    ``transport`` names destination fields that are settings of how the
    credential travels (not where it goes); the refusal then says the
    transport changed rather than the destination.

    ``blank_keeps`` names the credential fields whose handler reads ``""`` as
    "keep the stored value" (the common integration convention) rather than
    "clear it". For those a blank is not a re-entry, so it does not satisfy the
    rule; a handler where ``""`` clears leaves the field out.
    """
    keeps_blank = set(blank_keeps)
    moved = moved_destinations(row, changes, destination, replaced)
    if not moved:
        return
    for name, stored in secrets.items():
        sent = changes.get(name)
        if sent == "" and name in keeps_blank:
            sent = None
        if _present(stored) and sent is None:
            if moved[0] in set(transport):
                raise HTTPException(
                    status_code=422,
                    detail=(
                        f"{moved[0]} changed to a less protected transport: "
                        f"re-enter {name} in the same request"
                    ),
                )
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


def require_secret_for_changed_connection(
    row: Any,
    supplied: Mapping[str, Any],
    *,
    destination: Iterable[str],
    secrets: Mapping[str, Any],
) -> None:
    """422 when a connection test on a stored row would use its credential
    against a destination other than the row's.

    A test that names a stored row falls back to the stored credential for
    every field it leaves blank. If it also names a different host, port or
    URL, that fallback would send the credential to the new place, so the
    request must carry the credential itself. Blank or absent fields mean "use
    the stored value" here and are not compared.
    """
    given = {k: v for k, v in supplied.items() if v not in (None, "")}
    require_secret_with_destination_change(
        row,
        given,
        destination=destination,
        secrets=secrets,
        blank_keeps=secrets.keys(),
    )
