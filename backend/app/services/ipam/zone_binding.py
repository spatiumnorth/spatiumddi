"""The text ``dns_zone_id`` binding IPAM rows carry (#2923).

Spaces, blocks, subnets, templates and addresses store the DNS zone they
publish into as text rather than as a foreign key, so nothing in the
database refuses a value that is not a zone id. These helpers are the one
rule for both directions: ``check_zone_uuid`` / ``check_zone_uuid_list``
(and ``check_group_uuid_list`` for the ``dns_group_ids`` beside them)
refuse a non-UUID on the way in (a pydantic ``field_validator`` turns the
``ValueError`` into a 422), and ``stored_zone_uuid`` reads a value already
stored — including one an older build accepted — without raising.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable

ZONE_ID_ERROR = "dns_zone_id must be the UUID of a DNS zone"


def check_zone_uuid(v: str | None, *, blank: str | None = None) -> str | None:
    """Return ``v`` as a canonical UUID string, or raise ``ValueError``.

    ``None`` passes through. ``""`` is returned as ``blank``: ``None`` where
    an empty string has no meaning of its own (a space, block, subnet or
    template binding, where null and ``""`` both read as "no zone"), and
    ``""`` where it does (an address body, where it is the dialog's "None —
    no DNS record", #2466).
    """
    if v is None:
        return None
    if v == "":
        return blank
    try:
        return str(uuid.UUID(str(v)))
    except ValueError as exc:
        raise ValueError(ZONE_ID_ERROR) from exc


def check_uuid_list(v: Iterable[str] | None, *, field: str, noun: str) -> list[str] | None:
    """Refuse a list of ids with any entry that is not a UUID; return the
    entries in canonical form."""
    if v is None:
        return None
    out: list[str] = []
    for item in v:
        try:
            out.append(str(uuid.UUID(str(item))))
        except ValueError as exc:
            raise ValueError(f"{field} entries must be UUIDs of {noun}") from exc
    return out


def check_zone_uuid_list(v: Iterable[str] | None, *, field: str) -> list[str] | None:
    """Refuse a list of zone ids with any entry that is not a UUID."""
    return check_uuid_list(v, field=field, noun="DNS zones")


def check_group_uuid_list(v: Iterable[str] | None) -> list[str] | None:
    """The same rule for the ``dns_group_ids`` binding beside the zone."""
    return check_uuid_list(v, field="dns_group_ids", noun="DNS server groups")


def stored_zone_uuid(value: object) -> uuid.UUID | None:
    """Parse a stored ``dns_zone_id`` for use, never raising.

    A value that is not a UUID names no zone, so it reads as no zone — the
    same answer ``forward_zone_ids_in_order`` gives a non-UUID entry in
    ``extra_zone_ids``. Before #2923 the space and block creates (and the
    subnet, template and plan writes) stored such a value as given, and the
    effective-DNS walk then raised on it for every subnet inheriting it.
    """
    if not value:
        return None
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        return None


def stored_uuid_list(values: Iterable[object] | None) -> list[uuid.UUID]:
    """Parse a stored list of ids (``dns_group_ids``), skipping any entry
    that is not a UUID — the list counterpart of :func:`stored_zone_uuid`."""
    out: list[uuid.UUID] = []
    for raw in values or []:
        try:
            out.append(uuid.UUID(str(raw)))
        except (ValueError, TypeError):
            continue
    return out
