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
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

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


def norm_uuid_sql(expr: str) -> str:
    """SQL folding a stored id (text) to its 32 lower-case hex digits.

    Before #2923 the IPAM bindings stored an id as given, so a value Python's
    ``uuid.UUID`` reads as an id (upper-case, braced, unhyphenated,
    ``urn:uuid:``) need not equal ``<table>.id::text``, while every reader
    (:func:`stored_uuid_list`, :func:`stored_zone_uuid`) resolves it. Compare
    ``norm_uuid_sql(col)`` against ``uuid.hex`` (or against
    ``replace(id::text, '-', '')``) to match exactly the values the readers
    resolve. Shared by the DNS group prune (#3433) and the zone prune (#3443).
    """
    return f"regexp_replace(lower({expr}), 'urn:|uuid:|[{{}}-]', '', 'g')"


# The IPAM tables whose ``dns_group_ids`` can name a DNS server group (#3433).
DNS_GROUP_ID_TABLES = ("ip_space", "ip_block", "subnet")


def _group_prune_sql(table: str, keep: str, drop: str) -> str:
    """UPDATE keeping the ``dns_group_ids`` entries for which ``keep`` holds,
    in order (the first one picks the reverse-zone group), on rows with an
    entry for which ``drop`` holds. ``e`` / ``x`` are the folded entries."""
    elem_e = norm_uuid_sql("e #>> '{}'")
    elem_x = norm_uuid_sql("x #>> '{}'")
    return f"""
        UPDATE {table} SET dns_group_ids = COALESCE((
            SELECT jsonb_agg(e ORDER BY o)
            FROM jsonb_array_elements(dns_group_ids) WITH ORDINALITY AS t(e, o)
            WHERE COALESCE({keep.format(v=elem_e)}, false)
        ), '[]'::jsonb)
        WHERE jsonb_typeof(dns_group_ids) = 'array'
          AND EXISTS (
            SELECT 1 FROM jsonb_array_elements(dns_group_ids) x
            WHERE COALESCE({drop.format(v=elem_x)}, false)
          )
        """  # noqa: S608


async def prune_group_ids(db: AsyncSession, group_ids: Iterable[object]) -> None:
    """Remove these DNS server group ids from every IPAM ``dns_group_ids``
    (#3433).

    The column is a JSONB id list with no foreign key, so deleting a group
    leaves every space, block and subnet that named it counting a group that
    is gone. Raw UPDATEs, so Trash rows lose the id too and a restore brings
    back no dead reference. Ids compare by their hex digits, so any spelling
    the readers resolve is matched. The caller owns the commit.
    """
    ids = sorted({u.hex for u in stored_uuid_list(group_ids)})
    if not ids:
        return
    for table in DNS_GROUP_ID_TABLES:
        await db.execute(
            text(
                _group_prune_sql(
                    table,
                    keep="NOT ({v} = ANY(CAST(:ids AS text[])))",
                    drop="{v} = ANY(CAST(:ids AS text[]))",
                )
            ),
            {"ids": ids},
        )


async def prune_dead_group_ids_asyncpg(conn: Any) -> None:
    """Remove every IPAM ``dns_group_ids`` entry that names no
    ``dns_server_group`` row (#3433).

    For the factory reset, which wipes DNS over a raw asyncpg connection and
    keeps IPAM when only the DNS section is chosen: after the wipe every
    entry is dead. Same rules as :func:`prune_group_ids`.
    """
    live = "(SELECT replace(id::text, '-', '') FROM dns_server_group)"
    for table in DNS_GROUP_ID_TABLES:
        await conn.execute(
            _group_prune_sql(table, keep="{v} IN " + live, drop="{v} NOT IN " + live)
        )


async def assert_zones_exist(db: AsyncSession, zone_ids: Iterable[object] | None) -> None:
    """422 when a zone id a request carries names no zone (#3443).

    The columns are text / JSONB with no foreign key, so nothing in the
    database refuses an id that names no zone. A zone in the Trash still
    exists (a restore brings it back), so it passes: the model is queried
    with ``include_deleted``. Blank entries and non-UUIDs are the validators'
    business, not this check's.
    """
    from app.models.dns import DNSZone  # noqa: PLC0415

    wanted = {u for u in (stored_zone_uuid(z) for z in zone_ids or []) if u is not None}
    if not wanted:
        return
    found = set(
        (
            await db.execute(
                select(DNSZone.id)
                .where(DNSZone.id.in_(wanted))
                .execution_options(include_deleted=True)
            )
        )
        .scalars()
        .all()
    )
    missing = sorted(str(z) for z in wanted - found)
    if missing:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"DNS zone(s) that do not exist: {', '.join(missing)}",
        )


# (table, text zone column, JSONB zone-list column) for every IPAM row that
# names a DNS zone without a foreign key (#3443).
_ZONE_ID_COLUMNS: tuple[tuple[str, str | None, str], ...] = (
    ("ip_space", "dns_zone_id", "dns_additional_zone_ids"),
    ("ip_block", "dns_zone_id", "dns_additional_zone_ids"),
    ("subnet", "dns_zone_id", "dns_additional_zone_ids"),
    ("ipam_template", "dns_zone_id", "dns_additional_zone_ids"),
    ("ip_address", None, "extra_zone_ids"),
)


def _strip_plan_zones(node: Any, dead: set[str]) -> bool:
    if not isinstance(node, dict):
        return False
    changed = False
    zid = stored_zone_uuid(node.get("dns_zone_id"))
    if zid is not None and str(zid) in dead:
        node["dns_zone_id"] = None
        changed = True
    for child in node.get("children") or []:
        changed = _strip_plan_zones(child, dead) or changed
    return changed


async def prune_zone_ids(db: AsyncSession, zone_ids: Iterable[object]) -> None:
    """Remove ``zone_ids`` from every IPAM row that names a DNS zone (#3443).

    Called by every path that deletes a zone row (Trash purge, permanent
    delete, the scheduled purge, a reverse-zone retirement, an importer's
    overwrite, deleting the group a trashed zone belongs to). Raw UPDATEs, so
    rows in the Trash lose the id too and a restore brings back no dead
    reference. Ids compare as lower-case text and the entries kept stay in
    order (the first one picks the reverse-zone group). Unapplied subnet plans
    have the id cleared from their tree nodes; an applied plan is a record of
    what was created and is left alone. The caller owns the commit.
    """
    dead = {str(u) for u in (stored_zone_uuid(z) for z in zone_ids) if u is not None}
    if not dead:
        return
    ids = sorted(dead)
    for table, text_col, list_col in _ZONE_ID_COLUMNS:
        if text_col:
            await db.execute(
                text(
                    f"UPDATE {table} SET {text_col} = NULL "  # noqa: S608
                    f"WHERE lower({text_col}) = ANY(CAST(:ids AS text[]))"
                ),
                {"ids": ids},
            )
        await db.execute(
            text(f"""
                UPDATE {table} SET {list_col} = COALESCE((
                    SELECT jsonb_agg(e ORDER BY o)
                    FROM jsonb_array_elements({list_col}) WITH ORDINALITY AS t(e, o)
                    WHERE NOT (lower(e #>> '{{}}') = ANY(CAST(:ids AS text[])))
                ), '[]'::jsonb)
                WHERE jsonb_typeof({list_col}) = 'array'
                  AND EXISTS (
                    SELECT 1 FROM jsonb_array_elements({list_col}) x
                    WHERE lower(x #>> '{{}}') = ANY(CAST(:ids AS text[]))
                  )
                """),  # noqa: S608
            {"ids": ids},
        )

    from app.models.ipam import SubnetPlan  # noqa: PLC0415

    for plan in (
        (await db.execute(select(SubnetPlan).where(SubnetPlan.applied_at.is_(None))))
        .scalars()
        .all()
    ):
        tree = plan.tree
        if _strip_plan_zones(tree, dead):
            plan.tree = dict(tree)
            from sqlalchemy.orm.attributes import flag_modified  # noqa: PLC0415

            flag_modified(plan, "tree")
