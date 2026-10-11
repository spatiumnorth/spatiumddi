"""Supported scope of the experimental agentless ``technitium_api`` driver (#1784).

The driver writes into a Technitium server SpatiumDDI does not own and has
no reconcile loop, so several things the platform offers on other drivers
would either do nothing or do damage there (DNS pools collapse to one
member, an overwrite wipes the operator's own records, SOA / ACL / zone
options are never written, a second server never receives the zone).  Fixing
them is tracked for 1.1.0 (#1769, #1771, #1774, #1775); for 1.0.0 the driver
is labelled experimental and the API refuses what it cannot do, instead of
accepting it and silently not doing it.

Supported: ONE ``technitium_api`` server per group, zones SpatiumDDI creates
(Primary only), records on those zones.  Everything else is a 422 from here.

Groups that already violate the scope (two servers, pools) are NOT broken:
serving continues, the refusals apply only to new changes, and
:func:`scope_warnings_by_group` surfaces a warning on the group.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Any

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import (
    ZONE_DEFAULT_EXPIRE,
    ZONE_DEFAULT_MINIMUM,
    ZONE_DEFAULT_REFRESH,
    ZONE_DEFAULT_RETRY,
    DNSPool,
    DNSServer,
    DNSServerOptions,
)

DRIVER = "technitium_api"
EXPERIMENTAL = "technitium_api is experimental in 1.0"

#: Zone fields the driver never writes (it sends only ``zone`` + ``type``),
#: with the value they hold when left alone.
ZONE_UNAPPLIED_DEFAULTS: dict[str, Any] = {
    "ttl": 3600,
    "refresh": ZONE_DEFAULT_REFRESH,
    "retry": ZONE_DEFAULT_RETRY,
    "expire": ZONE_DEFAULT_EXPIRE,
    "minimum": ZONE_DEFAULT_MINIMUM,
    "primary_ns": "",
    "admin_email": "",
    "allow_query": None,
    "allow_transfer": None,
    "also_notify": None,
    "notify_enabled": None,
}

#: Group-level fields on ``DNSServerGroup`` the driver never applies.
GROUP_UNAPPLIED_DEFAULTS: dict[str, Any] = {"catalog_zones_enabled": False}


def refusal(reason: str, deferred: str = "1.1.0") -> HTTPException:
    """422 naming the experimental status and the reason."""
    return HTTPException(
        status_code=422,
        detail=(
            f"{EXPERIMENTAL}: {reason} Full support is planned for {deferred} "
            "(#1769, #1771, #1774, #1775). Use the agent-managed 'technitium' "
            "driver for this."
        ),
    )


def _empty(value: Any) -> bool:
    return value is None or value == "" or value == []


async def group_is_technitium_api(db: AsyncSession, group_id: uuid.UUID) -> bool:
    n = (
        await db.execute(
            select(func.count())
            .select_from(DNSServer)
            .where(DNSServer.group_id == group_id, DNSServer.driver == DRIVER)
        )
    ).scalar_one()
    return bool(n)


async def count_other_servers(
    db: AsyncSession, group_id: uuid.UUID, exclude_server_id: uuid.UUID | None = None
) -> int:
    conditions = [DNSServer.group_id == group_id, DNSServer.driver == DRIVER]
    if exclude_server_id is not None:
        conditions.append(DNSServer.id != exclude_server_id)
    return int(
        (
            await db.execute(select(func.count()).select_from(DNSServer).where(*conditions))
        ).scalar_one()
    )


def single_server_message(group_name: str) -> str:
    return (
        f"{EXPERIMENTAL}: group {group_name!r} already has a technitium_api "
        "server, and only one is supported per group. The driver has no "
        "reconcile loop, so a second server never receives zones the first "
        "was given (#1771). Put it in its own group."
    )


def refuse_unapplied_zone_changes(changes: dict[str, Any], current: Any | None) -> None:
    """422 a zone field the driver never writes being set to a non-default.

    ``current`` is the stored zone on update: only a CHANGED value is
    refused, so a zone that already holds one (set before the gate, or on
    another driver and moved in) can still be re-saved unchanged.  On
    create it is ``None`` and the baseline is the default.
    """
    for field, default in ZONE_UNAPPLIED_DEFAULTS.items():
        if field not in changes:
            continue
        value = changes[field]
        baseline = getattr(current, field) if current is not None else default
        if value == baseline or (_empty(value) and _empty(baseline)):
            continue
        raise refusal(
            f"zone field {field!r} is never written to the Technitium server, "
            "so setting it would be accepted and have no effect.",
        )


def refuse_non_primary(zone_type: str | None) -> None:
    if zone_type is not None and zone_type != "primary":
        raise refusal(
            f"only Primary zones are supported; this zone is {zone_type!r}. "
            "Create secondary / stub / forward zones in the Technitium "
            "console (they are not managed by SpatiumDDI), or use the "
            "agent-managed 'technitium' driver.",
        )


def _column_default(column_name: str) -> Any:
    col = DNSServerOptions.__table__.c[column_name]
    default = col.default
    if default is None:
        return None
    if getattr(default, "is_scalar", False):
        return default.arg
    if getattr(default, "is_callable", False):
        # SQLAlchemy wraps a column default callable to take the exec context.
        return default.arg(None)
    return None


#: Option fields that are bookkeeping, not settings the operator configures.
_OPTION_IGNORED = frozenset({"id", "group_id", "created_at", "modified_at"})


def refuse_unapplied_option_changes(
    changes: dict[str, Any], current: DNSServerOptions | None
) -> None:
    """422 a group option being changed: this driver writes none of them.

    Compared against the stored row (or the column default when there is no
    row yet) so an unchanged re-save of a form passes.
    """
    for field, value in changes.items():
        if field in _OPTION_IGNORED or field not in DNSServerOptions.__table__.c:
            continue
        baseline = (
            getattr(current, field, None)
            if current is not None and current.id is not None
            else _column_default(field)
        )
        if value == baseline or (_empty(value) and _empty(baseline)):
            continue
        raise refusal(
            f"group option {field!r} is never applied to the Technitium "
            "server (the driver writes zones and records only), so changing "
            "it would be accepted and have no effect.",
        )


async def scope_warnings_by_group(
    db: AsyncSession, group_ids: Iterable[uuid.UUID]
) -> dict[uuid.UUID, list[str]]:
    """Warnings for groups that already violate the supported scope."""
    ids = list(group_ids)
    if not ids:
        return {}
    servers = {
        gid: n
        for gid, n in (
            await db.execute(
                select(DNSServer.group_id, func.count())
                .where(DNSServer.group_id.in_(ids), DNSServer.driver == DRIVER)
                .group_by(DNSServer.group_id)
            )
        ).all()
    }
    if not servers:
        return {}
    pools = {
        gid: n
        for gid, n in (
            await db.execute(
                select(DNSPool.group_id, func.count())
                .where(DNSPool.group_id.in_(list(servers)))
                .group_by(DNSPool.group_id)
            )
        ).all()
    }
    out: dict[uuid.UUID, list[str]] = {}
    for gid, n in servers.items():
        warnings = [
            f"{EXPERIMENTAL}: zones SpatiumDDI creates, one server per group, no "
            "pools, no group or zone options."
        ]
        if n > 1:
            warnings.append(
                f"This group has {n} technitium_api servers; only one is "
                "supported. Zones created later reach every server, but a server "
                "added after a zone exists never receives it."
            )
        if pools.get(gid):
            warnings.append(
                f"This group has {pools[gid]} DNS pool(s); pools are not "
                "supported on technitium_api and collapse to one member."
            )
        out[gid] = warnings
    return out
