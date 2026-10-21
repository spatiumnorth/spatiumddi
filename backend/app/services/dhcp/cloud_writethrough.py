"""Write-through to agentless cloud/REST DHCP providers (FortiGate today).

Companion to :mod:`app.services.dhcp.windows_writethrough`. Where the
Windows driver takes per-object cmdlets, a cloud driver (subclass of
:class:`app.drivers.dhcp._cloud_base.AgentlessDHCPDriverBase`) takes the
**whole DHCP-server object per scope** — so every scope / pool / static /
option edit re-pushes the scope's full desired state, rebuilt from the DB.

Called from the scope / pool / static API endpoints (via the
``windows_writethrough`` helpers, which fan out to both Windows and cloud
members) **after** the DB is flushed but **before** commit, so a REST
failure surfaces as a 502 and rolls the transaction back — keeping the DB
and the FortiGate in sync.
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dhcp import get_driver, is_cloud
from app.drivers.dhcp._cloud_base import CloudDHCPAdoptionError
from app.drivers.dhcp.base import PoolDef, ScopeDef, StaticAssignmentDef
from app.models.dhcp import DHCPPool, DHCPScope, DHCPServer, DHCPStaticAssignment
from app.models.ipam import Subnet

logger = structlog.get_logger(__name__)


class CloudPushError(HTTPException):
    """502 — an agentless DHCP write-through failed; caller rolled back."""

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=502, detail=f"DHCP provider push failed: {detail}")


class CloudAdoptionRequired(HTTPException):
    """409 — a push would overwrite a provider DHCP object we never created.

    The operator must opt in (``adopt_existing``) to take it over. Distinct
    from :class:`CloudPushError` so the UI can offer an adopt-and-retry action
    instead of treating it as a transient provider failure.

    Carries ``X-Adoption-Required: true`` so clients can tell this 409 apart
    from other conflicts on the same endpoint (scope create also 409s on a
    duplicate group+subnet, where an adopt-retry would be wrong) — #865.
    """

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=409, detail=detail, headers={"X-Adoption-Required": "true"})


async def cloud_servers_for_group(db: AsyncSession, group_id: Any) -> list[DHCPServer]:
    """Return the cloud/REST DHCP members of ``group_id`` (possibly empty)."""
    if group_id is None:
        return []
    res = await db.execute(select(DHCPServer).where(DHCPServer.server_group_id == group_id))
    return [s for s in res.scalars().all() if is_cloud(s.driver)]


async def build_scope_def(
    db: AsyncSession,
    scope: DHCPScope,
    *,
    exclude_pool_ids: set[Any] | None = None,
    exclude_static_ids: set[Any] | None = None,
) -> ScopeDef:
    """Rebuild a neutral :class:`ScopeDef` for ``scope`` from current DB state.

    Queries pools + statics explicitly (rather than the ORM collections) so
    the freshly-flushed desired state is reflected — a just-added pool or a
    just-updated static is visible after the endpoint's flush.

    ``exclude_pool_ids`` / ``exclude_static_ids`` drop rows that are about to
    be deleted but haven't been removed from the DB yet: the scope / pool /
    static DELETE endpoints call the write-through **before** ``db.delete``
    (so the Windows driver can still read the object's attributes for its
    per-object ``remove_*`` cmdlet). Without this, a delete would re-push the
    doomed row and it would never leave the FortiGate.
    """
    exclude_pool_ids = exclude_pool_ids or set()
    exclude_static_ids = exclude_static_ids or set()

    subnet = await db.get(Subnet, scope.subnet_id)
    if subnet is None:
        raise CloudPushError(f"Scope {scope.id}'s subnet is missing from IPAM")
    subnet_cidr = str(subnet.network) if subnet.network else ""
    if not subnet_cidr:
        raise CloudPushError(f"Scope {scope.id}'s subnet has no CIDR")

    pool_rows = [
        p
        for p in (await db.execute(select(DHCPPool).where(DHCPPool.scope_id == scope.id)))
        .scalars()
        .all()
        if p.id not in exclude_pool_ids
    ]
    static_rows = [
        s
        for s in (
            await db.execute(
                select(DHCPStaticAssignment).where(DHCPStaticAssignment.scope_id == scope.id)
            )
        )
        .scalars()
        .all()
        if s.id not in exclude_static_ids
    ]

    pools = tuple(
        PoolDef(
            start_ip=str(p.start_ip),
            end_ip=str(p.end_ip),
            pool_type=p.pool_type,
            name=p.name or "",
            class_restriction=p.class_restriction,
            lease_time_override=p.lease_time_override,
            options_override=p.options_override or None,
        )
        for p in pool_rows
    )
    statics = tuple(
        StaticAssignmentDef(
            ip_address=str(s.ip_address),
            mac_address=str(s.mac_address),
            hostname=s.hostname or "",
            client_id=s.client_id,
            options_override=s.options_override or None,
        )
        for s in static_rows
    )
    return ScopeDef(
        subnet_cidr=subnet_cidr,
        lease_time=scope.lease_time,
        min_lease_time=scope.min_lease_time,
        max_lease_time=scope.max_lease_time,
        options=dict(scope.options or {}),
        pools=pools,
        statics=statics,
        is_active=scope.is_active,
        address_family=getattr(scope, "address_family", "ipv4") or "ipv4",
    )


def _provider_ref_for(scope: DHCPScope, server: DHCPServer) -> dict[str, Any] | None:
    """The ownership marker this ``(scope, server)`` pair holds, if any."""
    refs = scope.provider_refs or {}
    ref = refs.get(str(server.id))
    return ref if isinstance(ref, dict) else None


def _set_provider_ref(scope: DHCPScope, server: DHCPServer, ref: dict[str, Any] | None) -> None:
    """Persist / clear the ownership marker for ``(scope, server)``.

    Reassigns a fresh dict so SQLAlchemy flags the JSONB column dirty (mutating
    in place wouldn't, absent a MutableDict wrapper).
    """
    refs = dict(scope.provider_refs or {})
    key = str(server.id)
    if ref is None:
        refs.pop(key, None)
    else:
        refs[key] = ref
    scope.provider_refs = refs or None


async def push_cloud_scope_upsert(
    db: AsyncSession,
    scope: DHCPScope,
    *,
    exclude_pool_ids: set[Any] | None = None,
    exclude_static_ids: set[Any] | None = None,
    adopt_existing: bool = False,
) -> None:
    """Re-push the whole scope object to every cloud member of its group.

    ``exclude_pool_ids`` / ``exclude_static_ids`` drop rows pending deletion
    that the endpoint hasn't removed from the DB yet (see
    :func:`build_scope_def`).

    ``adopt_existing`` opts in to overwriting a pre-existing provider DHCP
    object SpatiumDDI never created (default off → :class:`CloudAdoptionRequired`
    / 409). The provider-assigned ownership marker each push returns is
    persisted onto ``scope.provider_refs`` so later edits target the same
    object without re-adopting.
    """
    servers = await cloud_servers_for_group(db, scope.group_id)
    if not servers:
        return
    scope_def = await build_scope_def(
        db,
        scope,
        exclude_pool_ids=exclude_pool_ids,
        exclude_static_ids=exclude_static_ids,
    )
    for server in servers:
        driver = get_driver(server.driver)
        try:
            new_ref = await driver.apply_scope_full(  # type: ignore[attr-defined]
                server,
                scope_def,
                provider_ref=_provider_ref_for(scope, server),
                adopt_existing=adopt_existing,
            )
        except CloudDHCPAdoptionError as exc:
            logger.info(
                "cloud_dhcp_push_scope_adoption_required",
                scope=str(scope.id),
                server=str(server.id),
                driver=server.driver,
            )
            raise CloudAdoptionRequired(str(exc)) from exc
        except Exception as exc:  # noqa: BLE001 — surface the error as a 502
            logger.warning(
                "cloud_dhcp_push_scope_failed",
                scope=str(scope.id),
                server=str(server.id),
                driver=server.driver,
                error=str(exc),
            )
            raise CloudPushError(str(exc)) from exc
        if new_ref is not None:
            _set_provider_ref(scope, server, new_ref)


async def push_cloud_scopes_delete_from_batch(db: AsyncSession, batch: Any) -> None:
    """Remove every soft-deleted :class:`DHCPScope` in ``batch`` from its cloud members.

    Cascade deletes (subnet / block / space) soft-delete their descendant DHCP
    scopes without the per-scope write-through firing. Agent-based Kea drops a
    soft-deleted scope automatically (the global ``deleted_at`` filter hides it
    from the config bundle), but an agentless push driver (FortiGate) only
    reflects the delete if we push it. Call this before commit so a REST
    failure (502) rolls the whole cascade back.
    """
    for row in getattr(batch, "rows", []):
        obj = getattr(row, "obj", None)
        if isinstance(obj, DHCPScope):
            await push_cloud_scope_delete(db, obj)


async def push_cloud_scope_delete(db: AsyncSession, scope: DHCPScope) -> None:
    """Remove the scope's DHCP object from every cloud member of its group."""
    servers = await cloud_servers_for_group(db, scope.group_id)
    if not servers:
        return
    subnet = await db.get(Subnet, scope.subnet_id)
    subnet_cidr = str(subnet.network) if subnet and subnet.network else ""
    if not subnet_cidr:
        return
    for server in servers:
        driver = get_driver(server.driver)
        try:
            await driver.remove_scope_full(  # type: ignore[attr-defined]
                server, subnet_cidr, provider_ref=_provider_ref_for(scope, server)
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "cloud_dhcp_push_scope_delete_failed",
                scope=str(scope.id),
                server=str(server.id),
                driver=server.driver,
                error=str(exc),
            )
            raise CloudPushError(str(exc)) from exc
        # We released (or never owned) the object — drop the ownership marker so
        # a later restore re-creates + re-claims rather than assuming ownership.
        _set_provider_ref(scope, server, None)


__all__ = [
    "CloudAdoptionRequired",
    "CloudPushError",
    "build_scope_def",
    "cloud_servers_for_group",
    "push_cloud_scope_delete",
    "push_cloud_scope_upsert",
    "push_cloud_scopes_delete_from_batch",
]
