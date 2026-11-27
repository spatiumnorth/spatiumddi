"""Tenant boundary enforcement (#4263, multi-tenancy phase 1 of #695).

One rule, applied in one place. A *tenant user* is a user none of whose
effective superadmin status applies and at least one of whose groups is bound
to a tenant (or whose API token is pinned to one). For such a request the auth
dependency stores the tenant ids on the request's session
(``session.info["tenant_scope"]``), and this module's ``do_orm_execute`` hook
then narrows every SELECT over an IPAM model to the tenant's spaces:

* ``ip_space.tenant_id`` is the only stored fact; blocks, subnets and addresses
  follow their space (``ip_block.space_id``, ``subnet.space_id``,
  ``ip_address.subnet_id -> subnet``), so moving a block between spaces moves
  its tenant with it;
* a row of another tenant is simply absent, so a guessed id reads 404, never
  403, and lists, counts, searches, exports and reports cover only the tenant;
* the filter is independent of ``include_deleted``: a trashed row of another
  tenant is just as invisible;
* sessions without a scope (everyone but tenant users) pay one dict lookup.

Writes are checked at flush: a tenant session cannot create or move a space
into another tenant, and cannot point an IPAM row at DNS / DHCP objects (those
stay install-wide in phase 1).

NOT covered, by design: Core ``Table`` joins and ``text()`` SQL. Routes that
use raw SQL over IPAM tables must filter by hand, and every route that is not
declared tenant-aware (``app.api.tenant_binding``) is refused to tenant users.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Any

import structlog
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, with_loader_criteria
from sqlalchemy.orm.attributes import get_history

logger = structlog.get_logger(__name__)

SCOPE_KEY = "tenant_scope"

# table name -> (column that carries the link, what the link points at)
_LINKS: dict[str, tuple[str, str]] = {
    "ip_space": ("tenant_id", "tenant"),
    "ip_block": ("space_id", "space"),
    "subnet": ("space_id", "space"),
    "ip_address": ("subnet_id", "subnet"),
    "subnet_domain": ("subnet_id", "subnet"),
    "subnet_utilization_history": ("subnet_id", "subnet"),
    "subnet_plan": ("space_id", "space"),
    "vlan_mapping": ("space_id", "space"),
    "ip_mac_history": ("ip_address_id", "address"),
}


def tenant_models() -> tuple[type, ...]:
    """The tenant-scoped IPAM models, resolved lazily (import cycles)."""
    from app.models.ipam import (
        IPAddress,
        IPBlock,
        IpMacHistory,
        IPSpace,
        Subnet,
        SubnetDomain,
        SubnetPlan,
        SubnetUtilizationHistory,
        VLANMapping,
    )

    return (
        IPSpace,
        IPBlock,
        Subnet,
        IPAddress,
        SubnetDomain,
        SubnetUtilizationHistory,
        SubnetPlan,
        VLANMapping,
        IpMacHistory,
    )


# ── Who is a tenant user ────────────────────────────────────────────────────


def tenant_scope_for(user: Any) -> frozenset[uuid.UUID] | None:
    """The tenant ids ``user`` is confined to, or ``None`` for no confinement.

    * An effective superadmin is never confined by group membership, but a
      token pinned to a tenant still confines the request.
    * Otherwise the scope is the union of the tenants of the user's groups. A
      user in one tenant group and one ordinary group is a tenant user.
    * A token pin only narrows: it intersects with the user's own tenants, so a
      token pinned to a tenant its owner does not belong to sees nothing.
    """
    from app.core.permissions import is_effective_superadmin

    base: frozenset[uuid.UUID] | None = None
    if not is_effective_superadmin(user):
        ids = {g.tenant_id for g in getattr(user, "groups", ()) if g.tenant_id is not None}
        if ids:
            base = frozenset(ids)
    pin = getattr(user, "_api_token_tenant_id", None)
    if pin is None:
        return base
    if base is None:
        return frozenset({pin})
    return frozenset({pin}) & base


def is_tenant_user(user: Any) -> bool:
    return tenant_scope_for(user) is not None


def session_scope(session: Any) -> frozenset[uuid.UUID] | None:
    info = getattr(session, "info", None)
    return None if info is None else info.get(SCOPE_KEY)


def set_session_scope(session: Any, scope: frozenset[uuid.UUID] | None) -> None:
    if scope is None:
        session.info.pop(SCOPE_KEY, None)
    else:
        session.info[SCOPE_KEY] = scope


# ── Read filter ─────────────────────────────────────────────────────────────


def _tables() -> dict[str, Any]:
    from app.models.ipam import IPAddress, IPSpace, Subnet

    return {"space": IPSpace.__table__, "subnet": Subnet.__table__, "address": IPAddress.__table__}


def _ids_select(kind: str, scope: Iterable[uuid.UUID]) -> Any:
    """``SELECT id`` of every row of ``kind`` inside ``scope`` (Core tables, so
    the subquery is never re-filtered)."""
    t = _tables()
    ids = sorted(scope, key=str)
    spaces = select(t["space"].c.id).where(t["space"].c.tenant_id.in_(ids))
    if kind == "space":
        return spaces
    subnets = select(t["subnet"].c.id).where(t["subnet"].c.space_id.in_(spaces))
    if kind == "subnet":
        return subnets
    return select(t["address"].c.id).where(t["address"].c.subnet_id.in_(subnets))


def predicate_for(table: Any, scope: Iterable[uuid.UUID]) -> Any:
    """The tenant predicate for ``table`` (a Core table, alias or ORM class's
    selectable), or ``None`` when it is not a tenant-scoped table."""
    name = getattr(table, "name", None)
    if name is None and getattr(table, "element", None) is not None:
        name = getattr(table.element, "name", None)
    link = _LINKS.get(name or "")
    if link is None:
        return None
    column, kind = link
    ids = sorted(scope, key=str)
    if kind == "tenant":
        return table.c[column].in_(ids)
    return table.c[column].in_(_ids_select(kind, ids))


def apply_tenant_filter(statement: Any, scope: frozenset[uuid.UUID]) -> Any:
    """``statement`` narrowed to ``scope`` for every tenant-scoped model it
    references anywhere (joins and subqueries included)."""
    from app.db import _filter_implicit_froms, _scan_statement

    models = tenant_models()
    referenced, selects = _scan_statement(statement, models)
    if not referenced:
        return statement
    if selects:
        try:
            statement = _filter_implicit_froms(
                statement,
                selects,
                {m.__tablename__ for m in referenced},
                predicate=lambda f: predicate_for(f, scope),
            )
        except Exception:  # pragma: no cover - defensive: fail closed
            logger.error("tenant_implicit_from_rewrite_failed", exc_info=True)
            raise
    for model in models:
        if model not in referenced:
            continue
        link = _LINKS[model.__tablename__]
        col = getattr(model, link[0])
        ids = sorted(scope, key=str)
        crit = col.in_(ids) if link[1] == "tenant" else col.in_(_ids_select(link[1], ids))
        statement = statement.options(
            with_loader_criteria(
                model,
                crit,
                include_aliases=True,
                propagate_to_loaders=False,
            )
        )
    return statement


def on_orm_execute(execute_state: Any) -> None:
    """``do_orm_execute`` hook (mounted from ``app.db``)."""
    scope = execute_state.session.info.get(SCOPE_KEY)
    if scope is None or not execute_state.is_select:
        return
    execute_state.statement = apply_tenant_filter(execute_state.statement, scope)


# ── Write guard ─────────────────────────────────────────────────────────────

# Columns that point an IPAM row at DNS / DHCP objects. Those stay install-wide
# in phase 1, so a tenant session may clear them but never set them.
_DNS_DHCP_COLUMNS = (
    "dns_group_ids",
    "dns_zone_id",
    "dns_additional_zone_ids",
    "dhcp_server_group_id",
)


def _refuse(detail: str, code: int = status.HTTP_403_FORBIDDEN) -> HTTPException:
    return HTTPException(status_code=code, detail=detail)


def on_before_flush(session: Session, _ctx: Any, _instances: Any) -> None:
    """Refuse a flush that would write outside the session's tenant scope."""
    scope = session.info.get(SCOPE_KEY)
    if scope is None:
        return
    from app.models.ipam import IPBlock, IPSpace, Subnet

    for obj in list(session.new) + list(session.dirty):
        if isinstance(obj, IPSpace):
            _guard_space(session, obj, scope)
        if isinstance(obj, (IPSpace, IPBlock, Subnet)):
            for col in _DNS_DHCP_COLUMNS:
                if not hasattr(obj, col):
                    continue
                value = getattr(obj, col)
                if not value:
                    continue
                if obj in session.new or get_history(obj, col).has_changes():
                    raise _refuse(
                        "A tenant user cannot assign DNS or DHCP objects to IPAM rows "
                        "(they are shared across tenants)"
                    )


def _guard_space(session: Session, space: Any, scope: frozenset[uuid.UUID]) -> None:
    if space in session.new:
        if space.tenant_id is None:
            if len(scope) != 1:
                raise _refuse(
                    "tenant_id is required: this user belongs to several tenants",
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                )
            space.tenant_id = next(iter(scope))
        elif space.tenant_id not in scope:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    elif get_history(space, "tenant_id").has_changes():
        raise _refuse("A tenant user cannot move an IP space to another tenant")
