"""Resource locks — freeze an IPAM / DNS / DHCP object against edit or delete (#3361).

One enforcement module for every write path. The state lives on the row
(:class:`app.models.base.LockMixin`), so a caller that already holds the
object it is about to write checks it without a query, and a read model shows
it for free.

Two levels:

* ``delete`` — the row stays editable but cannot be deleted (or purged from
  the Trash).
* ``edit`` — implies ``delete``, and freezes the *operative* fields: address,
  hostname, record name / value / type, TTL, zone SOA and options, CIDR,
  scope and reservation ranges, and so on. Annotations — description, tags,
  custom fields, owner, colour — stay editable
  (:data:`ANNOTATION_FIELDS`). A locked object cannot be renamed, moved or
  have its type changed: those are operative fields.

An expired lock (``lock_expires_at`` in the past, #63's change window) is no
lock; :func:`active_lock` is the one place that decides.

A refusal is ``423 Locked`` with ``code: "resource_locked"`` (:func:`refuse`).
Request paths raise it. A writer that works in batches calls :func:`blocked`
instead and skips-and-reports the row: a locked row must never fail a whole
bulk edit, an importer run or a scheduled sweep.

This module imports models only, never routers, so every layer can use it.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, model_validator
from sqlalchemy import Select, and_, cast, func, or_, select
from sqlalchemy.dialects.postgresql import CIDR
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.dhcp import DHCPScope, DHCPStaticAssignment
from app.models.dns import DNSRecord, DNSServerGroup, DNSView, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

LEVEL_DELETE = "delete"
LEVEL_EDIT = "edit"
LOCK_LEVELS: tuple[str, ...] = (LEVEL_DELETE, LEVEL_EDIT)

# The audit ``action`` of a lock / unlock, and the alert rule's trigger (#3361).
AUDIT_LOCK = "lock"
AUDIT_UNLOCK = "unlock"

# How many locked descendants a refusal names.
DESCENDANT_LIMIT = 5

# Fields an edit lock leaves editable: descriptive metadata that changes no
# behaviour. Everything else an update can set is operative and frozen.
ANNOTATION_FIELDS: frozenset[str] = frozenset(
    {
        "description",
        "tags",
        "custom_fields",
        "color",
        "owner_user_id",
        "owner_group_id",
        "customer_id",
        "site_id",
        "decom_date",
        "do_not_probe",
        "do_not_probe_reason",
        "show_free_ranges",
        # Request-shape fields that are not row attributes.
        "force",
    }
)


class LockState(BaseModel):
    """The lock fields every read model of a lockable type carries (#3361).

    Mix into a response model (``class SubnetResponse(LockState)``). An expired
    lock reads as unlocked here, as :func:`active_lock` treats it, so a client
    never has to compare ``lock_expires_at`` with its own clock.
    """

    lock_level: str | None = None
    locked_by: str | None = None
    locked_at: datetime | None = None
    lock_reason: str | None = None
    lock_expires_at: datetime | None = None

    @model_validator(mode="after")
    def _expired_lock_is_no_lock(self) -> LockState:
        if self.lock_expires_at is not None and self.lock_expires_at <= datetime.now(UTC):
            self.lock_level = None
            self.locked_by = None
            self.locked_at = None
            self.lock_reason = None
            self.lock_expires_at = None
        return self


@dataclass(frozen=True)
class LockSpec:
    """A lockable resource type: its ORM class and the RBAC type its ``lock``
    grant is checked against (a view is locked with ``lock`` on ``dns_group``)."""

    model: type
    permission_type: str


SPECS: dict[str, LockSpec] = {
    "ip_space": LockSpec(IPSpace, "ip_space"),
    "ip_block": LockSpec(IPBlock, "ip_block"),
    "subnet": LockSpec(Subnet, "subnet"),
    "ip_address": LockSpec(IPAddress, "ip_address"),
    "dns_group": LockSpec(DNSServerGroup, "dns_group"),
    "dns_view": LockSpec(DNSView, "dns_group"),
    "dns_zone": LockSpec(DNSZone, "dns_zone"),
    "dns_record": LockSpec(DNSRecord, "dns_record"),
    "dhcp_scope": LockSpec(DHCPScope, "dhcp_scope"),
    "dhcp_static": LockSpec(DHCPStaticAssignment, "dhcp_static"),
}

LOCKABLE_TYPES: tuple[str, ...] = tuple(SPECS)


def display(resource_type: str, obj: Any) -> str:
    """A human label for ``obj`` in refusals and audit rows."""
    if resource_type in ("ip_space", "dns_group", "dns_view", "dhcp_scope"):
        return str(getattr(obj, "name", "") or obj.id)
    if resource_type in ("ip_block", "subnet"):
        name = getattr(obj, "name", "") or ""
        return f"{obj.network} ({name})" if name else str(obj.network)
    if resource_type == "ip_address":
        return str(obj.address)
    if resource_type == "dns_zone":
        return str(obj.name)
    if resource_type == "dns_record":
        return f"{obj.name} {obj.record_type} {obj.value}"[:200]
    if resource_type == "dhcp_static":
        return f"{obj.ip_address} ({obj.mac_address or obj.client_id or obj.duid or ''})".strip()
    return str(getattr(obj, "id", ""))


# ── Lock state ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class LockInfo:
    level: str
    locked_by: str | None
    locked_at: datetime | None
    reason: str | None
    expires_at: datetime | None


def active_lock(obj: Any, *, now: datetime | None = None) -> LockInfo | None:
    """The lock on ``obj`` in force right now, or None.

    A lock whose ``lock_expires_at`` has passed is not in force; the row keeps
    the stale columns until the next lock or unlock overwrites them.
    """
    level = getattr(obj, "lock_level", None)
    if level is None:
        return None
    expires = getattr(obj, "lock_expires_at", None)
    if expires is not None and expires <= (now or datetime.now(UTC)):
        return None
    return LockInfo(
        level=level,
        locked_by=getattr(obj, "locked_by", None),
        locked_at=getattr(obj, "locked_at", None),
        reason=getattr(obj, "lock_reason", None),
        expires_at=expires,
    )


def active_lock_where(model: type) -> Any:
    """SQL twin of :func:`active_lock`: the rows of ``model`` locked right now."""
    return and_(
        model.lock_level.is_not(None),  # type: ignore[attr-defined]
        or_(
            model.lock_expires_at.is_(None),  # type: ignore[attr-defined]
            model.lock_expires_at > func.now(),  # type: ignore[attr-defined]
        ),
    )


def lock_detail(resource_type: str, obj: Any, info: LockInfo, verb: str) -> dict[str, Any]:
    label = display(resource_type, obj)
    who = f" by {info.locked_by}" if info.locked_by else ""
    why = f": {info.reason}" if info.reason else ""
    if info.level == LEVEL_EDIT:
        state = "edit-locked"
    else:
        state = "delete-locked"
    return {
        "code": "resource_locked",
        "message": f"{resource_type} {label} is {state}{who}{why}. It cannot be {verb}.",
        "resource_type": resource_type,
        "resource_id": str(obj.id),
        "resource_display": label,
        "level": info.level,
        "locked_by": info.locked_by,
        "locked_at": info.locked_at.isoformat() if info.locked_at else None,
        "reason": info.reason,
    }


def refuse(resource_type: str, obj: Any, info: LockInfo, verb: str = "changed") -> HTTPException:
    """The 423 a locked object answers a write with."""
    return HTTPException(status_code=423, detail=lock_detail(resource_type, obj, info, verb))


def _differs(current: Any, new: Any, key: str = "") -> bool:
    """Whether an update's ``new`` value is a change from ``current``.

    Edit dialogs send every field on every save, so presence is not change.
    Values compare by their string form, which makes a ``str`` CIDR / UUID in
    the payload equal to the typed value on the row; a list or dict compares
    structurally, with empty equal to NULL; a MAC compares without its
    separators or case.
    """
    if isinstance(current, (list, dict)) or isinstance(new, (list, dict)):
        return (current or None) != (new or None)
    if current is None and new in (None, ""):
        return False
    if key in ("mac_address", "client_id", "duid") and current is not None and new is not None:
        norm = lambda v: str(v).lower().replace(":", "").replace("-", "")  # noqa: E731
        return norm(current) != norm(new)
    return str(current) != str(new)


def _null_is_noop(obj: Any, key: str, noop: frozenset[str]) -> bool:
    """A ``None`` in an update payload leaves the field alone when the handler
    says so (``noop``), or when the column cannot hold NULL."""
    if key in noop:
        return True
    table = getattr(obj, "__table__", None)
    column = table.columns.get(key) if table is not None else None
    return column is not None and not column.nullable


def operative_changes(
    obj: Any, changes: Mapping[str, Any] | None, null_is_noop: frozenset[str] = frozenset()
) -> list[str]:
    """The fields ``changes`` would change that an edit lock freezes.

    ``changes=None`` means the caller cannot enumerate them (a structural
    operation: resize, move, merge), and every operative field counts.
    """
    if changes is None:
        return ["*"]
    frozen: list[str] = []
    for key, value in changes.items():
        if key in ANNOTATION_FIELDS:
            continue
        if value is None and _null_is_noop(obj, key, null_is_noop):
            continue
        if _differs(getattr(obj, key, None), value, key):
            frozen.append(key)
    return frozen


def blocked_edit(
    resource_type: str,
    obj: Any,
    changes: Mapping[str, Any] | None = None,
    null_is_noop: frozenset[str] = frozenset(),
) -> tuple[LockInfo, list[str]] | None:
    """``(lock, frozen fields)`` when an edit of ``obj`` is refused, else None.

    Only an ``edit`` lock refuses an edit; a ``delete`` lock leaves the row
    editable.
    """
    info = active_lock(obj)
    if info is None or info.level != LEVEL_EDIT:
        return None
    frozen = operative_changes(obj, changes, null_is_noop)
    if not frozen:
        return None
    return info, frozen


def assert_editable(
    resource_type: str,
    obj: Any,
    changes: Mapping[str, Any] | None = None,
    null_is_noop: frozenset[str] = frozenset(),
) -> None:
    """Raise 423 when an edit-lock freezes a field ``changes`` would change.

    Pass the update's field dict (``body.model_dump(exclude_unset=True)``).
    Pass ``None`` from a structural operation (resize, move, split, merge,
    reparent, zone / server move), which always rewrites operative state.
    """
    hit = blocked_edit(resource_type, obj, changes, null_is_noop)
    if hit is not None:
        info, frozen = hit
        detail = lock_detail(resource_type, obj, info, "changed")
        if frozen != ["*"]:
            detail["fields"] = sorted(frozen)
            detail["message"] += f" Locked fields: {', '.join(sorted(frozen))}."
        raise HTTPException(status_code=423, detail=detail)


# What a DNS server group's edit lock freezes beyond the group row itself (#3361):
# the config the group renders into every server it holds. ``what`` in
# :func:`assert_group_content_editable` is one of these.
GROUP_CONTENT_ACLS = "ACLs"
GROUP_CONTENT_TSIG_KEYS = "TSIG keys"
GROUP_CONTENT_TRUST_ANCHORS = "trust anchors"
GROUP_CONTENT_OPTIONS = "server options"

# Annotations of the group's sub-resources, on top of :data:`ANNOTATION_FIELDS`
# (an ACL's ``description`` is already there): a TSIG key's free-text notes.
GROUP_CONTENT_ANNOTATIONS: frozenset[str] = ANNOTATION_FIELDS | {"notes"}


def assert_group_content_editable(
    group: Any,
    what: str,
    *,
    current: Any = None,
    changes: Mapping[str, Any] | None = None,
) -> None:
    """Refuse a change to a DNS server group's ``what`` (ACLs, TSIG keys, trust
    anchors, server options) while the group is edit-locked.

    These are operative: an ACL, a key or an option is rendered into the config
    of every server in the group, so freezing the group row alone would let the
    freeze be undone through them. A ``delete`` lock does not freeze them (it
    protects only the group's existence). With ``changes`` (an update's field
    dict) and ``current`` (the row it updates) only a field that actually
    differs, and is not an annotation, is refused; a create, a delete, a key
    rotation or any call without ``changes`` is always a change.
    """
    info = active_lock(group)
    if info is None or info.level != LEVEL_EDIT:
        return
    frozen: list[str] = []
    if changes is not None:
        frozen = [
            k
            for k, v in changes.items()
            if k not in GROUP_CONTENT_ANNOTATIONS and _differs(getattr(current, k, None), v, k)
        ]
        if not frozen:
            return
    detail = lock_detail("dns_group", group, info, f"changed: its {what} are frozen")
    if frozen:
        detail["fields"] = sorted(frozen)
        detail["message"] += f" Locked fields: {', '.join(sorted(frozen))}."
    raise HTTPException(status_code=423, detail=detail)


def refusal_message(exc: HTTPException) -> str:
    """The one-sentence reason of an :class:`HTTPException` this module (or any
    handler) raised, for a preview that reports instead of raising."""
    detail = exc.detail
    if isinstance(detail, dict):
        return str(detail.get("message") or detail)
    return str(detail)


def blocked_delete(resource_type: str, obj: Any) -> LockInfo | None:
    """The lock refusing a delete of ``obj`` (any level; edit implies delete)."""
    return active_lock(obj)


def assert_deletable(resource_type: str, obj: Any) -> None:
    info = blocked_delete(resource_type, obj)
    if info is not None:
        raise refuse(resource_type, obj, info, "deleted")


def assert_all_deletable(items: Iterable[tuple[str, Any]]) -> None:
    for resource_type, obj in items:
        assert_deletable(resource_type, obj)


# ── Cascades ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class LockedChild:
    resource_type: str
    id: uuid.UUID
    display: str
    level: str
    locked_by: str | None
    reason: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "resource_type": self.resource_type,
            "resource_id": str(self.id),
            "resource_display": self.display,
            "level": self.level,
            "locked_by": self.locked_by,
            "reason": self.reason,
        }


async def _locked_rows(
    db: AsyncSession,
    resource_type: str,
    stmt: Select[Any],
    limit: int,
    edit_only: bool = False,
) -> list[LockedChild]:
    model = SPECS[resource_type].model
    stmt = stmt.where(active_lock_where(model))
    if edit_only:
        stmt = stmt.where(model.lock_level == LEVEL_EDIT)  # type: ignore[attr-defined]
    rows = (await db.execute(stmt.limit(limit))).scalars().all()
    return [
        LockedChild(
            resource_type,
            r.id,
            display(resource_type, r),
            r.lock_level,
            r.locked_by,
            r.lock_reason,
        )
        for r in rows
    ]


async def locked_descendants(
    db: AsyncSession,
    resource_type: str,
    obj: Any,
    *,
    limit: int = DESCENDANT_LIMIT,
    edit_only: bool = False,
) -> list[LockedChild]:
    """Up to ``limit`` locked rows a delete of ``obj`` would remove with it.

    A parent delete is refused when any descendant is locked, whatever its
    level: an edit lock implies a delete lock. ``edit_only`` narrows it to the
    rows an operation that REWRITES the subtree (split, merge, move) would
    change, which a delete lock does not protect.
    """
    found: list[LockedChild] = []

    async def add(rtype: str, stmt: Select[Any]) -> None:
        room = limit - len(found)
        if room > 0:
            found.extend(await _locked_rows(db, rtype, stmt, room, edit_only))

    if resource_type == "ip_space":
        await add("ip_block", select(IPBlock).where(IPBlock.space_id == obj.id))
        await add("subnet", select(Subnet).where(Subnet.space_id == obj.id))
        await add(
            "ip_address",
            select(IPAddress).where(
                IPAddress.subnet_id.in_(select(Subnet.id).where(Subnet.space_id == obj.id))
            ),
        )
    elif resource_type == "ip_block":
        # Child blocks and subnets nest by CIDR inside the block's own space.
        await add(
            "ip_block",
            select(IPBlock).where(
                IPBlock.space_id == obj.space_id,
                IPBlock.id != obj.id,
                IPBlock.network.op("<<")(cast(str(obj.network), CIDR)),
            ),
        )
        await add(
            "subnet",
            select(Subnet).where(
                Subnet.space_id == obj.space_id,
                Subnet.network.op("<<=")(cast(str(obj.network), CIDR)),
            ),
        )
        await add(
            "ip_address",
            select(IPAddress).where(
                IPAddress.subnet_id.in_(
                    select(Subnet.id).where(
                        Subnet.space_id == obj.space_id,
                        Subnet.network.op("<<=")(cast(str(obj.network), CIDR)),
                    )
                )
            ),
        )
    elif resource_type == "subnet":
        await add("ip_address", select(IPAddress).where(IPAddress.subnet_id == obj.id))
        await add("dhcp_scope", select(DHCPScope).where(DHCPScope.subnet_id == obj.id))
        await add(
            "dhcp_static",
            select(DHCPStaticAssignment).where(
                DHCPStaticAssignment.scope_id.in_(
                    select(DHCPScope.id).where(DHCPScope.subnet_id == obj.id)
                )
            ),
        )
        await add(
            "dns_record",
            select(DNSRecord).where(
                DNSRecord.ip_address_id.in_(
                    select(IPAddress.id).where(IPAddress.subnet_id == obj.id)
                ),
                DNSRecord.auto_generated.is_(True),
            ),
        )
    elif resource_type == "dns_zone":
        await add("dns_record", select(DNSRecord).where(DNSRecord.zone_id == obj.id))
    elif resource_type == "dns_group":
        await add("dns_zone", select(DNSZone).where(DNSZone.group_id == obj.id))
        await add("dns_view", select(DNSView).where(DNSView.group_id == obj.id))
        await add(
            "dns_record",
            select(DNSRecord).where(
                DNSRecord.zone_id.in_(select(DNSZone.id).where(DNSZone.group_id == obj.id))
            ),
        )
    elif resource_type == "dns_view":
        await add("dns_zone", select(DNSZone).where(DNSZone.view_id == obj.id))
    elif resource_type == "dhcp_scope":
        await add(
            "dhcp_static",
            select(DHCPStaticAssignment).where(DHCPStaticAssignment.scope_id == obj.id),
        )
    elif resource_type == "ip_address":
        await add(
            "dns_record",
            select(DNSRecord).where(
                DNSRecord.ip_address_id == obj.id, DNSRecord.auto_generated.is_(True)
            ),
        )
        # The DHCP reservation an address delete removes with it.
        await add(
            "dhcp_static",
            select(DHCPStaticAssignment).where(DHCPStaticAssignment.ip_address_id == obj.id),
        )
    return found


def cascade_refusal(
    resource_type: str,
    obj: Any,
    children: list[LockedChild],
    verb: str = "deleted",
    phrase: str = "it holds locked object(s)",
) -> HTTPException:
    names = ", ".join(f"{c.resource_type} {c.display}" for c in children)
    label = display(resource_type, obj)
    return HTTPException(
        status_code=423,
        detail={
            "code": "resource_locked",
            "message": f"{resource_type} {label} cannot be {verb}: {phrase}: {names}. Unlock first.",
            "resource_type": resource_type,
            "resource_id": str(obj.id),
            "resource_display": label,
            "level": children[0].level,
            "locked_by": children[0].locked_by,
            "reason": children[0].reason,
            "locked_descendants": [c.as_dict() for c in children],
        },
    )


async def assert_tree_editable(db: AsyncSession, resource_type: str, obj: Any) -> None:
    """Refuse a structural operation (split, merge, move, resize of a tree)
    on ``obj`` when it, or anything the operation rewrites with it, is
    edit-locked."""
    assert_editable(resource_type, obj, None)
    children = await locked_descendants(db, resource_type, obj, edit_only=True)
    if children:
        raise cascade_refusal(
            resource_type, obj, children, "changed", "it holds edit-locked object(s)"
        )


async def assert_tree_deletable(db: AsyncSession, resource_type: str, obj: Any) -> None:
    """Refuse a delete of ``obj`` when it, or anything a delete would take with
    it, is locked. Names the first :data:`DESCENDANT_LIMIT` locked descendants."""
    assert_deletable(resource_type, obj)
    children = await locked_descendants(db, resource_type, obj)
    if children:
        raise cascade_refusal(resource_type, obj, children)


# ── Integration-owned rows cannot be locked ───────────────────────────────


def integration_owner(resource_type: str, obj: Any) -> str | None:
    """The mirror that owns ``obj``, or None. An integration reconciler owns
    these rows and would overwrite or delete them whatever the lock said, so
    the lock endpoint refuses (#3361 decision 4)."""
    from app.services.integration_ownership import (  # noqa: PLC0415
        INTEGRATION_OWNERSHIP,
        dns_record_owned_elsewhere,
    )

    for fk, name in INTEGRATION_OWNERSHIP.items():
        if getattr(obj, fk, None) is not None:
            return name
    if resource_type == "dns_record" and dns_record_owned_elsewhere(obj):
        return "an integration or the pool pipeline"
    if resource_type == "ip_address" and getattr(obj, "auto_from_lease", False):
        return "the DHCP server (dynamic lease mirror)"
    return None


# ── Setting and clearing ──────────────────────────────────────────────────


def _audit_row(
    user: Any, action: str, resource_type: str, obj: Any, old: dict | None, new: dict | None
) -> AuditLog:
    return AuditLog(
        user_id=user.id,
        user_display_name=user.display_name,
        auth_source=user.auth_source,
        action=action,
        resource_type=resource_type,
        resource_id=str(obj.id),
        resource_display=display(resource_type, obj),
        old_value=old,
        new_value=new,
        result="success",
    )


# Address fields whose change IPAM's DNS sync turns into a rewrite of the
# address's host / PTR records.
DNS_SYNC_FIELDS: frozenset[str] = frozenset(
    {
        "hostname",
        "dns_zone_id",
        "forward_zone_id",
        "extra_zone_ids",
        "status",
        "address",
        "fqdn",
    }
)


async def locked_sync_records(
    db: AsyncSession, ip: IPAddress, *, removing: bool, limit: int = DESCENDANT_LIMIT
) -> list[LockedChild]:
    """The DNS records IPAM's sync generated for ``ip`` that are locked against
    what the sync is about to do: an edit lock stops a rewrite, any lock stops
    a removal."""
    stmt = select(DNSRecord).where(
        DNSRecord.ip_address_id == ip.id, DNSRecord.auto_generated.is_(True)
    )
    if not removing:
        stmt = stmt.where(DNSRecord.lock_level == LEVEL_EDIT)
    return await _locked_rows(db, "dns_record", stmt, limit)


async def assert_dns_sync_unlocked(
    db: AsyncSession, ip: IPAddress, changes: Mapping[str, Any] | None
) -> None:
    """Refuse an IPAM change that the IPAM->DNS sync would carry into a locked
    DNS record (#3361 decision 2), naming the record.

    ``changes=None`` is the removal of the address (its records go with it);
    otherwise the update's field dict, of which only the fields the sync
    publishes (:data:`DNS_SYNC_FIELDS`) matter.
    """
    removing = changes is None
    if not removing:
        touched = [k for k in operative_changes(ip, changes) if k in DNS_SYNC_FIELDS]
        if not touched:
            return
    children = await locked_sync_records(db, ip, removing=removing)
    if children:
        verb = "deleted" if removing else "changed"
        raise cascade_refusal(
            "ip_address",
            ip,
            children,
            verb,
            "the DNS sync would "
            + ("remove" if removing else "rewrite")
            + " the locked DNS record(s)",
        )


# Address fields an edit carries into the DHCP reservation linked to the row.
STATIC_SYNC_FIELDS: frozenset[str] = frozenset({"hostname", "mac_address", "address", "status"})


async def assert_static_sync_unlocked(
    db: AsyncSession, ip: IPAddress, changes: Mapping[str, Any]
) -> None:
    """Refuse an IPAM edit that would rewrite an edit-locked DHCP reservation
    linked to ``ip`` (the IPAM->DHCP mirror of :func:`assert_dns_sync_unlocked`)."""
    touched = [k for k in operative_changes(ip, changes) if k in STATIC_SYNC_FIELDS]
    if not touched:
        return
    conds = [DHCPStaticAssignment.ip_address_id == ip.id]
    if ip.static_assignment_id:
        try:
            conds.append(DHCPStaticAssignment.id == uuid.UUID(str(ip.static_assignment_id)))
        except ValueError:
            pass
    children = await _locked_rows(
        db,
        "dhcp_static",
        select(DHCPStaticAssignment).where(or_(*conds)),
        DESCENDANT_LIMIT,
        edit_only=True,
    )
    if children:
        raise cascade_refusal(
            "ip_address",
            ip,
            children,
            "changed",
            "the change would rewrite the locked DHCP reservation(s)",
        )


# Reservation fields the DHCP -> IPAM mirror writes into the linked address row
# (``upsert_ipam_for_static``): the reservation is the source of truth for them.
STATIC_TO_IP_FIELDS: frozenset[str] = frozenset({"hostname", "mac_address", "ip_address"})


async def assert_ip_mirror_unlocked(
    db: AsyncSession,
    static: DHCPStaticAssignment,
    subnet_id: uuid.UUID,
    changes: Mapping[str, Any] | None,
) -> None:
    """Refuse a reservation edit or delete that the DHCP -> IPAM mirror would
    carry into an edit-locked IP address row (the reverse direction of
    :func:`assert_static_sync_unlocked`).

    The mirror rewrites the address row's hostname / MAC / address on an edit
    and releases or removes it on a delete, so an edit lock on the address
    would otherwise be bypassed from the DHCP side. ``changes=None`` is the
    delete. The row is found by the reservation's own link, by the address's
    back-link, and by the subnet + address the mirror itself keys on.
    """
    removing = changes is None
    if not removing:
        touched = [k for k in operative_changes(static, changes) if k in STATIC_TO_IP_FIELDS]
        if not touched:
            return
    conds = [
        IPAddress.static_assignment_id == str(static.id),
        and_(IPAddress.subnet_id == subnet_id, IPAddress.address == str(static.ip_address)),
    ]
    if static.ip_address_id:
        conds.append(IPAddress.id == static.ip_address_id)
    children = await _locked_rows(
        db,
        "ip_address",
        select(IPAddress).where(or_(*conds)),
        DESCENDANT_LIMIT,
        edit_only=True,
    )
    if children:
        raise cascade_refusal(
            "dhcp_static",
            static,
            children,
            "deleted" if removing else "changed",
            "the IPAM mirror of this reservation would be "
            + ("removed" if removing else "rewritten")
            + " in the edit-locked address(es)",
        )


async def sync_blocked_by_locked_records(
    db: AsyncSession, ip: IPAddress, action: str
) -> list[LockedChild]:
    """The locked DNS records IPAM's sync of ``ip`` (``action`` create / update
    / delete) would remove or rewrite, judged against the address's CURRENT
    values: an edit-locked record the address still agrees with is untouched
    by a sync and is not reported.

    The safety net under :func:`assert_dns_sync_unlocked` for every caller of
    the sync, the automatic writers (DDNS from a lease, the scheduled
    auto-sync, importers, discovery) included: they skip the address and
    report, rather than fail a batch over one locked record.
    """
    if action == "delete":
        return await locked_sync_records(db, ip, removing=True)
    stmt = select(DNSRecord).where(
        DNSRecord.ip_address_id == ip.id,
        DNSRecord.auto_generated.is_(True),
        DNSRecord.lock_level == LEVEL_EDIT,
        active_lock_where(DNSRecord),
    )
    hostname = (ip.hostname or "").strip().lower()
    out: list[LockedChild] = []
    for rec in (await db.execute(stmt)).scalars().all():
        value = str(rec.value or "").rstrip(".").lower()
        if rec.record_type == "PTR":
            drift = not hostname or value.split(".")[0] != hostname
        elif rec.record_type in ("A", "AAAA"):
            drift = (
                not hostname
                or str(rec.name).lower() != hostname
                or value != str(ip.address).lower()
            )
        else:
            drift = False
        if drift:
            out.append(
                LockedChild(
                    "dns_record",
                    rec.id,
                    display("dns_record", rec),
                    rec.lock_level or LEVEL_EDIT,
                    rec.locked_by,
                    rec.lock_reason,
                )
            )
    return out


def lock_snapshot(obj: Any) -> dict[str, Any] | None:
    info = active_lock(obj)
    if info is None:
        return None
    return {
        "level": info.level,
        "locked_by": info.locked_by,
        "locked_at": info.locked_at.isoformat() if info.locked_at else None,
        "reason": info.reason,
        "expires_at": info.expires_at.isoformat() if info.expires_at else None,
    }


def set_lock(
    db: AsyncSession,
    user: Any,
    resource_type: str,
    obj: Any,
    *,
    level: str,
    reason: str,
    expires_at: datetime | None = None,
) -> None:
    """Stamp the lock on ``obj`` and queue its audit row. Re-locking replaces
    the lock (a level change is a lock event of its own)."""
    owner = integration_owner(resource_type, obj)
    if owner is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                f"{resource_type} {display(resource_type, obj)} is owned by {owner} and "
                "cannot be locked: the integration would overwrite it."
            ),
        )
    old = lock_snapshot(obj)
    obj.lock_level = level
    obj.locked_by = user.username if hasattr(user, "username") else user.display_name
    obj.locked_at = datetime.now(UTC)
    obj.lock_reason = reason
    obj.lock_expires_at = expires_at
    db.add(_audit_row(user, AUDIT_LOCK, resource_type, obj, old, {**(lock_snapshot(obj) or {})}))


def clear_lock(
    db: AsyncSession,
    user: Any,
    resource_type: str,
    obj: Any,
    *,
    reason: str,
) -> None:
    """Remove the lock from ``obj`` and queue its audit row, carrying the
    operator's reason and who had locked it."""
    old = lock_snapshot(obj) or {
        "level": getattr(obj, "lock_level", None),
        "locked_by": getattr(obj, "locked_by", None),
    }
    obj.lock_level = None
    obj.locked_by = None
    obj.locked_at = None
    obj.lock_reason = None
    obj.lock_expires_at = None
    db.add(_audit_row(user, AUDIT_UNLOCK, resource_type, obj, old, {"reason": reason}))


async def load_lockable(db: AsyncSession, resource_type: str, resource_id: uuid.UUID) -> Any | None:
    spec = SPECS.get(resource_type)
    if spec is None:
        return None
    return await db.get(spec.model, resource_id)


# ── Skip-and-report for batch writers ─────────────────────────────────────


@dataclass(frozen=True)
class SkippedLocked:
    """One row a batch writer skipped because it is locked."""

    resource_type: str
    id: uuid.UUID
    display: str
    level: str
    locked_by: str | None
    reason: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "resource_type": self.resource_type,
            "resource_id": str(self.id),
            "resource_display": self.display,
            "level": self.level,
            "locked_by": self.locked_by,
            "reason": self.reason,
        }


def skipped(resource_type: str, obj: Any, info: LockInfo) -> SkippedLocked:
    return SkippedLocked(
        resource_type,
        obj.id,
        display(resource_type, obj),
        info.level,
        info.locked_by,
        info.reason,
    )


def skip_edit(
    resource_type: str,
    obj: Any,
    changes: Mapping[str, Any] | None = None,
    null_is_noop: frozenset[str] = frozenset(),
) -> SkippedLocked | None:
    """For a batch edit: the skip record when ``obj`` is locked against
    ``changes``, else None."""
    hit = blocked_edit(resource_type, obj, changes, null_is_noop)
    return skipped(resource_type, obj, hit[0]) if hit else None


def skip_delete(resource_type: str, obj: Any) -> SkippedLocked | None:
    """For a batch delete: the skip record when ``obj`` is locked, else None."""
    info = blocked_delete(resource_type, obj)
    return skipped(resource_type, obj, info) if info else None


async def skip_delete_tree(db: AsyncSession, resource_type: str, obj: Any) -> SkippedLocked | None:
    """As :func:`skip_delete`, also skipping when a descendant is locked."""
    first = skip_delete(resource_type, obj)
    if first is not None:
        return first
    children = await locked_descendants(db, resource_type, obj, limit=1)
    if children:
        c = children[0]
        return SkippedLocked(
            resource_type,
            obj.id,
            display(resource_type, obj),
            c.level,
            c.locked_by,
            f"holds locked {c.resource_type} {c.display}" + (f" ({c.reason})" if c.reason else ""),
        )
    return None


def withhold_locked_from_diff(diff: Any, existing: Iterable[Any]) -> list[str]:
    """Take every update an edit lock freezes, and every delete any lock
    refuses, out of an importer's ``diff`` (``to_update`` / ``to_delete`` of
    ``RecordChange`` rows carrying ``existing_id``), and return one skipped line
    per record left alone. Preview and commit share this, so the operator sees
    the locked rows before committing."""
    by_id = {str(r.id): r for r in existing}
    notes: list[str] = []

    def keep(change: Any, verb: str, level_matters: bool) -> bool:
        rec = by_id.get(str(change.existing_id)) if change.existing_id else None
        info = active_lock(rec) if rec is not None else None
        if info is None or (level_matters and info.level != LEVEL_EDIT):
            return True
        who = f" by {info.locked_by}" if info.locked_by else ""
        why = f": {info.reason}" if info.reason else ""
        notes.append(
            f"{change.name} {change.record_type} {change.value}: left alone, "
            f"{info.level}-locked{who}{why} (would have been {verb})"
        )
        return False

    diff.to_update = [c for c in diff.to_update if keep(c, "updated", True)]
    diff.to_delete = [c for c in diff.to_delete if keep(c, "deleted", False)]
    return notes


def withhold_locked_from_sheet_plan(plan: Any, issue_cls: Any) -> None:
    """The spreadsheet importer's twin of :func:`withhold_locked_from_diff`:
    drops the planned updates an edit lock freezes and the planned deletes any
    lock refuses, adding each to ``plan.skipped`` as an ``issue_cls`` row
    (``RowIssue``) naming the lock."""

    def reason(info: LockInfo, verb: str) -> str:
        who = f" by {info.locked_by}" if info.locked_by else ""
        why = f": {info.reason}" if info.reason else ""
        return f"{info.level}-locked{who}{why}; would have been {verb}"

    keep_updates = []
    for u in plan.updates:
        info = active_lock(u.record)
        if info is not None and info.level == LEVEL_EDIT:
            plan.skipped.append(
                issue_cls(
                    row=None,
                    reason=reason(info, "updated"),
                    name=u.record.name,
                    record_type=u.record.record_type,
                    value=u.record.value,
                )
            )
        else:
            keep_updates.append(u)
    plan.updates = keep_updates
    keep_deletes = []
    for rec in plan.deletes:
        info = active_lock(rec)
        if info is not None:
            plan.skipped.append(
                issue_cls(
                    row=None,
                    reason=reason(info, "deleted"),
                    name=rec.name,
                    record_type=rec.record_type,
                    value=rec.value,
                )
            )
        else:
            keep_deletes.append(rec)
    plan.deletes = keep_deletes
