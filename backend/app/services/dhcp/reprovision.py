"""Re-provision a dynamic DHCP lease onto a static address (#1287).

A device that took a dynamic lease (first contact, factory hostname) is moved
to a permanent address in the scope's static range: a reservation for its MAC
at the new address, A + PTR under the new name, and the old lease, its IPAM
mirror and its DDNS records gone.

Two steps, both re-validated against live state:

* :func:`preview_reprovision` picks the target and reports what would change,
  without writing anything.
* :func:`commit_reprovision` creates the reservation: an IPAM row at the
  target (``status="static_dhcp"`` with the MAC) through
  ``sync_static_for_ipam_row`` (#1628), the same path an IPAM-side
  reservation takes — reservation, driver push, agent wake, IPAM back-link,
  A + PTR, audit.

What happens to the old lease depends on whether the device still holds it:

* **Live lease** — left alone. The device keeps using the address until it
  moves, so the lease, its IPAM mirror and its DNS records stay true until
  then, and Kea keeps the address from being handed to anyone else. With a
  reservation for the MAC elsewhere, Kea NAKs the next RENEW / REBIND; the
  device rediscovers, takes the reserved address, Kea drops the old lease,
  and the ordinary lease-event path removes the mirror and its DDNS records.
  Deleting the lease up front would be worse: Kea answers a RENEW for an
  address it holds no lease for with silence, not a NAK, so the device would
  keep the address until the lease ran out while Kea could hand it to
  another client.
* **Lease no longer live** (expired, released, the device is gone) — removed
  now: every copy in the scope's group (``purge_lease``: DDNS revoke, mirror,
  ``removed`` history, row) and a ``lease4_del`` op for each Kea server, so a
  later lease snapshot cannot bring it back. This commit lands before the
  reservation's, so a kept factory name never has its delete and create in
  one transaction (#1489).

The static range is the scope's ``reserved`` pools (held for static
assignments, never rendered by Kea). A scope without one falls back to the
subnet minus its dynamic and excluded pools. A target inside a dynamic pool is
refused: the point is to leave it.

Scope of this first cut, as agreed on #1287: DHCPv4 on Kea. A group with a
Windows DHCP (or any agentless) server is refused with a 422 — Windows wants
its reservations inside the scope range (#631), which needs its own handling.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dns_names import sanitize_hostname, validate_hostname
from app.models.auth import User
from app.models.dhcp import (
    DHCPConfigOp,
    DHCPLease,
    DHCPPool,
    DHCPScope,
    DHCPServer,
    DHCPStaticAssignment,
)
from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import IPAddress, Subnet

logger = structlog.get_logger(__name__)

# The agent op the Kea DHCP agent turns into ``lease4-del``.
LEASE4_DEL_OP = "lease4_del"

# Linear scan cap for the fallback picker, the same bound
# ``_pick_next_available_ip`` uses for IPv4.
_MAX_SCAN = 65536


class ReprovisionError(Exception):
    """A refusal with the HTTP status the REST layer should answer with."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass
class ReprovisionPlan:
    """What a re-provision would do. ``as_dict()`` is the REST / MCP shape."""

    lease_id: str
    scope_id: str
    subnet: str
    mac_address: str
    old_ip: str
    old_hostname: str
    target_ip: str
    target_source: str  # requested | reserved_pool | outside_dynamic_pools
    target_reason: str
    hostname: str
    fqdn: str | None
    dns_create: list[str] = field(default_factory=list)
    dns_remove: list[str] = field(default_factory=list)
    ipam_remove: list[str] = field(default_factory=list)
    ipam_create: str = ""
    old_lease: str = ""  # kept_until_moved | removed_now
    servers: list[str] = field(default_factory=list)
    expected_move: str = ""
    t1_at: datetime | None = None
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["t1_at"] = self.t1_at.isoformat() if self.t1_at else None
        return out


# ── helpers ─────────────────────────────────────────────────────────────────


def _ranges(pools: list[DHCPPool], kind: str) -> list[tuple[int, int, DHCPPool]]:
    out: list[tuple[int, int, DHCPPool]] = []
    for p in pools:
        if p.pool_type != kind:
            continue
        try:
            s = int(ipaddress.ip_address(str(p.start_ip)))
            e = int(ipaddress.ip_address(str(p.end_ip)))
        except ValueError:
            continue
        out.append((min(s, e), max(s, e), p))
    return sorted(out, key=lambda r: r[0])


def _in_any(ip_int: int, ranges: list[tuple[int, int, DHCPPool]]) -> DHCPPool | None:
    for s, e, p in ranges:
        if s <= ip_int <= e:
            return p
    return None


async def _taken_addresses(db: AsyncSession, scope: DHCPScope, subnet: Subnet) -> set[str]:
    """Every address something already holds in this subnet.

    An IPAM row of any status (reservations and lease mirrors each have one),
    plus reservations and live leases directly — a lease the mirror has not
    caught up with yet must not be handed to someone else.
    """
    taken: set[str] = set()
    rows = await db.execute(select(IPAddress.address).where(IPAddress.subnet_id == subnet.id))
    taken.update(str(r[0]).split("/")[0] for r in rows)
    rows = await db.execute(
        select(DHCPStaticAssignment.ip_address).where(DHCPStaticAssignment.scope_id == scope.id)
    )
    taken.update(str(r[0]).split("/")[0] for r in rows)
    rows = await db.execute(
        select(DHCPLease.ip_address).where(
            DHCPLease.scope_id == scope.id, DHCPLease.state == "active"
        )
    )
    taken.update(str(r[0]).split("/")[0] for r in rows)
    return taken


def _usable(net: ipaddress.IPv4Network, ip: ipaddress.IPv4Address) -> bool:
    if net.prefixlen >= 31:
        return ip in net
    return ip in net and ip not in (net.network_address, net.broadcast_address)


async def _pick_target(
    pools: list[DHCPPool],
    net: ipaddress.IPv4Network,
    taken: set[str],
) -> tuple[ipaddress.IPv4Address, str, str]:
    """First free address in the scope's reserved pools, else outside every pool."""
    dynamic = _ranges(pools, "dynamic")
    excluded = _ranges(pools, "excluded")
    for s, e, pool in _ranges(pools, "reserved"):
        for i in range(s, min(e, s + _MAX_SCAN) + 1):
            ip = ipaddress.IPv4Address(i)
            if not _usable(net, ip) or str(ip) in taken:
                continue
            if _in_any(i, dynamic) or _in_any(i, excluded):
                continue
            label = pool.name or f"{pool.start_ip}-{pool.end_ip}"
            return ip, "reserved_pool", f"first free address in reserved pool {label}"
    for n, ip in enumerate(net.hosts()):
        if n >= _MAX_SCAN:
            break
        if str(ip) in taken or _in_any(int(ip), dynamic) or _in_any(int(ip), excluded):
            continue
        return ip, "outside_dynamic_pools", "first free address outside the dynamic pools"
    raise ReprovisionError(409, f"No free address in {net} outside the dynamic pools.")


def _lease_is_live(lease: DHCPLease) -> bool:
    """Whether the device may still be using the lease's address."""
    if lease.state != "active":
        return False
    end = lease.ends_at or lease.expires_at
    return end is None or end > datetime.now(UTC)


async def _group_servers(db: AsyncSession, scope: DHCPScope) -> list[DHCPServer]:
    res = await db.execute(
        select(DHCPServer)
        .where(DHCPServer.server_group_id == scope.group_id)
        .order_by(DHCPServer.name)
    )
    return list(res.scalars().all())


async def _lease_mirror(db: AsyncSession, subnet: Subnet, ip: str) -> IPAddress | None:
    return (
        await db.execute(
            select(IPAddress).where(
                IPAddress.subnet_id == subnet.id,
                IPAddress.address == ip,
                IPAddress.auto_from_lease.is_(True),
            )
        )
    ).scalar_one_or_none()


def _record_text(rec: DNSRecord, zone_name: str) -> str:
    name = zone_name if rec.name in ("@", "") else f"{rec.name}.{zone_name}"
    return f"{rec.record_type} {name.rstrip('.')} -> {rec.value}"


# ── preview ─────────────────────────────────────────────────────────────────


async def preview_reprovision(
    db: AsyncSession,
    lease_id: uuid.UUID,
    *,
    target_ip: str | None = None,
    hostname: str | None = None,
) -> ReprovisionPlan:
    """Work out a re-provision without writing anything.

    ``target_ip`` overrides the pick; ``hostname`` overrides the lease's
    (sanitized) client hostname. Raises :class:`ReprovisionError`.
    """
    from app.api.v1.ipam.router import (  # noqa: PLC0415 — avoid an import cycle
        _resolve_effective_zone,
        _resolve_reverse_zone,
    )
    from app.services.dhcp.static_ipam import (  # noqa: PLC0415
        _static_mac_clash,
        candidate_scopes_for_ipam_row,
    )

    lease = await db.get(DHCPLease, lease_id)
    if lease is None:
        raise ReprovisionError(404, "Lease not found")
    old_ip = str(lease.ip_address).split("/")[0]
    try:
        old_addr = ipaddress.ip_address(old_ip)
    except ValueError as exc:
        raise ReprovisionError(422, f"Lease address {old_ip!r} is not an IP address") from exc
    if old_addr.version != 4:
        raise ReprovisionError(422, "Only DHCPv4 leases can be re-provisioned for now.")
    if not lease.mac_address:
        raise ReprovisionError(422, "The lease has no MAC address to reserve.")
    mac = str(lease.mac_address).lower()

    if lease.scope_id is None:
        raise ReprovisionError(422, "The lease is not linked to a scope.")
    scope = await db.get(DHCPScope, lease.scope_id)
    if scope is None:
        raise ReprovisionError(422, "The lease's scope no longer exists.")
    subnet = await db.get(Subnet, scope.subnet_id)
    if subnet is None:
        raise ReprovisionError(422, "The scope has no subnet.")
    net = ipaddress.ip_network(str(subnet.network), strict=False)
    if not isinstance(net, ipaddress.IPv4Network):
        raise ReprovisionError(422, "Only DHCPv4 scopes are supported for now.")

    servers = await _group_servers(db, scope)
    if not servers:
        raise ReprovisionError(422, "The scope's server group has no DHCP servers.")
    other = sorted({s.driver for s in servers if s.driver != "kea"})
    if "windows_dhcp" in other:
        raise ReprovisionError(
            422,
            "Re-provisioning is not available for Windows DHCP yet: its reservations "
            "have to sit inside the scope range (#631).",
        )
    if other:
        raise ReprovisionError(
            422, f"Re-provisioning needs Kea servers; this group also has {', '.join(other)}."
        )

    # The create step goes through sync_static_for_ipam_row, which refuses to
    # guess between several scopes on one subnet. Refuse that here, before
    # anything is cleaned up.
    probe = IPAddress(subnet_id=subnet.id, address=old_ip)
    if len(await candidate_scopes_for_ipam_row(db, probe)) != 1:
        raise ReprovisionError(
            422, "More than one DHCP scope serves this subnet; not guessing which one."
        )

    clash = await _static_mac_clash(db, scope, mac, exclude_id=None)
    if clash is not None:
        raise ReprovisionError(
            409,
            f"MAC {mac} already has a reservation in this group "
            f"({clash.ip_address}, scope {clash.scope_id}).",
        )

    if hostname is not None and hostname.strip():
        try:
            new_name = validate_hostname(hostname)
        except ValueError as exc:
            raise ReprovisionError(422, str(exc)) from exc
    else:
        new_name = sanitize_hostname(lease.hostname)
    if "." in new_name:
        raise ReprovisionError(
            422, "Give the new name as a single label; the zone comes from the subnet."
        )

    pools = list(
        (await db.execute(select(DHCPPool).where(DHCPPool.scope_id == scope.id))).scalars().all()
    )
    taken = await _taken_addresses(db, scope, subnet)
    if target_ip:
        try:
            target = ipaddress.ip_address(target_ip.strip())
        except ValueError as exc:
            raise ReprovisionError(422, f"{target_ip!r} is not an IP address") from exc
        if not isinstance(target, ipaddress.IPv4Address) or not _usable(net, target):
            raise ReprovisionError(422, f"{target} is not a usable host address in {net}.")
        if str(target) == old_ip:
            raise ReprovisionError(
                422, "The target is the lease's own address; pick an address outside the pool."
            )
        pool = _in_any(int(target), _ranges(pools, "dynamic"))
        if pool is not None:
            raise ReprovisionError(
                422,
                f"{target} is inside the dynamic pool {pool.name or pool.start_ip}; "
                "a re-provisioned device has to leave the pool.",
            )
        pool = _in_any(int(target), _ranges(pools, "excluded"))
        if pool is not None:
            raise ReprovisionError(
                422, f"{target} is inside the excluded range {pool.name or pool.start_ip}."
            )
        if str(target) in taken:
            raise ReprovisionError(409, f"{target} is already in use.")
        source, reason = "requested", "address given by the operator"
    else:
        target, source, reason = await _pick_target(pools, net, taken)

    plan = ReprovisionPlan(
        lease_id=str(lease.id),
        scope_id=str(scope.id),
        subnet=str(net),
        mac_address=mac,
        old_ip=old_ip,
        old_hostname=lease.hostname or "",
        target_ip=str(target),
        target_source=source,
        target_reason=reason,
        hostname=new_name,
        fqdn=None,
        servers=[s.name for s in servers],
    )

    # DNS: what the new name publishes, and what goes with the old mirror.
    mirror = await _lease_mirror(db, subnet, old_ip)
    zone_id = await _resolve_effective_zone(db, subnet)
    zone = await db.get(DNSZone, zone_id) if zone_id else None
    if new_name and zone is not None:
        zone_name = zone.name.rstrip(".")
        plan.fqdn = f"{new_name}.{zone_name}"
        clash_q = select(DNSRecord).where(
            DNSRecord.zone_id == zone.id,
            func.lower(DNSRecord.name) == new_name,
            DNSRecord.record_type.in_(("A", "AAAA", "CNAME")),
        )
        for rec in (await db.execute(clash_q)).scalars().all():
            if mirror is not None and rec.ip_address_id == mirror.id:
                continue  # the lease's own record, removed by the cleanup
            raise ReprovisionError(
                409, f"{plan.fqdn} already exists ({rec.record_type} {rec.value})."
            )
        plan.dns_create.append(f"A {plan.fqdn} -> {target}")
        rev = await _resolve_reverse_zone(db, subnet, target)
        if rev is not None:
            plan.dns_create.append(f"PTR {target.reverse_pointer} -> {plan.fqdn}")
    elif new_name:
        plan.warnings.append("The subnet has no forward DNS zone; no records will be created.")
    else:
        plan.warnings.append("No hostname; the reservation gets no name and no DNS records.")

    if mirror is not None:
        plan.ipam_remove.append(f"{old_ip} (lease mirror)")
        recs = (
            await db.execute(select(DNSRecord).where(DNSRecord.ip_address_id == mirror.id))
        ).scalars()
        for rec in recs:
            z = await db.get(DNSZone, rec.zone_id)
            plan.dns_remove.append(_record_text(rec, z.name if z else ""))
    plan.ipam_create = f"{target} (static_dhcp, {mac})"

    if _lease_is_live(lease):
        plan.old_lease = "kept_until_moved"
    else:
        plan.old_lease = "removed_now"
        plan.warnings.append(
            f"The lease is no longer live ({lease.state}); it is removed now, "
            "and the device takes the reserved address when it comes back."
        )
    if lease.starts_at and lease.ends_at and lease.ends_at > lease.starts_at:
        plan.t1_at = lease.starts_at + (lease.ends_at - lease.starts_at) / 2
        when = f"its next renewal (around {plan.t1_at:%Y-%m-%d %H:%M} UTC)"
    else:
        when = "its next renewal"
    if plan.old_lease == "kept_until_moved":
        plan.expected_move = (
            f"The device moves at {when}, when Kea NAKs the old address, or right away if "
            "you reboot it. The old lease, its IPAM row and its DNS records stay until then."
        )
    else:
        plan.expected_move = "The device takes the reserved address at its next DISCOVER."
    return plan


# ── commit ──────────────────────────────────────────────────────────────────


async def commit_reprovision(
    db: AsyncSession,
    user: User,
    lease_id: uuid.UUID,
    *,
    target_ip: str,
    hostname: str | None = None,
) -> dict[str, Any]:
    """Apply a re-provision to ``target_ip`` (from the preview).

    One commit for the reservation, plus one before it for the cleanup when
    the lease is no longer live (see the module docstring).
    """
    from app.api.v1.dhcp._audit import write_audit  # noqa: PLC0415
    from app.core.agent_wake import collect_wake, dhcp_server_channel  # noqa: PLC0415
    from app.services.dhcp.lease_cleanup import purge_lease  # noqa: PLC0415
    from app.services.dhcp.static_ipam import sync_static_for_ipam_row  # noqa: PLC0415

    if not target_ip:
        raise ReprovisionError(422, "target_ip is required; take it from the preview.")
    plan = await preview_reprovision(db, lease_id, target_ip=target_ip, hostname=hostname)
    scope = await db.get(DHCPScope, uuid.UUID(plan.scope_id))
    assert scope is not None  # validated by the preview
    servers = await _group_servers(db, scope)
    server_ids = [s.id for s in servers]

    copies_removed = 0
    if plan.old_lease == "removed_now":
        # The device is not using the address: every copy of the lease in the
        # group (an HA partner holds one too), its mirror and DDNS, and the
        # lease on each Kea server. Committed on its own (#1489).
        copies = (
            (
                await db.execute(
                    select(DHCPLease).where(
                        DHCPLease.server_id.in_(server_ids),
                        func.host(DHCPLease.ip_address) == plan.old_ip,
                    )
                )
            )
            .scalars()
            .all()
        )
        mirror_removed = False
        for copy in copies:
            mirror_removed |= await purge_lease(db, copy, spare_if_peer_holds=False)
        copies_removed = len(copies)
        for srv in servers:
            db.add(
                DHCPConfigOp(
                    server_id=srv.id,
                    op_type=LEASE4_DEL_OP,
                    payload={"ip_address": plan.old_ip, "mac_address": plan.mac_address},
                    status="pending",
                )
            )
            collect_wake(dhcp_server_channel(srv.id))
        write_audit(
            db,
            user=user,
            action="reprovision_cleanup",
            resource_type="dhcp_lease",
            resource_id=plan.lease_id,
            resource_display=f"{plan.mac_address} {plan.old_ip}",
            new_value={
                "old_ip": plan.old_ip,
                "lease_copies_removed": copies_removed,
                "mirror_removed": mirror_removed,
                "dns_removed": plan.dns_remove,
                "lease4_del_servers": plan.servers,
            },
        )
        await db.commit()

    # 2. Create — the reservation, through the IPAM-row path (#1628).
    row = IPAddress(
        subnet_id=scope.subnet_id,
        address=plan.target_ip,
        status="static_dhcp",
        mac_address=plan.mac_address,
        hostname=plan.hostname or None,
        description=f"Re-provisioned from {plan.old_ip}",
        created_by_user_id=user.id,
    )
    db.add(row)
    await db.flush()
    result = await sync_static_for_ipam_row(db, row, user=user)
    if result.static is None or result.action != "create":
        await db.rollback()
        raise ReprovisionError(
            409,
            "The reservation could not be created: "
            f"{result.warning or 'unknown reason'}."
            + (" The expired lease was already removed." if copies_removed else ""),
        )
    write_audit(
        db,
        user=user,
        action="reprovision",
        resource_type="dhcp_lease",
        resource_id=plan.lease_id,
        resource_display=f"{plan.mac_address} {plan.old_ip} -> {plan.target_ip}",
        new_value={
            "old_ip": plan.old_ip,
            "target_ip": plan.target_ip,
            "hostname": plan.hostname,
            "static_assignment_id": str(result.static.id),
            "ip_address_id": str(row.id),
            "dns_created": plan.dns_create,
            "old_lease": plan.old_lease,
            "lease_copies_removed": copies_removed,
        },
    )
    await db.commit()
    logger.info(
        "dhcp_lease_reprovisioned",
        old_ip=plan.old_ip,
        target_ip=plan.target_ip,
        mac=plan.mac_address,
    )
    out = plan.as_dict()
    out["static_assignment_id"] = str(result.static.id)
    out["ip_address_id"] = str(row.id)
    return out


__all__ = [
    "LEASE4_DEL_OP",
    "ReprovisionError",
    "ReprovisionPlan",
    "commit_reprovision",
    "preview_reprovision",
]
