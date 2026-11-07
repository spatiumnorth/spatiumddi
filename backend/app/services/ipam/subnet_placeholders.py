"""The network / broadcast / gateway rows a new subnet holds (#2979).

One home so every path that creates a subnet (``POST /ipam/subnets``, plan
apply, the subnet import) leaves it with the same rows, and therefore the same
counters and the same "Next available" answer: the stored gateway is never
offered as a free host.

The rule (``create_subnet``, #506): a subnet gets a ``network`` row, and for
IPv4 a ``broadcast`` one, only when its prefix is short enough to have them:
below /31 for IPv4 (RFC 3021) and below /127 for IPv6. IPv6 has no broadcast.
A multicast subnet gets none: its addresses are stream identities, not
endpoint slots. ``has_boundary_rows`` / ``boundary_rows`` are that rule and
nothing else, so the operations that rebuild a subnet at a new prefix (Split,
Merge, Resize) can share it with the create paths rather than carry a copy.
"""

from __future__ import annotations

import ipaddress
import uuid
from typing import Any

from sqlalchemy import ColumnElement, and_, exists, false, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPStaticAssignment
from app.models.ipam import IPAddress, Subnet
from app.services.ipam.address_create_rules import reclaim_available_row

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_V4_MULTICAST = ipaddress.IPv4Network("224.0.0.0/4")
_V6_MULTICAST = ipaddress.IPv6Network("ff00::/8")


def subnet_kind_for(net: IPNetwork) -> str:
    """``multicast`` for a subnet inside the IANA multicast ranges, else
    ``unicast`` (#126) — the kind ``create_subnet`` stamps."""
    if isinstance(net, ipaddress.IPv4Network):
        return "multicast" if net.subnet_of(_V4_MULTICAST) else "unicast"
    return "multicast" if net.subnet_of(_V6_MULTICAST) else "unicast"


def has_boundary_rows(net: IPNetwork, kind: str | None = "unicast") -> bool:
    """True when a subnet at this prefix (and kind) gets network / broadcast
    rows (and, on create, a gateway row)."""
    if kind == "multicast":
        return False
    return net.prefixlen < (127 if isinstance(net, ipaddress.IPv6Network) else 31)


def boundary_rows(net: IPNetwork, kind: str | None = "unicast") -> list[tuple[str, str, str]]:
    """``(address, status, description)`` for the boundary rows create_subnet seeds."""
    if not has_boundary_rows(net, kind):
        return []
    rows = [(str(net.network_address), "network", "Network address")]
    if isinstance(net, ipaddress.IPv4Network):
        rows.append((str(net.broadcast_address), "broadcast", "Broadcast address"))
    return rows


# The gateway row ``create_placeholder_rows`` writes, as one name each, so the
# row it makes and the test for "still untouched" cannot drift apart.
GATEWAY_STATUS = "reserved"
GATEWAY_DESCRIPTION = "Gateway"
GATEWAY_HOSTNAME = "gateway"


def untouched_gateway_row() -> ColumnElement[bool]:
    """SQL: this ``ip_address`` row is still the gateway placeholder its subnet's
    create added (#3042) — reserved, "Gateway" / ``gateway``, sitting on
    ``subnet.gateway`` and nothing more. Needs ``Subnet`` in the FROM. A row the
    operator renamed, gave DNS zones / an owner / tags to, or turned into a real
    allocation is not it, and neither is a hand-made row at another address.
    NULL-safe: a subnet with no stored gateway has no placeholder.

    What the system writes onto the row by itself does not disqualify it: the
    create's own PTR publish (``fqdn``, ``reverse_zone_id``), discovery's
    ``last_seen_*`` and the MAC it fills in from ARP (a MAC on a row nothing has
    seen came from an operator, so that one still counts), profiling. Anything
    an operator edit leaves behind does: ``user_modified_at`` (stamped by every
    hostname / description / status / MAC edit), the API-settable fields
    without that stamp, integration or import ownership, and a registry record
    (BACnet / OT / E911 / multicast) that would cascade away with the row."""
    from app.models.bacnet import BACnetDevice  # noqa: PLC0415
    from app.models.e911 import ERLBinding  # noqa: PLC0415
    from app.models.multicast import MulticastMembership  # noqa: PLC0415
    from app.models.ot import OTDevice  # noqa: PLC0415
    from app.services.integration_ownership import INTEGRATION_OWNERSHIP_FKS  # noqa: PLC0415

    unowned = [getattr(IPAddress, fk).is_(None) for fk in sorted(INTEGRATION_OWNERSHIP_FKS)]
    unreferenced = [
        ~exists().where(child.ip_address_id == IPAddress.id)
        for child in (BACnetDevice, OTDevice, ERLBinding, MulticastMembership)
    ]
    return func.coalesce(
        and_(
            IPAddress.status == GATEWAY_STATUS,
            IPAddress.description == GATEWAY_DESCRIPTION,
            IPAddress.hostname == GATEWAY_HOSTNAME,
            IPAddress.address == Subnet.gateway,
            IPAddress.user_modified_at.is_(None),
            IPAddress.role.is_(None),
            or_(IPAddress.mac_address.is_(None), IPAddress.last_seen_at.is_not(None)),
            IPAddress.managed_by.is_(None),
            IPAddress.owner_user_id.is_(None),
            IPAddress.owner_group_id.is_(None),
            IPAddress.reserved_until.is_(None),
            IPAddress.decom_date.is_(None),
            IPAddress.forward_zone_id.is_(None),
            IPAddress.dns_record_id.is_(None),
            IPAddress.extra_zone_ids == text("'[]'::jsonb"),
            IPAddress.dhcp_lease_id.is_(None),
            IPAddress.static_assignment_id.is_(None),
            IPAddress.auto_from_lease.is_(False),
            IPAddress.import_source.is_(None),
            IPAddress.custom_fields == text("'{}'::jsonb"),
            IPAddress.tags == text("'{}'::jsonb"),
            *unowned,
            *unreferenced,
        ),
        false(),
    )


async def create_placeholder_rows(
    db: AsyncSession,
    subnet: Subnet,
    net: IPNetwork,
    *,
    gateway: str | None,
    created_by_user_id: uuid.UUID | None,
) -> tuple[list[str], IPAddress | None]:
    """Add the network, broadcast (IPv4 only) and gateway rows and stamp
    ``subnet.gateway``. The gateway defaults to the first host, as on New
    Subnet. The caller decides whether the subnet takes them
    (``has_boundary_rows``, and ``skip_auto_addresses`` on New Subnet).
    Returns ``(addresses created, gateway row)``. Does not flush."""
    created: list[str] = []
    for addr, row_status, desc in boundary_rows(net):
        db.add(
            IPAddress(
                subnet_id=subnet.id,
                address=addr,
                status=row_status,
                description=desc,
                created_by_user_id=created_by_user_id,
            )
        )
        created.append(addr)
    gw_addr = gateway or str(net.network_address + 1)
    gw_row = IPAddress(
        subnet_id=subnet.id,
        address=gw_addr,
        status=GATEWAY_STATUS,
        description=GATEWAY_DESCRIPTION,
        hostname=GATEWAY_HOSTNAME,
        created_by_user_id=created_by_user_id,
    )
    db.add(gw_row)
    subnet.gateway = gw_addr
    created.append(gw_addr)
    return created, gw_row


# ── Moving a stored gateway (#3317) ─────────────────────────────────────────
#
# Edit Subnet and the subnet import's ``overwrite`` change an existing
# subnet's gateway. Both follow New Subnet: the gateway gets the reserved row
# ``create_placeholder_rows`` would have given it, so Next available never
# offers it, and the old untouched placeholder goes. The caller retracts the
# old row's DNS before deleting it and publishes the new row's, as it would
# for any address it writes.


async def holds_placeholder_rows(db: AsyncSession, subnet: Subnet) -> bool:
    """True when ``subnet`` carries New Subnet's placeholder rows, so its
    gateway takes a row too. False for a subnet New Subnet gives none (a /31,
    a multicast range, a Kubernetes pod / service CIDR) and for one created
    with ``skip_auto_addresses`` or stripped by ``manage_auto_addresses``,
    which has no ``network`` row: New Subnet reserves no gateway row there
    either, and accepts a gateway on the network / broadcast address."""
    net = ipaddress.ip_network(str(subnet.network), strict=False)
    if subnet.kubernetes_semantics or not has_boundary_rows(net, subnet.kind):
        return False
    return bool(
        await db.scalar(
            select(
                exists().where(
                    IPAddress.subnet_id == subnet.id,
                    IPAddress.status == "network",
                )
            )
        )
    )


async def find_untouched_gateway_row(db: AsyncSession, subnet: Subnet) -> IPAddress | None:
    """The placeholder row on the subnet's *stored* gateway, or None when the
    operator has made it theirs (``untouched_gateway_row``). Read it before the
    gateway column changes: the test compares the row with ``subnet.gateway``."""
    return await db.scalar(
        select(IPAddress)
        .join(Subnet, Subnet.id == IPAddress.subnet_id)
        .where(IPAddress.subnet_id == subnet.id, untouched_gateway_row())
    )


async def gateway_target_problem(db: AsyncSession, subnet: Subnet, gateway: str) -> str | None:
    """Why the gateway cannot move onto ``gateway``, an address other than the
    stored one, or None. The address is free: it has no row, or holds an
    ``available`` row (a free slot Next available offers, #2980, which the
    gateway takes over as Bulk allocate does, #3319), or a ``reserved`` row (an
    infrastructure reservation such as the router's own, kept as it is). Any
    other row is a host, a DHCP lease, a discovered or orphaned address, or an
    ``available`` row still linked to a DHCP reservation: the gateway would
    point at it, and when the row went the address would be offered as free.
    Edit Subnet, Resize's gateway move, the import and the mirror sync share
    this rule (#2413, #3709)."""
    row = await db.scalar(
        select(IPAddress).where(IPAddress.subnet_id == subnet.id, IPAddress.address == gateway)
    )
    if row is None or row.status == GATEWAY_STATUS:
        return None
    if row.status == "available" and row.static_assignment_id is None:
        linked = await db.scalar(
            select(func.count())
            .select_from(DHCPStaticAssignment)
            .where(DHCPStaticAssignment.ip_address_id == row.id)
        )
        if not linked:
            return None
    holder = f'"{row.hostname}" ({row.status})' if row.hostname else f"a {row.status} row"
    return (
        f"Gateway {gateway} is already held by {holder} in subnet {subnet.network}: "
        "free that address, or mark it reserved, first"
    )


async def add_gateway_row(
    db: AsyncSession,
    subnet: Subnet,
    gateway: str,
    *,
    created_by_user_id: uuid.UUID | None,
    user: Any = None,
) -> IPAddress | None:
    """Add the reserved gateway row at ``gateway`` (as ``create_placeholder_rows``
    does) unless a row already holds it, and flush. An ``available`` row there
    is a free slot and is taken over (``reclaim_available_row``, audited under
    ``user``) and made the gateway row. Returns the new or taken-over row, or
    None when the address was already held (``gateway_target_problem`` let it
    through as a reservation of the operator's)."""
    held = await db.scalar(
        select(IPAddress.id).where(IPAddress.subnet_id == subnet.id, IPAddress.address == gateway)
    )
    if held is not None:
        row = await reclaim_available_row(db, subnet, gateway, user)
        if row is None:
            return None
        row.status = GATEWAY_STATUS
        row.description = GATEWAY_DESCRIPTION
        row.hostname = GATEWAY_HOSTNAME
        row.created_by_user_id = created_by_user_id
        await db.flush()
        return row
    row = IPAddress(
        subnet_id=subnet.id,
        address=gateway,
        status=GATEWAY_STATUS,
        description=GATEWAY_DESCRIPTION,
        hostname=GATEWAY_HOSTNAME,
        created_by_user_id=created_by_user_id,
    )
    db.add(row)
    await db.flush()
    return row


# ── Integration mirrors (#3347) ─────────────────────────────────────────────


async def sync_mirror_gateway_row(
    db: AsyncSession, subnet: Subnet, new_gateway: str | None
) -> str | None:
    """Keep the reserved gateway row of an integration-mirrored subnet in step
    with the gateway the integration reports, so Next available never offers it.

    Call it *before* the caller assigns ``subnet.gateway = new_gateway`` (the
    untouched-row test reads the stored gateway), and once for a subnet created
    this sync, after a flush. It creates the row when the gateway has none,
    moves an untouched one when the gateway changed, and removes an untouched
    one when the gateway went away. It may add or delete a row, so the caller
    recounts every subnet it passes here (once, after the loop).

    A subnet New Subnet gives no gateway row (Kubernetes semantics, /31, /127,
    multicast) gets none, and nor does a gateway that is the network or
    broadcast address or outside the subnet. An address held by another
    (non-reserved) row is never overwritten: when the gateway moves onto it,
    the problem text is returned for the reconciler's own warning list and the
    gateway row is not created.

    An operator who deletes the placeholder gets it back on the next sync (the
    integration's gateway is authoritative, as for the Docker / OPNsense
    gateway rows); one who edits it makes it theirs, and it is then neither
    moved nor removed."""
    if subnet.kubernetes_semantics:
        return None
    net = ipaddress.ip_network(str(subnet.network), strict=False)
    if not has_boundary_rows(net, subnet.kind):
        return None

    target: str | None = None
    if new_gateway:
        try:
            gw = ipaddress.ip_address(new_gateway)
        except ValueError:
            gw = None
        if (
            gw is not None
            and gw.version == net.version
            and gw in net
            and gw != net.network_address
            and not (isinstance(net, ipaddress.IPv4Network) and gw == net.broadcast_address)
        ):
            target = str(gw)

    old = await find_untouched_gateway_row(db, subnet)
    if old is not None and target is not None and str(old.address) == target:
        return None

    # A gateway that did not move and whose address a row already holds (the
    # operator's edit of the placeholder, or a row that was there first) is
    # left as it stands, silently: nothing changed, and a warning on every
    # sync would only be noise. Only a gateway moving onto a held address is
    # reported, once, when it moves.
    stored = str(subnet.gateway) if subnet.gateway is not None else None
    problem: str | None = None
    if target is not None and target != stored:
        problem = await gateway_target_problem(db, subnet, target)
    if old is not None:
        # Same retraction every other row removal does (a PTR it published).
        from app.services.dns.record_ops import retract_address_dns  # noqa: PLC0415

        await retract_address_dns(db, [old.id])
        await db.delete(old)
        await db.flush()
    if target is not None and problem is None:
        await add_gateway_row(db, subnet, target, created_by_user_id=None)
    return problem
