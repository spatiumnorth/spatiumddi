"""Collision checks for a new or edited DHCP static reservation.

One home for the rules the REST ``statics`` router enforces, so the
operation apply path (request portal + copilot, #2901 / #2902) and a
submit-time pre-check (#2903) call the same code instead of copies.
``check_static_conflicts`` raises a 4xx ``HTTPException`` (409 for a
duplicate MAC in the group or a duplicate IP in the scope, 422 for a bad or
out-of-subnet IP).
"""

from __future__ import annotations

import ipaddress
import uuid

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPScope, DHCPStaticAssignment
from app.models.ipam import Subnet


async def check_static_conflicts(
    db: AsyncSession,
    scope: DHCPScope,
    ip: str,
    mac: str,
    exclude_id: uuid.UUID | None = None,
    *,
    name_other_scope: bool = True,
) -> None:
    """Conflict: same MAC in the group (across scopes), same IP in the scope,
    a malformed IP, or an IP outside the scope's subnet.

    ``name_other_scope=False`` keeps the id of the scope already holding the
    MAC out of the 409: the request portal's submitter holds read on THIS
    scope only, and the holding scope may be one they cannot see (#2903).
    """
    # MAC dup across every scope served by the same group
    same_mac = await db.execute(
        select(DHCPStaticAssignment)
        .join(DHCPScope, DHCPStaticAssignment.scope_id == DHCPScope.id)
        .where(
            DHCPScope.group_id == scope.group_id,
            DHCPStaticAssignment.mac_address == mac,
        )
    )
    for row in same_mac.scalars().all():
        if exclude_id is not None and row.id == exclude_id:
            continue
        where = f" in scope {row.scope_id}" if name_other_scope else ""
        raise HTTPException(
            status_code=409,
            detail=f"MAC {mac} already reserved in this group{where}",
        )

    try:
        ip_addr = ipaddress.ip_address(ip)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=f"Invalid IP: {e}") from e

    # The same IP twice in one scope — the partial unique index
    # ``uq_dhcp_static_scope_ip`` (scope_id, ip_address) would refuse it
    # anyway; naming it here gives the submit pre-check (#2903) and every
    # other caller one legible 409. After the parse, so a malformed IP keeps
    # its "Invalid IP" 422 instead of reaching the INET comparison.
    same_ip = await db.execute(
        select(DHCPStaticAssignment).where(
            DHCPStaticAssignment.scope_id == scope.id,
            DHCPStaticAssignment.ip_address == str(ip_addr),
        )
    )
    for row in same_ip.scalars().all():
        if exclude_id is not None and row.id == exclude_id:
            continue
        raise HTTPException(
            status_code=409,
            detail=f"IP {ip} is already reserved in this scope",
        )

    # The reservation's IP must fall inside the scope's subnet. Kea renders the
    # reservation *nested inside* that subnet's stanza
    # (``"subnet4": [{"subnet": "<cidr>", "reservations": [...]}]``) and Windows
    # keys reservations by the scope's network address, so an out-of-CIDR
    # reservation ships structurally invalid config to the backend. Catch it
    # here as a legible 422 instead of a downstream agent failure (#619).
    subnet_row = await db.get(Subnet, scope.subnet_id)
    if subnet_row is not None:
        try:
            network = ipaddress.ip_network(str(subnet_row.network), strict=False)
        except ValueError:  # pragma: no cover — a malformed subnet CIDR can't be validated against
            network = None
        if network is not None and ip_addr not in network:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"IP {ip} is outside the scope's subnet {network}. "
                    "A reservation must fall inside the subnet its scope serves."
                ),
            )

    # NOTE: a reservation whose IP lands inside a *dynamic* pool is explicitly
    # allowed. Pinning a MAC inside the range is the standard idiom on every
    # driver we ship — Kea honours it (default ``reservations-out-of-pool:
    # false`` runs the in-pool check and won't hand the address to another
    # client), FortiGate renders ``reserved-address`` independently of
    # ``ip-range``, and Windows *requires* the reservation to fall inside the
    # scope's StartRange–EndRange (which is derived from the dynamic pool). The
    # old in-pool 409 had no driver basis, its "exclude it first" workaround was
    # a no-op or actively harmful, and it looked like it broke Windows statics
    # outright (#631). Pool occupancy accounts for these reservations separately
    # (``services/dhcp/pool_occupancy.py``).
