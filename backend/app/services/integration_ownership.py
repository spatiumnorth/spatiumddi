"""Which integration owns an IPAM row (#1135).

Every read-only integration mirror stamps its own provenance FK on the
``IPAddress`` / ``Subnet`` / ``IPBlock`` rows it creates or claims, and must
never claim a row that another integration already owns. The FKs live here
and nowhere else.

Before #1135 each of the seven older reconcilers kept its own hand-written
``row.x_id is not None or …`` chain, and every one had fallen behind as
integrations were added after it. A mirror that misses another's FK claims
that row and stamps ``user_modified_at``, which freezes it for both
integrations and keeps it alive after both let go.

``tests/test_integration_ownership.py`` derives the FK set from the models,
so a new integration's column fails CI until it is added here. It also fails
on any hand-written chain of these columns elsewhere in ``app/``.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress

# Ownership FK → the integration's name, as block-sync targets and the
# block-move blockers report it.
INTEGRATION_OWNERSHIP: dict[str, str] = {
    "kubernetes_cluster_id": "kubernetes",
    "docker_host_id": "docker",
    "proxmox_node_id": "proxmox",
    "tailscale_tenant_id": "tailscale",
    "unifi_controller_id": "unifi",
    "cloud_endpoint_id": "cloud",
    "opnsense_router_id": "opnsense",
    "netbird_instance_id": "netbird",
    "panos_firewall_id": "paloalto",
    "fortinet_firewall_id": "fortinet",
    "meraki_org_id": "meraki",
}

INTEGRATION_OWNERSHIP_FKS: frozenset[str] = frozenset(INTEGRATION_OWNERSHIP)


def owning_integration(row: object) -> str | None:
    """The name of the integration that owns ``row``, or None if none does.

    A row should have at most one owner. If a pre-#1135 cross-claim left it
    with two, this names one of them.
    """
    for fk, name in INTEGRATION_OWNERSHIP.items():
        if getattr(row, fk) is not None:
            return name
    return None


def owned_by_other_integration(row: object, own_fk: str) -> bool:
    """True if an integration other than the one whose FK is ``own_fk`` owns
    ``row``. Another target of the SAME integration is the caller's check:
    each reconciler words that warning for its own kind of target."""
    if own_fk not in INTEGRATION_OWNERSHIP:
        raise ValueError(f"not an integration ownership FK: {own_fk!r}")
    return any(getattr(row, fk) is not None for fk in INTEGRATION_OWNERSHIP if fk != own_fk)


async def subnet_has_surviving_addresses(
    db: AsyncSession, subnet_id: uuid.UUID, own_fk: str
) -> bool:
    """Whether deleting the subnet would cascade-delete addresses that are
    not purely the caller's own (#1558).

    ``IPAddress.subnet_id`` is ON DELETE CASCADE, so deleting a mirrored
    ``Subnet`` takes every address in it with it — including operator
    allocations, rows another integration owns, and the caller's own rows
    an operator edited (``user_modified_at`` set), which the address pass
    would otherwise un-claim and keep. A mirror whose upstream network
    left the desired set must check here first and un-claim the subnet
    (clear its own FK) instead of deleting it when this returns True.
    The OPNsense and firewall-mirror reconcilers hand-rolled this check
    first; every other mirror goes through here so the predicate can't
    drift again.
    """
    if own_fk not in INTEGRATION_OWNERSHIP:
        raise ValueError(f"not an integration ownership FK: {own_fk!r}")
    survivor = or_(
        IPAddress.user_modified_at.is_not(None),
        getattr(IPAddress, own_fk).is_(None),
        *(getattr(IPAddress, fk).is_not(None) for fk in INTEGRATION_OWNERSHIP if fk != own_fk),
    )
    count = await db.scalar(
        select(func.count())
        .select_from(IPAddress)
        .where(IPAddress.subnet_id == subnet_id)
        .where(survivor)
    )
    return bool(count)


# Ownership FKs stamped on ``DNSRecord`` rows by a non-IPAM owner: the
# three integration mirrors plus the DNS pool health-check pipeline.
# IPAM's DNS drift sweep must never treat these rows as its own stale
# output (#1554).
DNS_RECORD_OWNER_FKS: tuple[str, ...] = (
    "kubernetes_cluster_id",
    "tailscale_tenant_id",
    "netbird_instance_id",
    "pool_member_id",
)

# ``DNSRecord.tags`` key marking a record as an ACME challenge TXT
# (acme-dns provider or the DNS-01 client). ACME records are not IPAM
# sync output — they have their own writers and janitor (#1554).
ACME_RECORD_TAG = "acme_challenge"


def dns_record_owned_elsewhere(record: object) -> bool:
    """True if a ``DNSRecord`` belongs to something other than IPAM DNS
    sync (#1554): an integration mirror's FK, the DNS pool pipeline, or
    the ACME challenge marker. Such rows carry no ``ip_address_id``, so
    the drift sweep's orphan query would otherwise report (and, with
    auto-delete on, delete) them as stale IPAM output."""
    if any(getattr(record, fk, None) is not None for fk in DNS_RECORD_OWNER_FKS):
        return True
    tags = getattr(record, "tags", None) or {}
    return bool(tags.get(ACME_RECORD_TAG))


__all__ = [
    "ACME_RECORD_TAG",
    "DNS_RECORD_OWNER_FKS",
    "INTEGRATION_OWNERSHIP",
    "INTEGRATION_OWNERSHIP_FKS",
    "dns_record_owned_elsewhere",
    "owned_by_other_integration",
    "owning_integration",
    "subnet_has_surviving_addresses",
]
