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


__all__ = [
    "INTEGRATION_OWNERSHIP",
    "INTEGRATION_OWNERSHIP_FKS",
    "owned_by_other_integration",
    "owning_integration",
]
