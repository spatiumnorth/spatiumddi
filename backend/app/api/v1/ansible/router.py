"""Ansible dynamic-inventory endpoint (#67).

``GET /api/v1/ansible/inventory`` returns a standard Ansible dynamic
inventory JSON document built from IPAM data — a drop-in replacement for
a static inventory file or an inventory script. Hosts are grouped by IP
space, IP block, subnet, every tag, and every custom-field value, and
each host's metadata is exposed under ``_meta.hostvars`` so Ansible
needs only the single ``--list`` call (no per-host round-trips).

Read-only and gated on ``read``/``ip_address`` — point Ansible at it with
an API token scoped to read. Non-negotiables:
* #13 (MCP): no dedicated MCP tool — this is a machine-format *export* of
  data the copilot already reads via ``find_ip`` / ``find_subnet``; adding
  a ``get_ansible_inventory`` tool would duplicate that surface. Explicit
  decision: skip.
* #14 (feature module): not a togglable module — it's a single read-only
  projection endpoint gated by the existing IPAM read permission, not a
  new top-level resource family / sidebar section / tool cluster.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

import structlog
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from app.api.deps import DB
from app.core.permissions import require_permission
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.ipam.host_name import current_fqdn

logger = structlog.get_logger(__name__)

router = APIRouter()

# The Ansible ``--list`` contract requires the *complete* inventory in one
# response, so this endpoint deliberately loads every address (capping would
# silently drop hosts from automation — far worse than the latency). This is
# the soft size past which we log a heads-up so an operator on a very large
# install has a breadcrumb if the call gets slow / memory-heavy.
_LARGE_INVENTORY_WARN = 50_000

# Roles that are placeholder rows (the network / broadcast addresses IPAM
# auto-creates), not manageable hosts — never emit them as Ansible hosts.
_NON_HOST_ROLES = frozenset({"network", "broadcast"})

_INVALID_GROUP_CHARS = re.compile(r"[^A-Za-z0-9_]+")


def _group(*parts: str) -> str:
    """Sanitise a group name to Ansible's ``[A-Za-z0-9_]`` grammar."""
    raw = "_".join(p for p in parts if p)
    cleaned = _INVALID_GROUP_CHARS.sub("_", raw).strip("_")
    return cleaned or "ungrouped"


@router.get(
    "/inventory",
    summary="Ansible dynamic inventory (JSON)",
    dependencies=[Depends(require_permission("read", "ip_address"))],
    response_model=None,
)
async def ansible_inventory(
    db: DB,
    host: str | None = Query(
        default=None,
        description="Ansible ``--host`` compatibility: return just this host's vars.",
    ),
    status: str | None = Query(
        default=None,
        description="Optional: only include addresses with this lifecycle status.",
    ),
) -> dict[str, Any]:
    """Return the full ``--list`` inventory (with ``_meta.hostvars``), or a
    single host's vars when ``?host=`` is supplied."""
    addresses = (await db.execute(select(IPAddress))).scalars().all()
    if len(addresses) >= _LARGE_INVENTORY_WARN:
        logger.warning(
            "ansible.inventory.large",
            address_count=len(addresses),
            threshold=_LARGE_INVENTORY_WARN,
        )
    subnets = {s.id: s for s in (await db.execute(select(Subnet))).scalars().all()}
    blocks = {b.id: b for b in (await db.execute(select(IPBlock))).scalars().all()}
    spaces = {sp.id: sp for sp in (await db.execute(select(IPSpace))).scalars().all()}

    groups: dict[str, dict[str, list[str]]] = defaultdict(lambda: {"hosts": []})
    hostvars: dict[str, dict[str, Any]] = {}
    all_hosts: list[str] = []
    seen: dict[str, Any] = {}

    for ip in addresses:
        if (ip.role or "") in _NON_HOST_ROLES:
            continue
        if status is not None and (ip.status or "") != status:
            continue

        addr = str(ip.address)
        name = ip.hostname or addr
        # Inventory hostnames must be unique — fall back to the (unique) IP
        # when a hostname is shared by more than one address.
        if name in seen and seen[name] != ip.id:
            name = addr
        seen[name] = ip.id

        subnet = subnets.get(ip.subnet_id)
        block = blocks.get(subnet.block_id) if subnet and subnet.block_id else None
        space_id = (subnet.space_id if subnet else None) or (block.space_id if block else None)
        space = spaces.get(space_id) if space_id else None
        # IPAddress.tags is a JSONB dict ({key: value}), not a list — group
        # by key+value (like custom fields) so distinct values don't collide
        # into one group and values aren't dropped.
        tags = dict(ip.tags or {})
        custom = dict(ip.custom_fields or {})

        hostvars[name] = {
            "ansible_host": addr,
            "spatium_address": addr,
            "spatium_status": ip.status,
            "spatium_role": ip.role,
            "spatium_mac": ip.mac_address,
            "spatium_hostname": ip.hostname,
            "spatium_fqdn": current_fqdn(ip.hostname, ip.fqdn),
            "spatium_description": ip.description,
            "spatium_subnet": str(subnet.network) if subnet else None,
            "spatium_subnet_name": subnet.name if subnet else None,
            "spatium_block": block.name if block else None,
            "spatium_space": space.name if space else None,
            "spatium_tags": tags,
            "spatium_custom_fields": custom,
        }

        all_hosts.append(name)
        if space:
            groups[_group("space", space.name)]["hosts"].append(name)
        if block:
            groups[_group("block", block.name)]["hosts"].append(name)
        if subnet:
            groups[_group("subnet", subnet.name or str(subnet.network))]["hosts"].append(name)
        for key, value in tags.items():
            groups[_group("tag", str(key), str(value))]["hosts"].append(name)
        for field, value in custom.items():
            groups[_group("cf", str(field), str(value))]["hosts"].append(name)

    # ``--host`` compatibility — Ansible may still probe individual hosts.
    if host is not None:
        return hostvars.get(host, {})

    inventory: dict[str, Any] = {
        "_meta": {"hostvars": hostvars},
        "all": {"hosts": all_hosts},
    }
    inventory.update(groups)
    return inventory
