"""Endpoint pulls for the phpIPAM importer (issue #4734).

Each ``fetch_*`` coroutine reads one phpIPAM controller through
:class:`~app.services.phpipam_import.client.PhpipamClient` and returns the raw
object dicts. Scalars arrive as integers on current phpIPAM (``"vlanId": 3``) and
as strings on others (``mask``, custom-field values), so the typing happens in
``mapping.py``, not here.

The per-subnet shape of the address pull is the point of :func:`fetch_addresses`:
phpIPAM has no "all addresses" endpoint and no pagination, so one request per
subnet is both the only way and the bound.
"""

from __future__ import annotations

from typing import Any

import structlog

from .client import PhpipamClient, PhpipamClientError

logger = structlog.get_logger(__name__)

# The custom-field controllers: ``GET /{controller}/custom_fields/`` answers
# ``{column_name: {"name", "type", "Comment", "Null", "Default"}}``.
CUSTOM_FIELD_CONTROLLERS: dict[str, str] = {
    "subnets": "subnets",
    "addresses": "addresses",
    "vlan": "vlan",
    "vrf": "vrf",
}


async def fetch_sections(ipam: PhpipamClient) -> list[dict[str, Any]]:
    """``/sections/``."""
    out = await ipam.get_list("/sections/")
    logger.info("phpipam_import.fetch.sections", count=len(out))
    return out


async def fetch_subnets(ipam: PhpipamClient, section_id: int) -> list[dict[str, Any]]:
    """``/sections/{id}/subnets/`` — every subnet and folder of one section."""
    return await ipam.get_list(f"/sections/{section_id}/subnets/")


async def fetch_addresses(ipam: PhpipamClient, subnet_id: int) -> list[dict[str, Any]]:
    """``/subnets/{id}/addresses/`` — the addresses of one subnet."""
    return await ipam.get_list(f"/subnets/{subnet_id}/addresses/")


async def fetch_vlans(ipam: PhpipamClient) -> list[dict[str, Any]]:
    """``/vlan/``."""
    return await ipam.get_list("/vlan/")


async def fetch_l2_domains(ipam: PhpipamClient) -> list[dict[str, Any]]:
    """``/l2domains/`` — VLAN domains. Absent on older phpIPAM (-> ``[]``)."""
    try:
        return await ipam.get_list("/l2domains/")
    except PhpipamClientError:
        return []


async def fetch_vrfs(ipam: PhpipamClient) -> list[dict[str, Any]]:
    """``/vrf/``."""
    return await ipam.get_list("/vrf/")


async def fetch_tags(ipam: PhpipamClient) -> list[dict[str, Any]]:
    """``/tools/tags/`` — the IP address states (Offline / Used / Reserved / DHCP + custom).

    Best effort: an old phpIPAM without the endpoint falls back to the default
    state ids in ``mapping``.
    """
    try:
        return await ipam.get_list("/tools/tags/")
    except PhpipamClientError:
        return []


async def fetch_custom_field_defs(
    ipam: PhpipamClient, controller: str
) -> dict[str, dict[str, Any]]:
    """``{column: definition}`` of one controller's custom fields (``{}`` if none)."""
    data = await ipam.get_data(f"/{controller}/custom_fields/")
    if not isinstance(data, dict):
        return {}
    return {str(k): v for k, v in data.items() if isinstance(v, dict)}
