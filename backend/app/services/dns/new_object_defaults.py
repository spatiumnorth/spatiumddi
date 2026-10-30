"""Platform-wide defaults for NEW DNS zones and server groups (#3087).

Settings -> DNS holds four values -- ``dns_default_ttl``,
``dns_default_zone_type``, ``dns_default_dnssec_validation`` and
``dns_recursive_by_default`` -- that used to be stored and read by nothing.
Every create path that has no value of its own for one of them asks here.

Importers and the move / pull paths carry the SOURCE's values and only fall
back to a default where the source has none.  The fallbacks are the model's
own constants, so a fresh install (whose stored defaults equal them) behaves
exactly as before.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNS_TTL_MAX, ZONE_DEFAULT_TTL, DNSServerGroup, DNSServerOptions
from app.models.settings import PlatformSettings
from app.services.dns import technitium_api_scope

logger = structlog.get_logger(__name__)

# The values each setting may hold.  The DNS router's create / options
# validators read these too, so Settings cannot store a value the object it
# seeds would refuse.  ``dnssec_validation`` is interpolated into
# ``named.conf``: a value BIND rejects stops the whole group converging.
ZONE_TYPES = frozenset({"primary", "secondary", "stub", "forward"})
DNSSEC_VALIDATION_MODES = frozenset({"auto", "yes", "no"})


@dataclass(frozen=True)
class DNSNewObjectDefaults:
    ttl: int = ZONE_DEFAULT_TTL
    zone_type: str = "primary"
    dnssec_validation: str = "auto"
    recursive: bool = True


async def load_dns_defaults(db: AsyncSession) -> DNSNewObjectDefaults:
    """The stored defaults, or the built-in constants when no settings row exists."""
    ps = await db.get(PlatformSettings, 1)
    if ps is None:
        return DNSNewObjectDefaults()
    builtin = DNSNewObjectDefaults()
    ttl = ps.dns_default_ttl
    zone_type = ps.dns_default_zone_type
    dnssec = ps.dns_default_dnssec_validation
    # Settings accepted any value while these were inert; a row stored then
    # must not reach a zone or named.conf.  Each bad value falls back alone.
    if not 0 <= ttl <= DNS_TTL_MAX:
        logger.warning("dns_default_invalid", field="dns_default_ttl", value=ttl)
        ttl = builtin.ttl
    if zone_type not in ZONE_TYPES:
        logger.warning("dns_default_invalid", field="dns_default_zone_type", value=zone_type)
        zone_type = builtin.zone_type
    if dnssec not in DNSSEC_VALIDATION_MODES:
        logger.warning("dns_default_invalid", field="dns_default_dnssec_validation", value=dnssec)
        dnssec = builtin.dnssec_validation
    return DNSNewObjectDefaults(
        ttl=ttl,
        zone_type=zone_type,
        dnssec_validation=dnssec,
        recursive=ps.dns_recursive_by_default,
    )


async def default_zone_ttl(db: AsyncSession, group_id: uuid.UUID) -> int:
    """The TTL a new zone in ``group_id`` takes when none was given.

    Settings' default, except in an experimental ``technitium_api`` group:
    that driver never writes a zone TTL and its scope gate refuses anything
    but the stock value (#1784), so the default would turn a create that
    omits the TTL into a 422 (or store a value nothing serves).
    """
    if await technitium_api_scope.group_is_technitium_api(db, group_id):
        return ZONE_DEFAULT_TTL
    return (await load_dns_defaults(db)).ttl


async def add_group_with_defaults(db: AsyncSession, group: DNSServerGroup) -> None:
    """Persist a server group nothing but the platform chose the settings for
    (agent auto-registration): recursion and DNSSEC validation come from the
    stored defaults, exactly as a REST create that omits them.
    """
    defaults = await load_dns_defaults(db)
    group.is_recursive = defaults.recursive
    db.add(group)
    await db.flush()
    db.add(DNSServerOptions(group=group, dnssec_validation=defaults.dnssec_validation))
