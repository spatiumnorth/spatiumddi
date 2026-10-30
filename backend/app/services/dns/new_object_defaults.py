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

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import ZONE_DEFAULT_TTL, DNSServerGroup, DNSServerOptions
from app.models.settings import PlatformSettings


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
    return DNSNewObjectDefaults(
        ttl=ps.dns_default_ttl,
        zone_type=ps.dns_default_zone_type,
        dnssec_validation=ps.dns_default_dnssec_validation,
        recursive=ps.dns_recursive_by_default,
    )


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
