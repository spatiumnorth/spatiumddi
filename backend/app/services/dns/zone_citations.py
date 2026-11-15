"""ACL / TSIG key names a zone cites that its server group does not define (#4226)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSAcl, DNSZone
from app.services.dns.named_conf_validation import is_name_reference, key_reference
from app.services.dns.tsig import group_key_names

#: The zone fields rendered as address-match lists / ``also-notify``.
ZONE_CITING_FIELDS = ("allow_query", "allow_transfer", "also_notify")


async def undefined_zone_citations(db: AsyncSession, zone: DNSZone) -> list[str]:
    """``ACL 'A'`` / ``TSIG key 'K'`` for each name ``zone`` cites that the
    group has no definition for.

    Same notion of "defined" as the zone API's 422 (#1316) and the bundle
    builder's drop (#2282, #2283): ACL names verbatim, key names as DNS names
    (case-insensitive, trailing dot ignored), the legacy group key included.
    """
    acl_names = set(
        (await db.execute(select(DNSAcl.name).where(DNSAcl.group_id == zone.group_id)))
        .scalars()
        .all()
    )
    key_names = {k.rstrip(".").lower() for k in await group_key_names(db, zone.group_id)}
    missing: list[str] = []
    for f in ZONE_CITING_FIELDS:
        elements: Any = getattr(zone, f, None) or []
        for el in elements:
            text = str(el)
            acl = is_name_reference(text)
            if acl is not None and acl not in acl_names:
                label = f"ACL '{acl}'"
                if label not in missing:
                    missing.append(label)
            key = key_reference(text)
            if key is not None and key.rstrip(".").lower() not in key_names:
                label = f"TSIG key '{key}'"
                if label not in missing:
                    missing.append(label)
    return missing
