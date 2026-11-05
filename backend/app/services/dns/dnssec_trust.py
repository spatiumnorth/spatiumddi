"""``dnssec-validation yes`` needs a trust anchor on BIND9 (#3560).

Since BIND 9.20 (GL #4373) ``dnssec-validation yes`` with no
``trust-anchors`` statement is a configuration error: ``named-checkconf``
exits 1 ("requires configured 'trust-anchors'"), the agent declines the
whole bundle and the group stops converging. ``auto`` uses the built-in
root key and needs nothing.

Only BIND9 has the rule. Technitium has a boolean validation switch and
no anchor concept, PowerDNS authoritative does not validate; both accept
``yes`` as before, so the check is scoped to groups holding a BIND9
server (an empty group reads as BIND9, like every other driver gate).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServerOptions, DNSTrustAnchor

NEEDS_ANCHOR_MESSAGE = (
    "dnssec_validation 'yes' requires a configured trust anchor on BIND9 (9.20 and later "
    "refuse to load the config otherwise). Either set dnssec_validation to 'auto' to "
    "validate against BIND's built-in root key, or add a trust anchor first."
)


async def count_anchors(
    db: AsyncSession, group_id: uuid.UUID, *, exclude_id: uuid.UUID | None = None
) -> int:
    stmt = (
        select(func.count(DNSTrustAnchor.id))
        .join(DNSServerOptions, DNSTrustAnchor.server_options_id == DNSServerOptions.id)
        .where(DNSServerOptions.group_id == group_id)
    )
    if exclude_id is not None:
        stmt = stmt.where(DNSTrustAnchor.id != exclude_id)
    return int((await db.execute(stmt)).scalar_one())


async def stored_validation(db: AsyncSession, group_id: uuid.UUID) -> str | None:
    return (
        await db.execute(
            select(DNSServerOptions.dnssec_validation).where(DNSServerOptions.group_id == group_id)
        )
    ).scalar_one_or_none()


def effective_dnssec_validation(validation: str, driver: str, n_anchors: int) -> str:
    """What to render for a BIND9 server.

    A row stored before the API refused ``yes`` without an anchor would make
    BIND refuse the file; it is rendered as ``auto`` instead (the group keeps
    validating, against the built-in root key) and the options response says so.
    """
    if driver == "bind9" and validation == "yes" and not n_anchors:
        return "auto"
    return validation
