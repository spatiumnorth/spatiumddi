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

A root (``.``) anchor must be ``initial-key`` (#3609). BIND refuses a
``static-key`` root anchor beside ``dnssec-validation auto`` ("static trust
anchor for root zone cannot be used with 'dnssec-validation auto'") and, in
any mode, warns that it "WILL FAIL after key rollover": a static key is never
updated, so validation of everything breaks at the next root KSK roll. There
is no mode in which a static root anchor is right, so it is refused on
create whatever the validation mode. A row stored before that refusal is
rendered as ``initial-key`` (RFC 5011 tracking from the same key), which
loads under every mode, and the options response says so.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServerOptions, DNSTrustAnchor

NEEDS_ANCHOR_MESSAGE = (
    "dnssec_validation 'yes' requires a configured trust anchor on BIND9 (9.20 and later "
    "refuse to load the config otherwise). Either set dnssec_validation to 'auto' to "
    "validate against BIND's built-in root key, or add a trust anchor first."
)

STATIC_ROOT_ANCHOR_MESSAGE = (
    "A static (is_initial_key: false) trust anchor for the root zone '.' is refused: BIND "
    "will not load it beside dnssec_validation 'auto', and in any mode a static root key "
    "stops validating everything at the next root key rollover. Add it as an initial-key "
    "anchor (is_initial_key: true, the default), which BIND keeps current by RFC 5011; "
    "it loads under both 'auto' and 'yes'."
)


def is_root_zone(zone_name: str) -> bool:
    return zone_name.strip().rstrip(".") == ""


def render_as_initial_key(zone_name: str, is_initial_key: bool) -> bool:
    """Whether to render an anchor as ``initial-key``.

    A static root anchor stored before #3609 refused it is rendered as
    ``initial-key`` so the group's config loads (BIND refuses it under
    ``auto``) and survives the next root key rollover.
    """
    return bool(is_initial_key) or is_root_zone(zone_name)


def has_static_root_anchor(anchors: Iterable[Any]) -> bool:
    return any(is_root_zone(a.zone_name) and not a.is_initial_key for a in anchors)


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
