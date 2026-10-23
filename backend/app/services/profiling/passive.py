"""Passive layer orchestration — fingerprint upsert + IPAddress stamping.

The agent ships fingerprints; the ingestion endpoint
(``/api/v1/dhcp/agents/dhcp-fingerprints``) calls
:func:`upsert_fingerprint` per row to land them in the
``dhcp_fingerprint`` table, then enqueues a Celery task per fresh
fingerprint to do the slow part (fingerbank lookup + IP stamping).

Why split? Fingerbank's API takes 100-500ms per call, and we don't
want to block the agent's bulk POST on N round-trips. The Celery
task is idempotent — if it runs twice for the same MAC it just sees
a fresh-cache hit on the second run and exits.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPScope, DHCPServer
from app.models.dhcp_fingerprint import DHCPFingerprint
from app.models.ipam import IPAddress, Subnet
from app.services.profiling.fingerbank import lookup as fingerbank_lookup

logger = structlog.get_logger(__name__)


def _normalize_mac(mac: str) -> str:
    """Lowercase canonical form so MAC matching survives ``aa:BB:cc`` casing.

    PG MACADDR canonicalises on insert, but we receive incoming MACs
    as JSON strings and want to match against ``IPAddress.mac_address``
    which is also MACADDR — both sides come back lowercase from
    Postgres so a simple ``.lower()`` is enough for the lookup keys.
    """
    return mac.strip().lower()


async def upsert_fingerprint(
    db: AsyncSession,
    *,
    mac_address: str,
    option_55: str | None,
    option_60: str | None,
    option_77: str | None,
    client_id: str | None,
) -> tuple[DHCPFingerprint, bool]:
    """Upsert one fingerprint row by MAC.

    Returns ``(row, is_new_or_changed)``. The boolean tells the
    caller whether to enqueue a fingerbank lookup task — we skip the
    enqueue when the signature is unchanged AND the cached lookup is
    still fresh, so a chatty client renewing every 5 min doesn't
    fan out into a fingerbank task per renewal.
    """
    mac = _normalize_mac(mac_address)
    existing = await db.get(DHCPFingerprint, mac)
    now = datetime.now(UTC)

    if existing is None:
        row = DHCPFingerprint(
            mac_address=mac,
            option_55=option_55,
            option_60=option_60,
            option_77=option_77,
            client_id=client_id,
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(row)
        return row, True

    signature_changed = (
        existing.option_55 != option_55
        or existing.option_60 != option_60
        or existing.option_77 != option_77
        or existing.client_id != client_id
    )
    existing.last_seen_at = now
    if signature_changed:
        existing.option_55 = option_55
        existing.option_60 = option_60
        existing.option_77 = option_77
        existing.client_id = client_id
        # New signature for this MAC (e.g. a Windows update changed
        # the parameter list) — invalidate the cached lookup so the
        # task re-queries fingerbank. We don't clear the cached
        # taxonomy — the IP detail modal keeps showing the old name
        # until the new lookup lands, which is better UX than a
        # transient blank.
        existing.fingerbank_last_lookup_at = None

    return existing, signature_changed


async def stamp_matching_ips(
    db: AsyncSession,
    *,
    fingerprint: DHCPFingerprint,
    server_id: uuid.UUID | None = None,
) -> int:
    """Copy fingerbank result onto the IPAddress rows sharing the MAC.

    Respects the ``user_modified_at`` lock — if the operator has
    manually edited the row's soft fields we leave the device columns
    alone too, because the operator may have set a more accurate
    description by hand. Returns the number of rows actually stamped
    (the caller doesn't strictly need this, but it's cheap and useful
    for the structlog event).

    Space scoping (#2577): IP spaces are independent, and the same MAC
    can sit on rows in several of them. The fingerprint was observed by
    one DHCP server (``server_id``), so only rows in the IP spaces that
    server's group serves (any space holding a subnet one of the
    group's scopes is bound to) are stamped. Without a server — a task
    enqueued before this change — or with a server that belongs to no
    server group, the rows are stamped only when they all sit in one
    space; a MAC spread across spaces is skipped rather than written
    into every one of them. The path taken is logged.
    """
    if fingerprint.fingerbank_device_name is None:
        return 0

    stmt = update(IPAddress).where(
        IPAddress.mac_address == fingerprint.mac_address,
        IPAddress.user_modified_at.is_(None),
    )
    group_id: uuid.UUID | None = None
    if server_id is not None:
        group_id = (
            await db.execute(select(DHCPServer.server_group_id).where(DHCPServer.id == server_id))
        ).scalar_one_or_none()
    if group_id is not None:
        served_spaces = (
            select(Subnet.space_id)
            .join(DHCPScope, DHCPScope.subnet_id == Subnet.id)
            .where(DHCPScope.group_id == group_id, DHCPScope.deleted_at.is_(None))
        )
        stmt = stmt.where(
            IPAddress.subnet_id.in_(select(Subnet.id).where(Subnet.space_id.in_(served_spaces)))
        )
        scope_path = "served_spaces"
    else:
        # No reporting server, or one in no server group (so it serves no
        # scope we could read a space off): stamp only when every matching
        # row is in one space, never into several at once.
        scope_path = "no_server" if server_id is None else "server_without_group"
        spaces = set(
            (
                await db.execute(
                    select(Subnet.space_id)
                    .join(IPAddress, IPAddress.subnet_id == Subnet.id)
                    .where(
                        IPAddress.mac_address == fingerprint.mac_address,
                        IPAddress.user_modified_at.is_(None),
                    )
                    .distinct()
                )
            ).scalars()
        )
        if len(spaces) > 1:
            logger.info(
                "fingerprint_stamp_skipped_ambiguous_space",
                mac=fingerprint.mac_address,
                spaces=len(spaces),
                path=scope_path,
            )
            return 0
    logger.debug(
        "fingerprint_stamp_space_scope",
        mac=fingerprint.mac_address,
        path=scope_path,
        server_id=str(server_id) if server_id else None,
    )

    result = await db.execute(
        stmt.values(
            device_type=fingerprint.fingerbank_device_name,
            device_class=fingerprint.fingerbank_device_class,
            device_manufacturer=fingerprint.fingerbank_manufacturer,
        ).execution_options(synchronize_session=False)
    )
    return int(result.rowcount or 0)


async def run_lookup_and_stamp(
    db: AsyncSession,
    *,
    mac_address: str,
    server_id: uuid.UUID | None = None,
) -> bool:
    """Celery-task body: fetch the fingerprint, hit fingerbank, stamp matching IPs.

    ``server_id`` is the DHCP server that reported the fingerprint; it
    scopes the stamp to the IP spaces that server serves (#2577).

    Idempotent + safe to retry. Returns True if a stamp happened (so
    the task can log a useful counter), False otherwise.
    """
    mac = _normalize_mac(mac_address)
    fingerprint = await db.get(DHCPFingerprint, mac)
    if fingerprint is None:
        logger.debug("fingerprint_lookup_missing_row", mac=mac)
        return False

    result = await fingerbank_lookup(db, fingerprint=fingerprint)
    if result is None:
        # Either cache hit, no API key, or API error — nothing to
        # stamp this round. The error case has already been recorded
        # on the row by the lookup function.
        await db.commit()
        return False

    stamped = await stamp_matching_ips(db, fingerprint=fingerprint, server_id=server_id)
    await db.commit()
    logger.info(
        "fingerprint_stamp_done",
        mac=mac,
        stamped=stamped,
        device_name=fingerprint.fingerbank_device_name,
    )
    return stamped > 0


async def get_fingerprint_for_ip(
    db: AsyncSession,
    *,
    ip: IPAddress,
) -> DHCPFingerprint | None:
    """Resolve the fingerprint row for an IPAddress via its MAC.

    Returns ``None`` when the IP has no MAC or no fingerprint exists
    yet. Used by the IP detail modal endpoint.
    """
    if ip.mac_address is None:
        return None
    res = await db.execute(
        select(DHCPFingerprint).where(
            DHCPFingerprint.mac_address == _normalize_mac(str(ip.mac_address))
        )
    )
    return res.scalar_one_or_none()


__all__ = [
    "get_fingerprint_for_ip",
    "run_lookup_and_stamp",
    "stamp_matching_ips",
    "upsert_fingerprint",
]
