"""Which DNS agent PROCESS owns a server identity (#2044).

A DNS agent names its process on every config poll
(``X-Spatium-Agent-Instance``, #2042). #2043 used that to take a record op
back from a replaced agent's leftover long-poll: an op ``in_flight`` to
another instance, shipped by an older poll, goes back to ``pending`` and this
poll ships it. That is right when the other instance is gone. When two agent
processes are live on ONE server identity at once — a cloned VM that kept its
``agent_id``, two containers sharing a state dir, an overlapping rollout —
each one's polls took the ops back from the other, and an op bounced between
them, one retry attempt per bounce, until its eight were spent.

So the server keeps one OWNER, and only the owner is served:

- An instance the server has never seen takes over at once. That is the
  replacement case (#2042): the old process exited, a new one started, and
  the new one must not wait for anything. The previous owner goes into
  ``agent_instances_displaced``.
- An instance in that list that polls again while the owner is still polling
  is a second live agent, not a replacement: replacements never come back. It
  is refused (409) and the episode is recorded on the row, for the server
  chip and the ``dns_agent_duplicate_instance`` alert.
- A displaced instance whose owner has not polled for :data:`OWNER_GONE_AFTER`
  takes back over, so the survivor of a duplicate pair recovers by itself when
  the other one is shut down.

- #2219: the refused process does not change the server's token either. It
  authenticates as the same server, against the same ``agent_jwt_hash``, so a
  token minted for it makes the owner's stale; the owner re-registers, and the
  two trade re-registrations forever. Its registration is refused (409) like
  its poll, and its heartbeat does not rotate.

The newest arrival winning is what keeps a replacement seamless; refusing the
returning one is what stops the ping-pong. Polls that carry no instance id (an
agent too old to send one) bypass all of this, as they bypass #2043.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServer

logger = structlog.get_logger(__name__)

#: An owner that has not started a config poll for this long is gone, and a
#: displaced instance may take the server back. Well past the 30 s long-poll
#: plus a large bundle's apply time, so a busy owner is never mistaken for a
#: departed one.
OWNER_GONE_AFTER = timedelta(minutes=5)
#: The owner's ``agent_instance_seen_at`` is rewritten at most this often; a
#: draining op backlog polls many times a second.
SEEN_REFRESH = timedelta(seconds=15)
#: How many displaced instance ids are remembered (newest last).
DISPLACED_KEEP = 16
#: A duplicate episode is current while its latest refused poll is this recent.
DUPLICATE_WINDOW = timedelta(minutes=10)
#: ...and is reported only once it has lasted this long. An overlapping rollout
#: (the old pod finishing its last poll while the new one starts) is refused
#: once or twice and then exits; that is not a misconfiguration to alarm about.
DUPLICATE_PERSIST = timedelta(minutes=2)


def duplicate_active(server: DNSServer, now: datetime | None = None) -> bool:
    """Whether a second live agent process is polling as ``server`` now."""
    first = server.duplicate_agent_first_at
    last = server.duplicate_agent_last_at
    if first is None or last is None:
        return False
    now = now or datetime.now(UTC)
    return now - last <= DUPLICATE_WINDOW and last - first >= DUPLICATE_PERSIST


def is_displaced(server: DNSServer, instance: str | None) -> bool:
    """Whether ``instance`` is a process this server's owner displaced and
    that is still talking to the control plane — the refused half of a
    duplicate pair, or a replaced agent's straggler.

    The heartbeat uses this to keep such a process's daemon / config-apply /
    spool reports off the row: they describe a process that is not being
    served, and written alternately with the owner's they would flap the
    row's state and could mask, or invent, an ``agent_config_rejected`` or
    ``agent_daemon_degraded`` verdict. False for an id never seen (a new
    process heartbeats before its first poll claims the server) and for an
    agent that sends no id."""
    if instance is None or server.agent_instance in (None, instance):
        return False
    return instance in (server.agent_instances_displaced or [])


def _owner_live(server: DNSServer, now: datetime) -> bool:
    """Whether the server's owner has started a config poll recently."""
    seen = server.agent_instance_seen_at
    return server.agent_instance is not None and seen is not None and now - seen <= OWNER_GONE_AFTER


def _record_refusal(server: DNSServer, now: datetime, client_ip: str | None) -> None:
    """Stamp a refused poll or registration on the (locked) row's episode."""
    last = server.duplicate_agent_last_at
    if last is None or now - last > DUPLICATE_WINDOW:
        server.duplicate_agent_first_at = now  # a new episode
    # At most every SEEN_REFRESH: an older agent retries a refusal every
    # 5 s, and the episode needs minutes of resolution, not seconds.
    if last is None or now - last >= SEEN_REFRESH:
        server.duplicate_agent_last_at = now
        server.duplicate_agent_ip = client_ip


def is_refused(server: DNSServer, instance: str | None, now: datetime | None = None) -> bool:
    """Whether ``instance`` is the refused half of a duplicate pair right now:
    a process the owner displaced, while the owner is still polling (#2219).

    Such a process must not change the server's token. Both processes of a
    pair authenticate as the one server, against its one ``agent_jwt_hash``;
    a token minted for the refused process (a re-registration, or a heartbeat
    rotation) makes the owner's stale, the owner re-registers, which makes
    the refused one's stale, and the two trade re-registrations forever."""
    return is_displaced(server, instance) and _owner_live(server, now or datetime.now(UTC))


async def refuse_registration(
    db: AsyncSession,
    server: DNSServer,
    instance: str | None,
    *,
    now: datetime | None = None,
    client_ip: str | None = None,
) -> bool:
    """Decide whether a registration from ``instance`` is refused (#2219).

    True for the refused half of a duplicate pair (:func:`is_refused`): the
    episode is recorded on the row, as a refused poll records it, and
    committed. The caller answers 409 and mints nothing, so the owner's token
    stays valid. False otherwise, with nothing written and no lock held: an
    agent that sends no instance id (older than #2219), a process the server
    has never seen, the owner itself, or a displaced one whose owner went
    quiet (it may take the server back, as at poll).

    The common case is decided from the row as read, without a lock, so a
    registration that is not refused takes its locks in the order it always
    did. Only a likely refusal locks the row, re-checks, and commits."""
    now = now or datetime.now(UTC)
    if instance is None or not is_refused(server, instance, now):
        return False
    locked = (
        await db.execute(
            select(DNSServer)
            .where(DNSServer.id == server.id)
            .with_for_update(key_share=True)  # as in claim_poll
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if locked is None:
        return False
    if not is_refused(locked, instance, now):
        await db.commit()  # nothing written; releases the row lock
        return False
    _record_refusal(locked, now, client_ip)
    await db.commit()
    logger.warning(
        "dns_agent_duplicate_instance_register_refused",
        server_id=str(locked.id),
        server=locked.name,
        refused_instance=instance,
        owner_instance=locked.agent_instance,
        client_ip=client_ip,
        issue="#2219",
    )
    return True


async def claim_poll(
    db: AsyncSession,
    server: DNSServer,
    instance: str,
    *,
    now: datetime | None = None,
    client_ip: str | None = None,
) -> bool:
    """Decide whether ``instance`` may be served this server's config poll.

    True: it is (now) the owner. False: it is a displaced instance and the
    owner is live — refuse the poll. Commits whatever it changed, on its own:
    the caller's long-poll then waits, and must not hold the server row lock.
    """
    now = now or datetime.now(UTC)
    seen = server.agent_instance_seen_at
    if server.agent_instance == instance and seen is not None and now - seen < SEEN_REFRESH:
        return True  # the owner, recently stamped: no write

    locked = (
        await db.execute(
            select(DNSServer)
            .where(DNSServer.id == server.id)
            # FOR NO KEY UPDATE, the lock a plain UPDATE of this row takes: it
            # serialises against every other writer of the row (another
            # replica's claim, the heartbeat, the bundle store, registration,
            # a server move) without blocking the KEY SHARE an insert of an
            # FK-referencing row takes (a record write enqueuing this server's
            # ops). This transaction holds no other lock while it waits — the
            # request has only read so far — and commits at once, so it can
            # wait behind a writer but never be part of a deadlock cycle.
            .with_for_update(key_share=True)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if locked is None:
        # Deleted since the token was checked: the long-poll's own refresh
        # answers 404, which is what sends the agent to re-register.
        return True
    owner = locked.agent_instance
    if owner is None or owner == instance:
        locked.agent_instance = instance
        locked.agent_instance_seen_at = now
        await db.commit()
        return True

    displaced = [d for d in (locked.agent_instances_displaced or []) if isinstance(d, str)]
    live = _owner_live(locked, now)
    if instance in displaced and live:
        _record_refusal(locked, now, client_ip)
        await db.commit()
        logger.warning(
            "dns_agent_duplicate_instance_refused",
            server_id=str(locked.id),
            server=locked.name,
            refused_instance=instance,
            owner_instance=owner,
            client_ip=client_ip,
        )
        return False

    # A new instance (an agent was replaced), or the owner is gone: take over.
    displaced = [d for d in displaced if d not in (instance, owner)] + [owner]
    locked.agent_instances_displaced = displaced[-DISPLACED_KEEP:]
    locked.agent_instance = instance
    locked.agent_instance_seen_at = now
    await db.commit()
    logger.info(
        "dns_agent_instance_took_over",
        server_id=str(locked.id),
        server=locked.name,
        instance=instance,
        previous_instance=owner,
        previous_gone=not live,
    )
    return True
