"""Which agent PROCESS owns a server identity (#2044, #2219, #3143).

An agent names its process on every config poll, heartbeat and registration
(``X-Spatium-Agent-Instance``: a uuid4 per process, not persisted). Two agent
processes can be live on ONE server identity at once — a cloned VM that kept
its ``agent_id``, two containers given one state dir, an overlapping rollout.
They authenticate as the same server, against its one token hash, so a token
minted for either stales the other's: the two trade 401s and re-registrations
forever and both report as one server.

So the server keeps one OWNER, and only the owner is served:

- An instance the server has never seen takes over at once. That is the
  replacement case: the old process exited, a new one started, and the new
  one must not wait for anything. The previous owner goes into
  ``agent_instances_displaced``.
- An instance in that list that polls again while the owner is still polling
  is a second live agent, not a replacement: replacements never come back. It
  is refused (409) and the episode is recorded on the row, for the server
  chip and the duplicate-instance alert.
- A displaced instance whose owner has not polled for :data:`OWNER_GONE_AFTER`
  takes back over, so the survivor of a duplicate pair recovers by itself when
  the other one is shut down.
- The refused process does not change the server's token either: its
  registration is refused (409) like its poll, and its heartbeat does not
  rotate (#2219).

Requests that carry no instance id (an agent too old to send one) bypass all
of this and behave exactly as before.

Shared by any agent-backed server model carrying the six ownership columns
(``agent_instance`` / ``agent_instance_seen_at`` / ``agent_instances_displaced``
/ ``duplicate_agent_first_at`` / ``duplicate_agent_last_at`` /
``duplicate_agent_ip``). The DHCP agent uses it (#3143); the DNS agent's
original copy lives in ``app.services.dns.agent_instance`` with the same
rules and constants.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import structlog
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPServer
from app.models.dns import DNSServer

logger = structlog.get_logger(__name__)

#: The per-process id an agent sends. A new value for a server means a new
#: agent process.
AGENT_INSTANCE_HEADER = "X-Spatium-Agent-Instance"
#: Set on the 409 a refused duplicate agent receives, so it can tell this
#: refusal from any other 409 without parsing the body.
DUPLICATE_INSTANCE_HEADER = "X-Spatium-Duplicate-Agent-Instance"
_AGENT_INSTANCE_MAX = 64  # the ``agent_instance`` column

#: An owner that has not started a config poll for this long is gone, and a
#: displaced instance may take the server back. Well past the 30 s long-poll
#: plus a large bundle's apply time, so a busy owner is never mistaken for a
#: departed one.
OWNER_GONE_AFTER = timedelta(minutes=5)
#: The owner's ``agent_instance_seen_at`` is rewritten at most this often.
SEEN_REFRESH = timedelta(seconds=15)
#: How many displaced instance ids are remembered (newest last).
DISPLACED_KEEP = 16
#: A duplicate episode is current while its latest refused request is this
#: recent.
DUPLICATE_WINDOW = timedelta(minutes=10)
#: ...and is reported only once it has lasted this long. An overlapping rollout
#: (the old pod finishing its last poll while the new one starts) is refused
#: once or twice and then exits; that is not a misconfiguration to alarm about.
DUPLICATE_PERSIST = timedelta(minutes=2)


def parse_agent_instance(raw: str | None) -> str | None:
    """The agent's instance id, or None when it sent none or an unusable one
    (an older agent, which is then not judged at all)."""
    value = (raw or "").strip()
    if not value or len(value) > _AGENT_INSTANCE_MAX or not value.isprintable():
        return None
    return value


def duplicate_instance_response(kind: str, server_name: str) -> JSONResponse:
    """409 for a poll or a registration from an agent process that does not
    own the server.

    Not 401 / 404: those make the agent drop its token and re-register
    (#2052), which would not change which process owns the row. The agent logs
    the refusal and keeps serving its cached config, asking again on a slow
    backoff; it takes the server back by itself if the owner stops polling."""
    return JSONResponse(
        status_code=409,
        headers={DUPLICATE_INSTANCE_HEADER: "1"},
        content={
            "detail": (
                f"Another agent process is polling as {kind} server '{server_name}'. "
                "Two live agents share one server identity (a cloned VM or a "
                "copied agent state directory keeps the same agent_id); only the "
                "most recent one is served. Stop the other agent, or give it its "
                "own identity by clearing its state directory."
            )
        },
    )


def duplicate_active(server: DNSServer | DHCPServer, now: datetime | None = None) -> bool:
    """Whether a second live agent process is polling as ``server`` now."""
    first = server.duplicate_agent_first_at
    last = server.duplicate_agent_last_at
    if first is None or last is None:
        return False
    now = now or datetime.now(UTC)
    return now - last <= DUPLICATE_WINDOW and last - first >= DUPLICATE_PERSIST


def is_displaced(server: DNSServer | DHCPServer, instance: str | None) -> bool:
    """Whether ``instance`` is a process this server's owner displaced and
    that is still talking to the control plane — the refused half of a
    duplicate pair, or a replaced agent's straggler.

    The heartbeat uses this to keep such a process's daemon / config-apply /
    spool reports off the row. False for an id never seen (a new process
    heartbeats before its first poll claims the server) and for an agent that
    sends no id."""
    if instance is None or server.agent_instance in (None, instance):
        return False
    return instance in (server.agent_instances_displaced or [])


def _owner_live(server: DNSServer | DHCPServer, now: datetime) -> bool:
    seen = server.agent_instance_seen_at
    return server.agent_instance is not None and seen is not None and now - seen <= OWNER_GONE_AFTER


def is_refused(
    server: DNSServer | DHCPServer, instance: str | None, now: datetime | None = None
) -> bool:
    """Whether ``instance`` is the refused half of a duplicate pair right now:
    a process the owner displaced, while the owner is still polling.

    Such a process must not change the server's token: a token minted for it
    (a re-registration, or a heartbeat rotation) makes the owner's stale, the
    owner re-registers, which makes the refused one's stale, and the two trade
    re-registrations forever."""
    return is_displaced(server, instance) and _owner_live(server, now or datetime.now(UTC))


def _record_refusal(server: DNSServer | DHCPServer, now: datetime, client_ip: str | None) -> None:
    """Stamp a refused poll or registration on the (locked) row's episode."""
    last = server.duplicate_agent_last_at
    if last is None or now - last > DUPLICATE_WINDOW:
        server.duplicate_agent_first_at = now  # a new episode
    # At most every SEEN_REFRESH: the episode needs minutes of resolution, not
    # seconds.
    if last is None or now - last >= SEEN_REFRESH:
        server.duplicate_agent_last_at = now
        server.duplicate_agent_ip = client_ip


async def _lock[ServerT: (
    DNSServer,
    DHCPServer,
)](db: AsyncSession, server: ServerT) -> ServerT | None:
    model = type(server)
    return (
        await db.execute(
            select(model)
            .where(model.id == server.id)
            # FOR NO KEY UPDATE, the lock a plain UPDATE of this row takes: it
            # serialises against every other writer of the row without
            # blocking the KEY SHARE an insert of an FK-referencing row takes.
            # The caller holds no other lock while it waits and this commits
            # at once, so it can wait behind a writer but never deadlock.
            # ``of=``: lock this row only. ``DHCPServer`` eager-joins its group
            # with an outer join, and Postgres refuses a row lock on the
            # nullable side of one.
            .with_for_update(key_share=True, of=model)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


async def refuse_registration[ServerT: (
    DNSServer,
    DHCPServer,
)](
    db: AsyncSession,
    server: ServerT,
    instance: str | None,
    *,
    kind: str,
    now: datetime | None = None,
    client_ip: str | None = None,
) -> bool:
    """Decide whether a registration from ``instance`` is refused (#2219).

    True for the refused half of a duplicate pair (:func:`is_refused`): the
    episode is recorded on the row and committed; the caller answers 409 and
    mints nothing, so the owner's token stays valid. False otherwise, with
    nothing written and no lock held in the common case: an agent that sends
    no instance id, a process the server has never seen, the owner itself, or
    a displaced one whose owner went quiet (it may take the server back)."""
    now = now or datetime.now(UTC)
    if instance is None or not is_refused(server, instance, now):
        return False
    locked = await _lock(db, server)
    if locked is None:
        return False
    if not is_refused(locked, instance, now):
        await db.commit()  # nothing written; releases the row lock
        return False
    _record_refusal(locked, now, client_ip)
    await db.commit()
    logger.warning(
        f"{kind}_agent_duplicate_instance_register_refused",
        server_id=str(locked.id),
        server=locked.name,
        refused_instance=instance,
        owner_instance=locked.agent_instance,
        client_ip=client_ip,
    )
    return True


async def claim_poll[ServerT: (
    DNSServer,
    DHCPServer,
)](
    db: AsyncSession,
    server: ServerT,
    instance: str,
    *,
    kind: str,
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

    locked = await _lock(db, server)
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
            f"{kind}_agent_duplicate_instance_refused",
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
        f"{kind}_agent_instance_took_over",
        server_id=str(locked.id),
        server=locked.name,
        instance=instance,
        previous_instance=owner,
        previous_gone=not live,
    )
    return True
