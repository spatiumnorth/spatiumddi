"""ACME DNS-01 provider — business logic layer.

Thin wrapper over the existing DNS record-op pipeline. Keeps the
router clean and ties together auth, source-IP enforcement, TXT
write, and the wait-for-apply pattern.

The "wait for apply" piece is the load-bearing one: Let's Encrypt
polls authoritative DNS within ~5-30 seconds of the client signaling
that the challenge is ready. If ``/update`` returns 200 before the
TXT record is actually live on the primary DNS server, LE will fetch
stale data and the challenge fails. We poll ``DNSRecordOp.state``
until it transitions to ``applied`` (or ``failed``) or we hit a
timeout, using fresh DB sessions so the poll doesn't hold a
connection open across ``await asyncio.sleep`` calls.
"""

from __future__ import annotations

import asyncio
import ipaddress
import uuid
from datetime import UTC, datetime

import structlog
from sqlalchemy import and_, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db import AsyncSessionLocal
from app.models.acme import ACMEAccount
from app.models.dns import DNSAgentBundle, DNSRecord, DNSRecordOp, DNSZone

log = structlog.get_logger(__name__)

# Short TTL so LE observes propagation quickly after /update returns;
# also so a left-behind TXT dies quickly if the janitor sweep falls
# behind. 60s matches the canonical acme-dns value.
ACME_TXT_TTL = 60

# Cap the number of concurrent TXT values per subdomain to mirror
# acme-dns behaviour: wildcard certs for ``example.com + *.example.com``
# request two different validation tokens on the SAME record name, and
# LE expects both to be visible during validation. Capping at 2 means
# a third /update for the same subdomain evicts the oldest value.
MAX_TXT_VALUES_PER_SUBDOMAIN = 2

# How long to wait for the agents to apply a TXT record. LE will retry
# challenges that fail, but it's polite to give a confident answer only
# after the record is actually live. This is the floor: a large group's
# own render time raises it (``apply_timeout_for``, #1184).
DEFAULT_APPLY_TIMEOUT_SECONDS = 30.0
APPLY_POLL_INTERVAL_SECONDS = 0.5
# Past the renders: the agent's fetch, apply and acknowledgement.
APPLY_TIMEOUT_MARGIN_SECONDS = 10.0
# The embedded ACME client waits in a Celery task, which has no time limit.
MAX_APPLY_TIMEOUT_SECONDS = 300.0
# The provider's /update waits inside the HTTP request, and the web
# frontend's nginx ends an /api/ request at 60 s (``proxy_read_timeout``).
PROVIDER_MAX_APPLY_TIMEOUT_SECONDS = 55.0


class ACMEError(Exception):
    """Base — all ACME-service-level errors inherit."""


class ACMEAuthError(ACMEError):
    """Bad ``X-Api-User`` / ``X-Api-Key`` / source IP."""


class ACMESubdomainMismatch(ACMEError):
    """Client's ``subdomain`` body field doesn't match their account."""


class ACMEApplyTimeout(ACMEError):
    """Exceeded the poll deadline waiting for the agent to apply the op."""


class ACMEApplyFailed(ACMEError):
    """The agent acknowledged the op but it failed (driver returned error)."""


# ── Auth ─────────────────────────────────────────────────────────────


def client_ip_allowed(account: ACMEAccount, client_ip: str | None) -> bool:
    """Check the client's source IP against the account's allowlist.

    Empty / null allowlist = open. Otherwise the client IP must be
    inside at least one of the configured CIDRs. Unresolvable client
    IPs (e.g. unix-socket callers) fail closed when an allowlist is
    set.
    """
    allow = account.allowed_source_cidrs or []
    if not allow:
        return True
    if client_ip is None:
        return False
    try:
        ip_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    for cidr in allow:
        try:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            # Operator typo in the allowlist — skip the entry rather
            # than fail the whole check.
            log.warning("acme_allowlist_bad_cidr", cidr=cidr)
            continue
    return False


async def authenticate(db: AsyncSession, username: str, password: str) -> ACMEAccount | None:
    """Return the matching account or None.

    Does the password verify even when the username doesn't exist, to
    keep timing roughly equivalent and deny attackers a free username-
    enumeration oracle.
    """
    from app.core.acme_auth import verify_acme_password

    stmt = (
        select(ACMEAccount)
        .where(ACMEAccount.username == username)
        .options(selectinload(ACMEAccount.zone))
    )
    account = (await db.execute(stmt)).scalar_one_or_none()
    # Dummy hash to waste similar time on non-existent usernames. The
    # exact hash here is irrelevant as long as it's a valid bcrypt
    # string so ``verify_acme_password`` exercises the KDF path.
    dummy = "$2b$12$AAAAAAAAAAAAAAAAAAAAAuhvdhPXYVDbOvRVnvMMF6VVO8AuXqJIu"
    if account is None:
        verify_acme_password(password, dummy)
        return None
    if not verify_acme_password(password, account.password_hash):
        return None
    return account


# ── Account management ──────────────────────────────────────────────


def fulldomain_of(account: ACMEAccount, zone: DNSZone) -> str:
    """Compute the ``fulldomain`` string returned to the client.

    This is the FQDN the operator will CNAME
    ``_acme-challenge.<their-domain>`` to. acme-dns clients store it
    verbatim — don't include a trailing dot.
    """
    zone_name = zone.name.rstrip(".")
    return f"{account.subdomain}.{zone_name}"


async def register_account(
    db: AsyncSession,
    *,
    zone: DNSZone,
    created_by_user_id: uuid.UUID,
    description: str = "",
    allowed_source_cidrs: list[str] | None = None,
) -> tuple[ACMEAccount, str, str]:
    """Create + persist a new ACME account. Returns ``(row, username,
    password)`` — the plaintext secrets are for the response body and
    must not be logged.
    """
    from app.core.acme_auth import (
        generate_acme_credentials,
        hash_acme_password,
    )

    username, password, subdomain = generate_acme_credentials()
    account = ACMEAccount(
        username=username,
        password_hash=hash_acme_password(password),
        subdomain=subdomain,
        zone_id=zone.id,
        allowed_source_cidrs=list(allowed_source_cidrs) if allowed_source_cidrs else None,
        description=description,
        created_by_user_id=created_by_user_id,
    )
    db.add(account)
    await db.flush()
    log.info(
        "acme_account_registered",
        account_id=str(account.id),
        zone=zone.name,
        subdomain=subdomain,
    )
    return account, username, password


# ── TXT record lifecycle ────────────────────────────────────────────


async def _existing_txt_records(db: AsyncSession, zone_id: uuid.UUID, name: str) -> list[DNSRecord]:
    stmt = (
        select(DNSRecord)
        .where(
            and_(
                DNSRecord.zone_id == zone_id,
                DNSRecord.name == name,
                DNSRecord.record_type == "TXT",
            )
        )
        .order_by(DNSRecord.created_at.asc())
    )
    return list((await db.execute(stmt)).scalars().all())


async def apply_txt_update(db: AsyncSession, account: ACMEAccount, txt: str) -> DNSRecordOp | None:
    """Upsert a TXT record at the account's subdomain.

    Keeps the most recent ``MAX_TXT_VALUES_PER_SUBDOMAIN`` values so
    that wildcard + base cert issuance (which stores two different
    tokens at the same FQDN) works.

    Returns the enqueued ``DNSRecordOp`` so the caller can wait for
    the agent to apply it. ``None`` means the zone has no primary
    server configured and the caller should surface a 503.
    """
    from app.services.dns.record_ops import enqueue_record_op
    from app.services.dns.serial import bump_zone_serial

    zone = account.zone
    existing = await _existing_txt_records(db, zone.id, account.subdomain)

    # Evict the oldest if we're at the cap, so the new value fits
    # under the 2-value rolling window.
    while len(existing) >= MAX_TXT_VALUES_PER_SUBDOMAIN:
        oldest = existing.pop(0)
        await db.execute(delete(DNSRecord).where(DNSRecord.id == oldest.id))
        target_serial = bump_zone_serial(zone)
        await enqueue_record_op(
            db,
            zone,
            "delete",
            {
                "name": oldest.name,
                "type": "TXT",
                "value": oldest.value,
                "ttl": oldest.ttl or ACME_TXT_TTL,
            },
            target_serial=target_serial,
        )

    # Idempotency: if the same (subdomain, txt) already exists, don't
    # create a duplicate — certbot / lego retries can produce
    # identical /update calls on network blips.
    for rec in existing:
        if rec.value == txt:
            return None  # nothing to do; already live

    zone_domain = zone.name.rstrip(".")
    new_rec = DNSRecord(
        zone_id=zone.id,
        name=account.subdomain,
        fqdn=f"{account.subdomain}.{zone_domain}",
        record_type="TXT",
        value=txt,
        ttl=ACME_TXT_TTL,
        auto_generated=True,
    )
    db.add(new_rec)
    # Let _enqueue_dns_op bump the serial + hit the primary server.
    target_serial = bump_zone_serial(zone)
    op_row = await enqueue_record_op(
        db,
        zone,
        "create",
        {
            "name": account.subdomain,
            "type": "TXT",
            "value": txt,
            "ttl": ACME_TXT_TTL,
        },
        target_serial=target_serial,
    )
    account.last_used_at = datetime.now(UTC)
    await db.flush()
    return op_row


async def apply_txt_delete(db: AsyncSession, account: ACMEAccount) -> list[DNSRecordOp]:
    """Remove all TXT records at the account's subdomain.

    Called from ``DELETE /update`` (post-validation cleanup) and from
    the stale-record janitor. Returns the list of enqueued delete ops
    so the caller can wait on them if it cares about propagation.
    """
    from app.services.dns.record_ops import enqueue_record_op
    from app.services.dns.serial import bump_zone_serial

    zone = account.zone
    existing = await _existing_txt_records(db, zone.id, account.subdomain)
    ops: list[DNSRecordOp] = []
    for rec in existing:
        target_serial = bump_zone_serial(zone)
        await db.execute(delete(DNSRecord).where(DNSRecord.id == rec.id))
        op_row = await enqueue_record_op(
            db,
            zone,
            "delete",
            {
                "name": rec.name,
                "type": "TXT",
                "value": rec.value,
                "ttl": rec.ttl or ACME_TXT_TTL,
            },
            target_serial=target_serial,
        )
        if op_row is not None:
            ops.append(op_row)
    account.last_used_at = datetime.now(UTC)
    await db.flush()
    return ops


# ── Wait-for-apply ──────────────────────────────────────────────────


async def apply_timeout_for(
    db: AsyncSession,
    op_ids: list[uuid.UUID],
    *,
    cap: float = MAX_APPLY_TIMEOUT_SECONDS,
) -> float:
    """How long to wait for ``op_ids`` to apply, in seconds (#1184).

    An agent receives a change with the first render of its bundle that
    starts after the change committed, and every server's render goes
    through one fleet-wide slot. So the worst case is the render already
    in the slot plus one render per target server: ``servers + 1`` times
    the slowest render those servers have stored, plus a margin. At a
    million records one render takes about 30 s, which put a fixed 30 s
    wait on the edge.

    Never below :data:`DEFAULT_APPLY_TIMEOUT_SECONDS`: a server with no
    stored render (an agentless driver, or one not rendered yet) keeps the
    old wait. Never above ``cap``.
    """
    if not op_ids:
        return DEFAULT_APPLY_TIMEOUT_SECONDS
    servers = select(DNSRecordOp.server_id).where(DNSRecordOp.id.in_(op_ids))
    rendered, slowest_ms = (
        await db.execute(
            select(
                func.count(func.distinct(DNSAgentBundle.server_id)),
                func.max(DNSAgentBundle.render_ms),
            ).where(DNSAgentBundle.server_id.in_(servers))
        )
    ).one()
    if not slowest_ms:
        return DEFAULT_APPLY_TIMEOUT_SECONDS
    scaled = (rendered + 1) * slowest_ms / 1000 + APPLY_TIMEOUT_MARGIN_SECONDS
    return min(max(DEFAULT_APPLY_TIMEOUT_SECONDS, scaled), cap)


async def wait_for_op_applied(
    op_id: uuid.UUID,
    *,
    timeout: float = DEFAULT_APPLY_TIMEOUT_SECONDS,
    poll_interval: float = APPLY_POLL_INTERVAL_SECONDS,
) -> str:
    """Block until the op's state transitions to ``applied`` / ``failed``.

    Returns the final state. Raises :class:`ACMEApplyTimeout` if the
    deadline expires. Opens a fresh DB session per poll so we don't
    pin a connection across ``await asyncio.sleep``.

    Rationale: the agent long-polls ``/config`` for bundle changes;
    after it applies the op it posts an ACK in its next heartbeat,
    which writes ``state=applied`` on the row. Polling is simple,
    correct, and usually converges in <5 seconds on a healthy pair.
    """
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        async with AsyncSessionLocal() as fresh_db:
            row = await fresh_db.get(DNSRecordOp, op_id)
            if row is None:
                # Op row vanished — treat as applied so the client
                # isn't held up by a race with the sweeper.
                return "applied"
            state = row.state
        if state in ("applied", "failed"):
            return state
        await asyncio.sleep(poll_interval)
    raise ACMEApplyTimeout(f"op {op_id} did not reach 'applied' within {timeout}s")


async def wait_for_ops_applied(
    op_ids: list[uuid.UUID],
    *,
    timeout: float = DEFAULT_APPLY_TIMEOUT_SECONDS,
) -> dict[uuid.UUID, str]:
    """Fan-out wait helper for the delete path (one op per evicted record).

    Uses a shared deadline — all ops are waited on concurrently rather
    than sequentially, so a 2-record delete doesn't double the
    perceived latency.
    """
    if not op_ids:
        return {}
    deadline = asyncio.get_running_loop().time() + timeout
    remaining = set(op_ids)
    result: dict[uuid.UUID, str] = {}
    while remaining and asyncio.get_running_loop().time() < deadline:
        async with AsyncSessionLocal() as fresh_db:
            rows = (
                (
                    await fresh_db.execute(
                        select(DNSRecordOp).where(DNSRecordOp.id.in_(list(remaining)))
                    )
                )
                .scalars()
                .all()
            )
            seen = {r.id for r in rows}
            for missing in remaining - seen:
                result[missing] = "applied"  # row swept
            for row in rows:
                if row.state in ("applied", "failed"):
                    result[row.id] = row.state
        remaining = set(op_ids) - set(result.keys())
        if remaining:
            await asyncio.sleep(APPLY_POLL_INTERVAL_SECONDS)
    for leftover in remaining:
        result[leftover] = "timeout"
    return result


# ── Sweep stale records (janitor) ───────────────────────────────────


async def sweep_stale_txt_records(db: AsyncSession, *, max_age_seconds: int = 24 * 3600) -> int:
    """Delete TXT records at ACME subdomains older than ``max_age_seconds``.

    Clients that crash between "/update set txt" and "/update delete txt"
    leave records behind. LE issuance has long since succeeded by the
    time this runs; the stale records don't hurt anyone but we clean
    them up so the zone doesn't accumulate noise.

    Returns the number of rows deleted. Enqueues delete ops so the
    agent applies the removal.
    """
    from datetime import timedelta

    from app.services.dns.record_ops import enqueue_record_op
    from app.services.dns.serial import bump_zone_serial

    cutoff = datetime.now(UTC) - timedelta(seconds=max_age_seconds)

    stmt = (
        select(DNSRecord, ACMEAccount)
        .join(
            ACMEAccount,
            and_(
                DNSRecord.zone_id == ACMEAccount.zone_id,
                DNSRecord.name == ACMEAccount.subdomain,
            ),
        )
        .where(
            DNSRecord.record_type == "TXT",
            DNSRecord.auto_generated.is_(True),
            DNSRecord.created_at < cutoff,
        )
    )
    rows = (await db.execute(stmt)).all()
    deleted = 0
    for rec, account in rows:
        zone = await db.get(DNSZone, rec.zone_id)
        if zone is None:
            continue
        target_serial = bump_zone_serial(zone)
        await db.execute(delete(DNSRecord).where(DNSRecord.id == rec.id))
        await enqueue_record_op(
            db,
            zone,
            "delete",
            {
                "name": rec.name,
                "type": "TXT",
                "value": rec.value,
                "ttl": rec.ttl or ACME_TXT_TTL,
            },
            target_serial=target_serial,
        )
        deleted += 1
        log.info(
            "acme_txt_swept",
            account_id=str(account.id),
            zone=zone.name,
            subdomain=account.subdomain,
            age_hours=(datetime.now(UTC) - rec.created_at).total_seconds() / 3600,
        )
    if deleted:
        await db.commit()
    return deleted


__all__ = [
    "APPLY_TIMEOUT_MARGIN_SECONDS",
    "DEFAULT_APPLY_TIMEOUT_SECONDS",
    "MAX_APPLY_TIMEOUT_SECONDS",
    "PROVIDER_MAX_APPLY_TIMEOUT_SECONDS",
    "ACMEApplyFailed",
    "ACMEApplyTimeout",
    "ACMEAuthError",
    "ACMEError",
    "ACMESubdomainMismatch",
    "ACME_TXT_TTL",
    "MAX_TXT_VALUES_PER_SUBDOMAIN",
    "apply_timeout_for",
    "apply_txt_delete",
    "apply_txt_update",
    "authenticate",
    "client_ip_allowed",
    "fulldomain_of",
    "register_account",
    "sweep_stale_txt_records",
    "wait_for_op_applied",
    "wait_for_ops_applied",
]
