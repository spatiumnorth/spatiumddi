"""Celery entry points for the embedded ACME client (issue #438).

* :func:`run_acme_order` (Phase 1) wraps the orchestrator so a
  ``POST /api/v1/appliance/acme/issue`` can fire-and-forget the (slow,
  network-bound) DNS-01 issuance flow off the request thread.
* :func:`renew_due_certificates` (Phase 2) is the 12 h beat task that
  re-issues active Let's Encrypt Web-UI certs nearing expiry.
* :func:`sweep_stale_acme_txt_records` is the hourly beat task that runs
  the stale-TXT janitor (#1530) — it previously had no caller at all.

The orchestrator is idempotent + re-runnable — it records normal
protocol / DNS failures on the order row (``status='invalid'`` +
``last_error``) and only re-raises genuinely unexpected errors, so a
Celery retry here re-converges from whatever state the order is in.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import httpx
import structlog
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError

from app.celery_app import celery_app
from app.db import task_session
from app.services.acme_client.orchestrator import run_order

logger = structlog.get_logger(__name__)

# Renew active Let's Encrypt certs once they're within this window of
# expiry (LE certs are 90 d; 30 d is the conventional renewal lead).
_RENEW_WINDOW_DAYS = 30
# Session-stable advisory-lock key so only one renewal sweep runs at a
# time across api/worker replicas (released on connection close).
_RENEW_LOCK_KEY = 0x53504D52454E  # "SPMREN"-ish


@celery_app.task(
    name="app.tasks.acme.run_acme_order",
    bind=True,
    # Autoretry only on transient DB / network classes — a protocol or
    # DNS failure is already recorded on the order as ``invalid`` by the
    # orchestrator (which returns normally), so it never reaches here.
    # ``httpx.TransportError`` (ConnectError / ConnectTimeout / ReadTimeout)
    # covers transient blips to the CA — these are NOT subclasses of
    # ConnectionError/OSError, so they must be listed explicitly or a
    # single network hiccup would permanently fail the order.
    autoretry_for=(SQLAlchemyError, ConnectionError, OSError, httpx.TransportError),
    retry_backoff=True,
    retry_backoff_max=60,
    retry_jitter=True,
    max_retries=3,
)
def run_acme_order(self: object, order_id: str) -> str:  # type: ignore[type-arg]
    return asyncio.run(_run(order_id))


async def _run(order_id: str) -> str:
    async with task_session() as session:
        try:
            status = await run_order(session, order_id)
            logger.info("acme_client_task_done", order_id=order_id, status=status)
            return status
        except Exception as exc:  # noqa: BLE001 — let Celery autoretry / capture
            logger.exception("acme_client_task_failed", order_id=order_id, error=str(exc))
            raise


@celery_app.task(
    name="app.tasks.acme.renew_due_certificates",
    bind=True,
    autoretry_for=(SQLAlchemyError, ConnectionError, OSError),
    retry_backoff=True,
    max_retries=2,
)
def renew_due_certificates(self: object) -> str:  # type: ignore[type-arg]
    """Beat task: re-issue active LE Web-UI certs within the renewal window.

    Idempotent + advisory-locked. Creates a fresh ACMEOrder (DNS-01,
    managed-zone only) per due cert and enqueues ``run_acme_order``;
    skips any cert that already has an in-flight order for the same
    domains. Gated on ``acme_enabled`` + ``acme_auto_renew``.
    """
    return asyncio.run(_renew())


async def _renew() -> str:
    from app.models.acme_client import ACMEClientAccount, ACMEOrder
    from app.models.appliance import CERT_SOURCE_LETSENCRYPT, ApplianceCertificate
    from app.models.settings import PlatformSettings

    async with task_session() as db:
        # Serialise across replicas — session-scoped lock, freed on close.
        got = (
            await db.execute(text("select pg_try_advisory_lock(:k)"), {"k": _RENEW_LOCK_KEY})
        ).scalar()
        if not got:
            return "locked"

        settings = await db.get(PlatformSettings, 1)
        if settings is None or not settings.acme_enabled or not settings.acme_auto_renew:
            return "disabled"
        account = (
            await db.execute(
                select(ACMEClientAccount).order_by(ACMEClientAccount.created_at.desc()).limit(1)
            )
        ).scalar_one_or_none()
        if account is None:
            return "no-account"

        now = datetime.now(UTC)
        cutoff = now + timedelta(days=_RENEW_WINDOW_DAYS)
        due = (
            (
                await db.execute(
                    select(ApplianceCertificate).where(
                        ApplianceCertificate.source == CERT_SOURCE_LETSENCRYPT,
                        ApplianceCertificate.is_active.is_(True),
                        ApplianceCertificate.valid_to.is_not(None),
                        ApplianceCertificate.valid_to <= cutoff,
                    )
                )
            )
            .scalars()
            .all()
        )
        if not due:
            return "none-due"

        inflight = (
            (
                await db.execute(
                    select(ACMEOrder).where(ACMEOrder.status.in_(("pending", "processing")))
                )
            )
            .scalars()
            .all()
        )
        inflight_domainsets = [frozenset(o.domains) for o in inflight]

        new_order_ids: list[str] = []
        for cert in due:
            # Prefer the operator-recorded issuance shape; fall back to the
            # cert's own SANs. Auto-renewal is managed-zone only (no manual).
            domains = list(settings.acme_domains or []) or list(cert.sans_json or [])
            if not domains:
                continue
            if frozenset(domains) in inflight_domainsets:
                continue  # already being (re)issued
            order = ACMEOrder(
                account_id=account.id,
                domains=domains,
                challenge_type="dns-01",
                status="pending",
                allow_manual=False,
            )
            db.add(order)
            await db.flush()
            new_order_ids.append(str(order.id))
            inflight_domainsets.append(frozenset(domains))

        await db.commit()  # persist orders + release the advisory lock

    for oid in new_order_ids:
        run_acme_order.delay(oid)
    logger.info("acme_client_renew_sweep", renewed=len(new_order_ids))
    return f"renewed={len(new_order_ids)}"


@celery_app.task(
    name="app.tasks.acme.sweep_stale_acme_txt_records",
    bind=True,
    autoretry_for=(SQLAlchemyError, ConnectionError, OSError),
    retry_backoff=True,
    max_retries=2,
)
def sweep_stale_acme_txt_records(self: object) -> str:  # type: ignore[type-arg]
    """Beat task: delete stale ACME TXT records older than 24 h (#1530).

    Covers both the provider path (acme-dns account subdomains) and the
    embedded-client path (``_acme-challenge`` records a crashed solve
    left behind). Runs ``services.acme.sweep_stale_txt_records``, which
    had no caller before this task existed.
    """
    return asyncio.run(_sweep_stale_txt())


async def _sweep_stale_txt() -> str:
    from app.services.acme import sweep_stale_txt_records

    async with task_session() as db:
        deleted = await sweep_stale_txt_records(db)
    logger.info("acme_stale_txt_sweep", deleted=deleted)
    return f"swept={deleted}"
