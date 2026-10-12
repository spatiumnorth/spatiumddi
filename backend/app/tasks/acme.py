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
Celery retry here re-converges from whatever state the order is in. A
network error to the CA is retried here too; the last attempt tells the
orchestrator so, and it then ends the order instead of re-raising (#1686).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

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
def run_acme_order(self: Any, order_id: str) -> str:  # type: ignore[type-arg]
    # Once ``max_retries`` retries have run, Celery re-raises the error
    # instead of retrying, so this attempt is the last: tell the
    # orchestrator, which then ends the order on a network error rather
    # than leave it ``processing`` for a retry that never comes (#1686).
    final_attempt = self.max_retries is not None and self.request.retries >= self.max_retries
    return asyncio.run(_run(order_id, final_attempt=final_attempt))


async def _run(order_id: str, *, final_attempt: bool = False) -> str:
    async with task_session() as session:
        try:
            status = await run_order(session, order_id, final_attempt=final_attempt)
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

    Idempotent + advisory-locked. Creates a fresh ACMEOrder per due cert
    reusing THAT cert's issuance shape (#1529 — the challenge type,
    provider and domains of the successful order that produced it) and
    enqueues ``run_acme_order``; skips any cert that already has an
    in-flight order for the same domains. A shape that cannot be renewed
    without a person (manual DNS-01 for unmanaged domains) is skipped
    and alerted on instead of minting an order that can never succeed.
    Gated on ``acme_enabled`` + ``acme_auto_renew``.
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
        skipped_manual = 0
        for cert in due:
            # #1529: reuse THIS cert's issuance shape (challenge type,
            # provider, domains) from the successful order that produced
            # it — not a single global shape. Previously every cert was
            # renewed as managed-zone dns-01 with the global
            # ``acme_domains``, so http-01 certs never renewed and a
            # failed issue attempt could retarget the renewal domains.
            domains, challenge_type, dns_provider, allow_manual = await _issuance_shape(
                db, cert, settings
            )
            if not domains:
                continue
            if challenge_type == "dns-01" and allow_manual:
                # The original order allowed the manual TXT fallback.
                # It can still renew unattended if every domain's
                # challenge is covered by a managed zone today;
                # otherwise it needs a person — skip + alert instead of
                # creating an order that cannot succeed.
                from app.services.acme_client import dns01  # noqa: PLC0415

                uncovered = [d for d in domains if await dns01.resolve_managed(db, d) is None]
                if uncovered:
                    await _emit_manual_renewal_alert(db, cert, domains, uncovered)
                    skipped_manual += 1
                    continue
                allow_manual = False  # fully managed — plain dns-01 renewal
            if frozenset(domains) in inflight_domainsets:
                continue  # already being (re)issued
            order = ACMEOrder(
                account_id=account.id,
                domains=domains,
                challenge_type=challenge_type,
                dns_provider=dns_provider,
                status="pending",
                allow_manual=False,
            )
            db.add(order)
            await db.flush()
            new_order_ids.append(str(order.id))
            inflight_domainsets.append(frozenset(domains))
            await _resolve_manual_renewal_alerts(db, cert)

        await db.commit()  # persist orders + release the advisory lock

    for oid in new_order_ids:
        run_acme_order.delay(oid)
    logger.info(
        "acme_client_renew_sweep", renewed=len(new_order_ids), skipped_manual=skipped_manual
    )
    result = f"renewed={len(new_order_ids)}"
    if skipped_manual:
        result += f" skipped_manual={skipped_manual}"
    return result


# ── #1529: per-certificate issuance shape + manual-renewal alert ────

# Name of the seeded singleton rule the sweep opens skip events against
# (mirrors ``app.services.alerts._ACME_MANUAL_RENEWAL_RULE_NAME``).
_ACME_MANUAL_RENEWAL_RULE_NAME = "acme-manual-renewal"


async def _issuance_shape(db, cert, settings):  # type: ignore[no-untyped-def]
    """The issuance shape to renew ``cert`` with (#1529).

    Returns ``(domains, challenge_type, dns_provider, allow_manual)``.
    The source of truth is the successful order that produced this cert
    (``ACMEOrder.certificate_id`` → ``status='valid'``, newest first) —
    the shape is stored per successful order, not globally. Certs with
    no linked order (issued before the link existed) fall back to the
    settings recorded by the last successful order, then to the cert's
    own SANs as managed-zone dns-01.
    """
    from app.models.acme_client import ACME_ORDER_VALID, ACMEOrder  # noqa: PLC0415

    order = (
        await db.execute(
            select(ACMEOrder)
            .where(
                ACMEOrder.certificate_id == cert.id,
                ACMEOrder.status == ACME_ORDER_VALID,
            )
            .order_by(ACMEOrder.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if order is not None:
        return (
            list(order.domains),
            order.challenge_type,
            order.dns_provider,
            bool(order.allow_manual),
        )
    domains = list(settings.acme_domains or []) or list(cert.sans_json or [])
    return domains, settings.acme_challenge_type or "dns-01", settings.acme_dns_provider, False


async def _emit_manual_renewal_alert(db, cert, domains, uncovered) -> None:  # type: ignore[no-untyped-def]
    """Open (deduped) an ``acme-manual-renewal`` event for a skipped cert.

    No-ops when the rule hasn't been seeded yet or the operator disabled
    it — the skip itself is still logged by the caller. Caller commits.
    """
    from app.models.alerts import AlertEvent, AlertRule  # noqa: PLC0415

    rule = (
        await db.execute(select(AlertRule).where(AlertRule.name == _ACME_MANUAL_RENEWAL_RULE_NAME))
    ).scalar_one_or_none()
    if rule is None or not rule.enabled:
        logger.warning(
            "acme_manual_renewal_alert_skipped_no_rule",
            cert_id=str(cert.id),
            rule_present=rule is not None,
        )
        return
    existing = (
        await db.execute(
            select(AlertEvent)
            .where(
                AlertEvent.rule_id == rule.id,
                AlertEvent.subject_id == str(cert.id),
                AlertEvent.resolved_at.is_(None),
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return  # one open event per cert — don't re-page every 12 h
    db.add(
        AlertEvent(
            rule_id=rule.id,
            subject_type="appliance_certificate",
            subject_id=str(cert.id),
            subject_display=cert.name,
            severity=rule.severity,
            message=(
                f"Let's Encrypt certificate {cert.name!r} "
                f"({', '.join(domains)}) is inside its renewal window but "
                f"cannot be auto-renewed: it was issued with manual DNS-01 "
                f"and no SpatiumDDI-managed zone covers "
                f"{', '.join(uncovered)}. Renew it by hand (issue a fresh "
                f"certificate and add the TXT records at your DNS provider) "
                f"before it expires"
                + (f" on {cert.valid_to:%Y-%m-%d}" if cert.valid_to else "")
                + "."
            ),
            fired_at=datetime.now(UTC),
            last_observed_value={
                "domains": list(domains),
                "uncovered_domains": list(uncovered),
                "valid_to": cert.valid_to.isoformat() if cert.valid_to else None,
            },
        )
    )
    logger.info("acme_manual_renewal_alert_opened", cert_id=str(cert.id), domains=list(domains))


async def _resolve_manual_renewal_alerts(db, cert) -> None:  # type: ignore[no-untyped-def]
    """Resolve any open ``acme-manual-renewal`` events for ``cert``.

    Called when the sweep successfully enqueues a renewal for the cert
    (its shape became renewable, e.g. a managed zone now covers it, or
    the operator re-issued it in an auto-renewable shape). Caller commits.
    """
    from app.models.alerts import AlertEvent, AlertRule  # noqa: PLC0415

    rule = (
        await db.execute(select(AlertRule).where(AlertRule.name == _ACME_MANUAL_RENEWAL_RULE_NAME))
    ).scalar_one_or_none()
    if rule is None:
        return
    open_events = (
        (
            await db.execute(
                select(AlertEvent).where(
                    AlertEvent.rule_id == rule.id,
                    AlertEvent.subject_id == str(cert.id),
                    AlertEvent.resolved_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    for evt in open_events:
        evt.resolved_at = datetime.now(UTC)


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
