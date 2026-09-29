"""End-to-end DNS-01 issuance orchestrator (issue #438 Phase 1).

Drives one :class:`~app.models.acme_client.ACMEOrder` from ``pending`` to
``valid`` (or ``invalid``):

1. load the order + its account, decrypt the account key;
2. ensure the ACME account exists at the CA (caching the account URL);
3. create the order, fetch authorizations;
4. for each authorization, solve the ``dns-01`` challenge by writing a
   ``_acme-challenge`` TXT into the matching managed zone, tell the CA
   it's ready, and poll the authorization to ``valid``;
5. generate a fresh cert key + CSR, finalize the order, poll to
   ``valid``, download the full PEM chain;
6. land the chain in an :class:`~app.models.appliance.ApplianceCertificate`
   row (``source="letsencrypt"``), make it the sole active cert, deploy
   it to nginx (tolerating deploy failure);
7. ALWAYS clean up every challenge TXT in a ``finally`` block.

The whole thing is idempotent + re-runnable: a re-run from any state
re-derives what it needs. Called from the Celery task
``app.tasks.acme.run_acme_order``.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

import httpx
import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_csr
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_str, encrypt_str
from app.db import AsyncSessionLocal
from app.models.acme_client import (
    ACME_CHALLENGE_HTTP01,
    ACME_ORDER_INVALID,
    ACME_ORDER_PROCESSING,
    ACME_ORDER_VALID,
    ACMEClientAccount,
    ACMEOrder,
)
from app.models.appliance import (
    CERT_SOURCE_LETSENCRYPT,
    ApplianceCertificate,
)
from app.models.audit import AuditLog
from app.services.acme_client import dns01, http01
from app.services.acme_client.engine import ACMEClient, ACMEProtocolError
from app.services.appliance.deployment import deploy_and_reload
from app.services.appliance.tls import (
    CSRSubject,
    generate_csr_and_key,
    parse_pem_certificate,
)
from app.services.dns.cert_rotation import wake_dns_groups_serving_cert

logger = structlog.get_logger(__name__)

# The cert key type the finalize CSR is generated with. EC-P256 is the
# modern default LE accepts and produces the smallest handshakes; an
# operator who needs RSA can be given a knob later — Phase 1 hardcodes.
_CERT_KEY_TYPE = "ec-p256"


async def run_order(db: AsyncSession, order_id: uuid.UUID | str) -> str:
    """Drive a single ACME order to completion.

    Returns the terminal order status (``"valid"`` / ``"invalid"``).
    Persists ``last_error`` on failure. Never raises for a normal
    protocol/DNS failure — those are recorded on the order row so the
    UI can surface them; only genuinely unexpected errors propagate
    (so Celery can log + retry).

    The passed ``db`` session is used for the cert + order bookkeeping;
    the DNS-01 solver opens / commits through the same session so the
    TXT record lands before we tell the CA to validate.
    """
    oid = order_id if isinstance(order_id, uuid.UUID) else uuid.UUID(str(order_id))
    order = await db.get(ACMEOrder, oid)
    if order is None:
        logger.warning("acme_client_order_missing", order_id=str(oid))
        return ACME_ORDER_INVALID
    if order.status in (ACME_ORDER_VALID, ACME_ORDER_INVALID):
        # Terminal — already issued, or cancelled/failed. Don't reprocess
        # (a duplicate dispatch, or a worker picking up an order the
        # operator cancelled before it started). Transient retries leave
        # the order ``processing`` (see the httpx handler below), so they
        # fall through here and re-converge.
        return order.status

    account = await db.get(ACMEClientAccount, order.account_id)
    if account is None:
        return await _fail(db, oid, "ACME account row not found")

    order.status = ACME_ORDER_PROCESSING
    order.last_error = None
    await db.commit()

    handles: list[dns01.DNS01Handle] = []
    try:
        account_key_pem = decrypt_str(account.account_key_encrypted)
        eab_hmac_b64 = (
            decrypt_str(account.eab_hmac_encrypted) if account.eab_hmac_encrypted else None
        )

        async with ACMEClient(
            account.directory_url,
            account_key_pem,
            account_url=account.account_url,
            eab_kid=account.eab_kid,
            eab_hmac_b64=eab_hmac_b64,
        ) as client:
            # 1. account
            account_url = await client.ensure_account(email=account.email)
            if account_url != account.account_url:
                account.account_url = account_url
                await db.commit()

            # 2. order — reuse a still-usable persisted order on a retry
            #    rather than minting a fresh one each time (idempotency,
            #    non-negotiable #9: a new order per retry orphans the prior
            #    one and burns the account's new-order rate limit). Only
            #    PRE-finalize orders (``pending``/``ready``) are reused: a
            #    ``processing``/``valid`` order was finalized with a cert
            #    key we generate fresh each run and never persist, so its
            #    issued cert wouldn't match our new key — mint fresh then.
            ca_order: dict | None = None
            if order.order_url:
                try:
                    existing = await client.get_order(order.order_url)
                    if existing.get("status") in ("pending", "ready"):
                        ca_order = existing
                except ACMEProtocolError:
                    ca_order = None  # stale / expired at the CA — mint fresh
            if ca_order is None:
                ca_order = await client.new_order(order.domains)
                order.order_url = ca_order["url"]
                order.finalize_url = ca_order.get("finalize")
                await db.commit()

            # 3. authorizations → solve each challenge by type. http-01
            #    publishes a token the well-known endpoint serves; dns-01
            #    writes a TXT into a managed zone (incl. cloud-hosted via
            #    the agentless drivers) or, for an unmanaged domain with
            #    allow_manual, asks the operator to add the TXT.
            authzs = await client.get_authorizations(ca_order)
            ready_challenge_urls: list[str] = []
            manual_pending: list[dict[str, str]] = []
            if order.challenge_type == ACME_CHALLENGE_HTTP01:
                for authz in authzs:
                    if authz.get("status") == "valid":
                        continue
                    challenge, key_auth = client.get_http01_challenge(authz)
                    await http01.publish(db, oid, challenge.token, key_auth)
                    ready_challenge_urls.append(challenge.url)
                if ready_challenge_urls:
                    # Make the tokens servable before telling the CA to fetch.
                    await db.commit()
            else:
                for authz in authzs:
                    if authz.get("status") == "valid":
                        # Already validated (re-run / wildcard reuse) — skip.
                        continue
                    challenge, _key_auth, txt_value = client.get_dns01_challenge(authz)
                    if await dns01.resolve_managed(db, challenge.identifier) is not None:
                        handle = await dns01.solve(db, challenge.identifier, txt_value)
                        handles.append(handle)
                        ready_challenge_urls.append(challenge.url)
                    elif order.allow_manual:
                        manual_pending.append(
                            {
                                "fqdn": challenge.identifier,
                                "record_name": dns01.challenge_fqdn(challenge.identifier),
                                "txt_value": txt_value,
                                "challenge_url": challenge.url,
                            }
                        )
                    else:
                        raise dns01.DNS01SolveError(
                            f"no SpatiumDDI-managed zone covers {challenge.identifier!r} and "
                            f"manual DNS-01 was not enabled for this order"
                        )

                # 3b. manual fallback: publish the required TXTs on the order
                #     so the UI can show them, then wait for the operator to
                #     add them at their own provider before signalling the CA.
                if manual_pending:
                    order.manual_challenges = [
                        {
                            "fqdn": m["fqdn"],
                            "record_name": m["record_name"],
                            "txt_value": m["txt_value"],
                        }
                        for m in manual_pending
                    ]
                    await db.commit()
                    for m in manual_pending:
                        if not await dns01.poll_public_txt(m["record_name"], m["txt_value"]):
                            raise dns01.DNS01SolveError(
                                f"timed out waiting for the manual TXT record "
                                f"{m['record_name']!r} to appear in public DNS"
                            )
                    ready_challenge_urls.extend(m["challenge_url"] for m in manual_pending)

            # 4. tell the CA every published challenge is ready, then poll
            #    each authorization to valid.
            for ch_url in ready_challenge_urls:
                await client.tell_ready(ch_url)
            for authz in authzs:
                if authz.get("status") == "valid":
                    continue
                await client.poll_authorization(authz["url"])

            # Manual TXTs served their purpose — clear them off the order.
            if manual_pending:
                order.manual_challenges = []
                await db.commit()

            # 5. finalize: fresh cert key + CSR (DER for the CA). Use the
            #    first non-wildcard domain as the subject CN — a wildcard
            #    CN ("*.example.com") trips strict non-LE / private CAs
            #    that enforce a CN policy; LE itself ignores the CN (SANs
            #    are authoritative), so this is a no-op there.
            cn = next((d for d in order.domains if not d.startswith("*.")), order.domains[0])
            subject = CSRSubject(common_name=cn)
            csr_pem, cert_key_pem = generate_csr_and_key(
                subject, list(order.domains), _CERT_KEY_TYPE
            )
            csr_der = load_pem_x509_csr(csr_pem.encode("utf-8")).public_bytes(
                serialization.Encoding.DER
            )
            order_url = ca_order["url"]
            ready_order = await client.poll_order(order_url, until=("ready",))
            finalized = await client.finalize(ready_order, csr_der)
            valid_order = await client.poll_order(
                finalized.get("url") or order_url, until=("valid",)
            )

            # 6. download + land the chain
            chain_pem = await client.download_certificate(valid_order)

        # Respect an operator cancel that landed while we were issuing:
        # cancel_order sets status=invalid in a separate session, so
        # re-read the committed value before we deploy + activate. This
        # narrows (does not fully close) the cancel race — a row-version
        # guard would be needed to eliminate the final micro-window.
        await db.refresh(order)
        if order.status == ACME_ORDER_INVALID:
            logger.warning("acme_client_order_cancelled_midflight", order_id=str(oid))
            return ACME_ORDER_INVALID

        cert_row = await _store_certificate(db, order, chain_pem, cert_key_pem)
        order.status = ACME_ORDER_VALID
        order.certificate_id = cert_row.id
        order.last_error = None
        await db.commit()
        logger.info(
            "acme_client_order_valid",
            order_id=str(order.id),
            domains=order.domains,
            cert_id=str(cert_row.id),
        )
        return ACME_ORDER_VALID

    except ACMEProtocolError as exc:
        return await _fail(db, oid, str(exc))
    except dns01.DNS01SolveError as exc:
        return await _fail(db, oid, str(exc))
    except httpx.TransportError as exc:
        # Transient network blip talking to the CA. Do NOT mark the order
        # terminally ``invalid`` — leave it ``processing`` and re-raise so
        # the Celery task autoretries (httpx.TransportError is in its
        # autoretry_for); the retry reuses the persisted order (above).
        logger.warning("acme_client_transient_ca_error", order_id=str(oid), error=str(exc))
        raise
    except Exception as exc:  # noqa: BLE001 — record + re-raise for Celery retry
        await _fail(db, oid, f"unexpected: {exc}")
        raise
    finally:
        # Always tear down challenge TXT records — they're useless after
        # validation and would accumulate as zone noise otherwise. Each
        # cleanup opens its own fresh session so a failed primary session
        # (rolled back) doesn't block the teardown.
        for handle in handles:
            try:
                async with AsyncSessionLocal() as cleanup_db:
                    await dns01.cleanup(cleanup_db, handle)
            except Exception as exc:  # noqa: BLE001 — best-effort teardown
                logger.warning(
                    "acme_client_cleanup_failed",
                    fqdn=handle.challenge_fqdn,
                    error=str(exc),
                )
        # http-01 token rows are useless after validation — sweep them too.
        try:
            async with AsyncSessionLocal() as cleanup_db:
                await http01.cleanup(cleanup_db, oid)
                await cleanup_db.commit()
        except Exception as exc:  # noqa: BLE001 — best-effort teardown
            logger.warning("acme_client_http01_cleanup_failed", order_id=str(oid), error=str(exc))


async def _fail(db: AsyncSession, order_id: uuid.UUID, message: str) -> str:
    """Persist an ``invalid`` order with ``last_error`` + commit.

    Takes the order's id as a plain value (not the ORM instance): the
    ``rollback`` below expires every instance, so re-reading the row by
    id is the only safe way to touch it afterwards (accessing an expired
    ORM attribute would trigger a sync lazy-load under async and raise).
    """
    try:
        await db.rollback()
    except Exception:  # noqa: BLE001 — already-clean session
        pass
    try:
        fresh = await db.get(ACMEOrder, order_id)
        if fresh is not None:
            fresh.status = ACME_ORDER_INVALID
            fresh.last_error = message[:2000]
            await db.commit()
    except Exception as exc:  # noqa: BLE001 — a secondary DB error here must
        # not mask the original failure the caller is about to re-raise.
        logger.warning("acme_client_fail_persist_failed", order_id=str(order_id), error=str(exc))
    logger.warning("acme_client_order_invalid", order_id=str(order_id), error=message)
    return ACME_ORDER_INVALID


async def _store_certificate(
    db: AsyncSession,
    order: ACMEOrder,
    chain_pem: str,
    key_pem: str,
) -> ApplianceCertificate:
    """Create (or reuse) the ApplianceCertificate row for an issued chain.

    Idempotent on the order's stable name: a re-run for the same order
    updates the existing row in place rather than colliding on the
    unique ``name``. The row is made the sole active cert and deployed
    to nginx (deploy failure logged, never raised).
    """
    info = parse_pem_certificate(chain_pem)
    name = f"letsencrypt-{order.id}"

    row = None
    if order.certificate_id is not None:
        row = await db.get(ApplianceCertificate, order.certificate_id)
    if row is None:
        # Re-run with no prior cert pointer — look up by our stable name.
        row = (
            await db.execute(select(ApplianceCertificate).where(ApplianceCertificate.name == name))
        ).scalar_one_or_none()

    if row is None:
        row = ApplianceCertificate(
            name=name,
            source=CERT_SOURCE_LETSENCRYPT,
            cert_pem=chain_pem,
            key_encrypted=encrypt_str(key_pem),
            is_active=False,
            subject_cn=info.subject_cn,
            sans_json=info.sans,
            issuer_cn=info.issuer_cn,
            fingerprint_sha256=info.fingerprint_sha256,
            valid_from=info.valid_from,
            valid_to=info.valid_to,
            notes=f"Issued via ACME DNS-01 for: {', '.join(order.domains)}",
        )
        db.add(row)
    else:
        row.source = CERT_SOURCE_LETSENCRYPT
        row.cert_pem = chain_pem
        row.key_encrypted = encrypt_str(key_pem)
        row.subject_cn = info.subject_cn
        row.sans_json = info.sans
        row.issuer_cn = info.issuer_cn
        row.fingerprint_sha256 = info.fingerprint_sha256
        row.valid_from = info.valid_from
        row.valid_to = info.valid_to
    await db.flush()

    await _make_sole_active(db, row)
    # Audit the serving-cert swap (non-negotiable #4). This runs off the
    # request thread in the Celery worker, so there is no operator actor —
    # record it as a system action (mirrors the scheduled-task audit
    # pattern). The earlier acme_issue audit only recorded the *request*.
    db.add(
        AuditLog(
            user_id=None,
            user_display_name="system",
            auth_source="system",
            action="activate",
            resource_type="appliance_certificate",
            resource_id=str(row.id),
            resource_display=row.name,
            new_value={
                "source": CERT_SOURCE_LETSENCRYPT,
                "subject_cn": row.subject_cn,
                "valid_to": row.valid_to.isoformat() if row.valid_to else None,
                "via": "acme_dns01",
                "order_id": str(order.id),
            },
            result="success",
        )
    )
    await db.commit()
    await db.refresh(row)

    # Deploy + reload — tolerate failure (DB is the source of truth; the
    # api boot's ensure_self_signed_cert re-deploys the active row). Run
    # the blocking kubeapi PATCH/roll off the event loop (non-negotiable
    # #2 — deploy_and_reload makes synchronous http.client round-trips).
    try:
        await asyncio.to_thread(
            deploy_and_reload, row.cert_pem or chain_pem, key_pem, name=row.name
        )
    except Exception as exc:  # noqa: BLE001 — never let a deploy hiccup fail issuance
        logger.warning("acme_client_cert_deploy_failed", cert_id=str(row.id), error=str(exc))

    # #50 — a renewal rewrites cert_pem in place, so any DoT/DoH listener
    # serving this row needs to pick up the new material.
    await wake_dns_groups_serving_cert(db, row.id)

    return row


async def _make_sole_active(db: AsyncSession, target: ApplianceCertificate) -> None:
    """Flip ``is_active`` true on ``target``, false on everyone else.

    Replicates the router's ``_activate_only`` invariant (at most one
    active row) without importing from the router layer.
    """
    tzinfo = target.valid_to.tzinfo if target.valid_to else UTC
    await db.execute(
        update(ApplianceCertificate)
        .where(ApplianceCertificate.id != target.id)
        .values(is_active=False)
    )
    target.is_active = True
    target.activated_at = datetime.now(tz=tzinfo)


__all__ = ["run_order"]
