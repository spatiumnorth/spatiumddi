"""Embedded ACME *client* — Let's Encrypt issuance surface (issue #438 Phase 1).

Mounted at ``/api/v1/appliance/acme`` behind the ``security.certificates``
feature module (404 when the module is off). SpatiumDDI acts as an ACME
client against a public CA (Let's Encrypt), driving the RFC 8555 DNS-01
flow over its OWN managed DNS zones to issue a CA-trusted cert for the
appliance Web UI. The issued chain lands in the existing
``ApplianceCertificate`` storage + deploy path with ``source="letsencrypt"``.

Two persistence surfaces:

* ``ACMEClientAccount`` — the operator's ACME account at the CA (account
  key Fernet-encrypted at rest, NEVER returned). One per install in the
  common case; ``GET/PUT/DELETE /account`` manage it.
* ``ACMEOrder`` — one issuance attempt. ``POST /issue`` creates it
  (``pending``) + enqueues the Celery task that drives the flow; reads
  surface its status + ``last_error``.

Mutations require ``admin`` on ``appliance``; reads accept ``read``.
Secret material (account key, EAB HMAC) NEVER leaves the server — the
account responses expose only an ``eab_hmac_set`` boolean. Every mutation
is audited (mirrors ``appliance/tls.py``).
"""

from __future__ import annotations

import uuid
from datetime import datetime

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import DB, CurrentUser
from app.core.crypto import encrypt_str
from app.core.permissions import require_permission
from app.models.acme_client import (
    ACME_CHALLENGE_DNS01,
    ACME_CHALLENGE_HTTP01,
    ACME_CHALLENGE_TLSALPN01,
    ACME_ORDER_PENDING,
    ACME_ORDER_PROCESSING,
    ACMEClientAccount,
    ACMEOrder,
)
from app.models.audit import AuditLog
from app.models.settings import PlatformSettings

logger = structlog.get_logger(__name__)

router = APIRouter()


# ── Response shapes ─────────────────────────────────────────────────


class ACMEAccountSummary(BaseModel):
    """ACME account metadata — NEVER the account key or EAB HMAC.

    ``eab_hmac_set`` is the only signal the UI gets about EAB material:
    a boolean, never the secret itself (mirrors the cert ``key`` and
    SNMP-community reveal-gating pattern).
    """

    id: uuid.UUID
    directory_url: str
    account_url: str | None
    email: str | None
    eab_kid: str | None
    eab_hmac_set: bool
    created_at: datetime
    modified_at: datetime


class ACMEOrderSummary(BaseModel):
    id: uuid.UUID
    domains: list[str]
    challenge_type: str
    dns_provider: str | None
    status: str
    order_url: str | None
    finalize_url: str | None
    certificate_id: uuid.UUID | None
    last_error: str | None
    allow_manual: bool
    # While ``processing`` a manual order, the TXT records the operator
    # must add at their own DNS provider: [{fqdn, record_name, txt_value}].
    manual_challenges: list[dict]
    created_at: datetime
    modified_at: datetime


def _account_summary(row: ACMEClientAccount) -> ACMEAccountSummary:
    return ACMEAccountSummary(
        id=row.id,
        directory_url=row.directory_url,
        account_url=row.account_url,
        email=row.email,
        eab_kid=row.eab_kid,
        eab_hmac_set=row.eab_hmac_encrypted is not None,
        created_at=row.created_at,
        modified_at=row.modified_at,
    )


def _order_summary(row: ACMEOrder) -> ACMEOrderSummary:
    return ACMEOrderSummary(
        id=row.id,
        domains=list(row.domains),
        challenge_type=row.challenge_type,
        dns_provider=row.dns_provider,
        status=row.status,
        order_url=row.order_url,
        finalize_url=row.finalize_url,
        certificate_id=row.certificate_id,
        last_error=row.last_error,
        allow_manual=row.allow_manual,
        manual_challenges=list(row.manual_challenges or []),
        created_at=row.created_at,
        modified_at=row.modified_at,
    )


# ── Request bodies ──────────────────────────────────────────────────


class ACMEAccountUpsert(BaseModel):
    # The ACME directory URL the account lives at. Validated https://
    # at the handler — http/unschemed is rejected so a misconfigured
    # directory can't smuggle account-key JWS over cleartext.
    directory_url: str = Field(min_length=1, max_length=2000)
    email: str | None = Field(default=None, max_length=255)
    # External Account Binding — only for CAs that require it (ZeroSSL,
    # some private CAs). Both NULL/omitted for Let's Encrypt. The HMAC
    # is write-only: supply it to set/replace, omit to leave unchanged.
    eab_kid: str | None = Field(default=None, max_length=255)
    eab_hmac_b64: str | None = Field(default=None, max_length=2000)


class ACMEIssueRequest(BaseModel):
    domains: list[str] = Field(min_length=1, max_length=100)
    challenge_type: str = Field(default=ACME_CHALLENGE_DNS01)
    # NULL = default path (SpatiumDDI's own managed zones via record_ops,
    # incl. cloud-hosted zones served through the agentless drivers).
    dns_provider: str | None = Field(default=None, max_length=64)
    # Phase 3: allow the manual DNS-01 fallback for domains whose zone
    # SpatiumDDI does NOT manage (operator adds the TXT at their own
    # provider; the order waits, showing the record, until it appears).
    allow_manual: bool = Field(default=False)


class ACMEDomainResolution(BaseModel):
    """How one requested domain's dns-01 challenge would be solved."""

    domain: str
    challenge_fqdn: str
    managed: bool  # True → SpatiumDDI writes the TXT automatically
    zone_name: str | None  # the managed zone that covers it (if any)
    record_name: str | None  # relative TXT label inside that zone
    driver: str | None  # bind9 / powerdns / cloudflare / route53 / ...
    # Set when the choice is worth a second look, e.g. a more specific
    # internal zone also covers the name and was skipped (#1454).
    note: str | None = None


class ACMEPreviewRequest(BaseModel):
    domains: list[str] = Field(min_length=1, max_length=100)


def _require_https(directory_url: str) -> str:
    cleaned = directory_url.strip()
    if not cleaned.lower().startswith("https://"):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "directory_url must be an https:// URL",
        )
    return cleaned


async def _get_account(db: DB) -> ACMEClientAccount | None:
    """Return the single ACME account row (most-recent if duplicates)."""
    return (
        await db.execute(
            select(ACMEClientAccount).order_by(ACMEClientAccount.created_at.desc()).limit(1)
        )
    ).scalar_one_or_none()


# ── Account endpoints ───────────────────────────────────────────────


@router.get(
    "/account",
    response_model=ACMEAccountSummary | None,
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Get the ACME account (no key material)",
)
async def get_account(db: DB) -> ACMEAccountSummary | None:
    row = await _get_account(db)
    return _account_summary(row) if row is not None else None


@router.put(
    "/account",
    response_model=ACMEAccountSummary,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Create or update the ACME account",
)
async def upsert_account(
    body: ACMEAccountUpsert,
    db: DB,
    user: CurrentUser,
) -> ACMEAccountSummary:
    """Upsert the install's ACME account.

    A freshly-created account gets a locally-generated EC account key
    (Fernet-encrypted at rest); the CA-side ``account_url`` is left NULL
    and filled lazily by the orchestrator's ``ensure_account`` on the
    first order. Changing ``directory_url`` on an existing row clears the
    cached ``account_url`` so the next order re-registers at the new CA.
    """
    directory_url = _require_https(body.directory_url)

    row = await _get_account(db)
    action = "update" if row is not None else "create"

    if row is None:
        # Generate a fresh EC-P256 account key. Done lazily here (not in
        # the engine) so the encrypted key is durable before any CA
        # round-trip — a re-run of the order reuses the same account.
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415

        account_key = ec.generate_private_key(ec.SECP256R1())
        account_key_pem = account_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        row = ACMEClientAccount(
            directory_url=directory_url,
            email=body.email,
            account_key_encrypted=encrypt_str(account_key_pem),
            eab_kid=body.eab_kid,
            eab_hmac_encrypted=(encrypt_str(body.eab_hmac_b64) if body.eab_hmac_b64 else None),
        )
        db.add(row)
    else:
        if row.directory_url != directory_url:
            # Re-pointed at a different CA — force re-registration.
            row.account_url = None
        row.directory_url = directory_url
        row.email = body.email
        row.eab_kid = body.eab_kid
        # HMAC is write-only: only replace when a new value is supplied.
        if body.eab_hmac_b64:
            row.eab_hmac_encrypted = encrypt_str(body.eab_hmac_b64)

    # Configuring an ACME account is the operator's explicit opt-in to LE
    # issuance — flip the documented ``acme_enabled`` gate on (issuance is
    # then additionally RBAC- + feature-module-gated). DELETE clears it.
    settings = await db.get(PlatformSettings, 1)
    if settings is not None:
        settings.acme_enabled = True

    await db.flush()
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action=action,
            resource_type="acme_client_account",
            resource_id=str(row.id),
            resource_display=row.directory_url,
            new_value={
                "directory_url": row.directory_url,
                "email": row.email,
                "eab_kid": row.eab_kid,
                "eab_hmac_set": row.eab_hmac_encrypted is not None,
            },
            result="success",
        )
    )
    await db.commit()
    await db.refresh(row)
    logger.info(
        "acme_client_account_upserted",
        account_id=str(row.id),
        directory_url=row.directory_url,
        action=action,
    )
    return _account_summary(row)


@router.delete(
    "/account",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Delete the ACME account",
)
async def delete_account(db: DB, user: CurrentUser) -> None:
    row = await _get_account(db)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no ACME account configured")
    account_id = row.id
    directory_url = row.directory_url
    # Removing the account is the operator's opt-out — clear the issuance
    # gate so a stray POST /issue can't drive a CA round-trip afterwards.
    settings = await db.get(PlatformSettings, 1)
    if settings is not None:
        settings.acme_enabled = False
    # Orders FK acme_client_account.id ON DELETE CASCADE — deleting the
    # account sweeps its order history too.
    await db.delete(row)
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="delete",
            resource_type="acme_client_account",
            resource_id=str(account_id),
            resource_display=directory_url,
            result="success",
        )
    )
    await db.commit()
    logger.info("acme_client_account_deleted", account_id=str(account_id))


# ── Preview ─────────────────────────────────────────────────────────


@router.post(
    "/preview",
    response_model=list[ACMEDomainResolution],
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Preview how each domain's DNS-01 challenge would be solved",
)
async def preview_domains(body: ACMEPreviewRequest, db: DB) -> list[ACMEDomainResolution]:
    """For each domain, report whether a SpatiumDDI-managed zone covers it
    (auto-solve, incl. cloud-hosted zones via the agentless drivers) or
    whether it needs the manual TXT fallback. Drives the Issue modal's
    per-domain status table. Read-only: nothing is written and no CA or
    DNS provider is contacted."""
    from app.services.acme_client import dns01  # noqa: PLC0415

    out: list[ACMEDomainResolution] = []
    for raw in body.domains:
        domain = raw.strip()
        if not domain:
            continue
        match = await dns01.resolve_managed(db, domain)
        note = None
        if match is not None and match.skipped_zone_name:
            note = (
                f"internal zone {match.skipped_zone_name} also covers this name; "
                f"the TXT goes into the public zone {match.zone_name} instead"
            )
        out.append(
            ACMEDomainResolution(
                domain=domain,
                challenge_fqdn=dns01.challenge_fqdn(domain),
                managed=match is not None,
                zone_name=match.zone_name if match else None,
                record_name=match.record_name if match else None,
                driver=match.driver if match else None,
                note=note,
            )
        )
    return out


# ── Order endpoints ─────────────────────────────────────────────────


@router.post(
    "/issue",
    response_model=ACMEOrderSummary,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Request a certificate via Let's Encrypt (DNS-01)",
)
async def issue_certificate(
    body: ACMEIssueRequest,
    db: DB,
    user: CurrentUser,
) -> ACMEOrderSummary:
    """Create a ``pending`` ACME order + enqueue the issuance task.

    Requires an ACME account to exist first (``PUT /account``). The
    Celery task ``app.tasks.acme.run_acme_order`` then drives the full
    DNS-01 flow off the request thread; poll ``GET /orders/{id}`` for
    progress (``processing`` → ``valid`` / ``invalid``).
    """
    if body.challenge_type == ACME_CHALLENGE_TLSALPN01:
        # tls-alpn-01 needs a per-challenge ``acme-tls/1`` cert served on
        # :443 — the nginx/k3s appliance terminates TLS itself and can't
        # swap that in, so it's unsupported on this topology (see #438).
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "tls-alpn-01 is not supported on this deployment — use dns-01 or http-01",
        )
    if body.challenge_type not in (ACME_CHALLENGE_DNS01, ACME_CHALLENGE_HTTP01):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"unsupported challenge type {body.challenge_type!r} — use dns-01 or http-01",
        )

    domains = [d.strip() for d in body.domains if d and d.strip()]
    if not domains:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "at least one non-empty domain is required",
        )

    account = await _get_account(db)
    if account is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "no ACME account configured — set one via PUT /api/v1/appliance/acme/account first",
        )

    settings = await db.get(PlatformSettings, 1)
    if settings is None or not settings.acme_enabled:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "ACME issuance is disabled — (re)configure the ACME account "
            "(PUT /api/v1/appliance/acme/account) to enable it",
        )

    order = ACMEOrder(
        account_id=account.id,
        domains=domains,
        challenge_type=body.challenge_type,
        dns_provider=body.dns_provider,
        allow_manual=body.allow_manual,
        status=ACME_ORDER_PENDING,
    )
    db.add(order)
    await db.flush()

    # Record the desired issuance shape so the deferred Phase-2 auto-renew
    # task knows what to renew (these columns are populated here, consumed
    # by that task).
    settings.acme_challenge_type = body.challenge_type
    settings.acme_dns_provider = body.dns_provider
    settings.acme_domains = domains

    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="acme_issue",
            resource_type="acme_order",
            resource_id=str(order.id),
            resource_display=", ".join(domains),
            new_value={
                "domains": domains,
                "challenge_type": order.challenge_type,
                "dns_provider": order.dns_provider,
            },
            result="success",
        )
    )
    await db.commit()
    await db.refresh(order)

    # Enqueue by the registered task name (lazy import keeps celery_app
    # out of the request import path; #218 — task is in both the worker
    # include list and task_routes so this dispatch can't silently fail).
    from app.tasks.acme import run_acme_order  # noqa: PLC0415

    run_acme_order.delay(str(order.id))
    logger.info(
        "acme_client_order_enqueued",
        order_id=str(order.id),
        domains=domains,
    )
    return _order_summary(order)


@router.get(
    "/orders",
    response_model=list[ACMEOrderSummary],
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="List ACME orders (newest first)",
)
async def list_orders(db: DB) -> list[ACMEOrderSummary]:
    result = await db.execute(select(ACMEOrder).order_by(ACMEOrder.created_at.desc()))
    return [_order_summary(row) for row in result.scalars().all()]


@router.get(
    "/orders/{order_id:uuid}",
    response_model=ACMEOrderSummary,
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Get one ACME order",
)
async def get_order(order_id: uuid.UUID, db: DB) -> ACMEOrderSummary:
    row = await db.get(ACMEOrder, order_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "order not found")
    return _order_summary(row)


@router.post(
    "/orders/{order_id:uuid}/cancel",
    response_model=ACMEOrderSummary,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Cancel an in-flight ACME order",
)
async def cancel_order(
    order_id: uuid.UUID,
    db: DB,
    user: CurrentUser,
) -> ACMEOrderSummary:
    """Mark a pending/processing order ``invalid`` so the UI stops polling.

    This is a local bookkeeping cancel — it doesn't recall the CA-side
    order (RFC 8555 has no client-driven order-cancel; orders just
    expire). A valid (already-issued) order can't be cancelled.
    """
    row = await db.get(ACMEOrder, order_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "order not found")
    if row.status not in (ACME_ORDER_PENDING, ACME_ORDER_PROCESSING):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"order is '{row.status}' — only pending/processing orders can be cancelled",
        )

    from app.models.acme_client import ACME_ORDER_INVALID  # noqa: PLC0415

    row.status = ACME_ORDER_INVALID
    row.last_error = "cancelled by operator"
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="acme_cancel",
            resource_type="acme_order",
            resource_id=str(row.id),
            resource_display=", ".join(row.domains),
            result="success",
        )
    )
    await db.commit()
    await db.refresh(row)
    logger.info("acme_client_order_cancelled", order_id=str(row.id))
    return _order_summary(row)
