"""ACME DNS-01 provider HTTP surface.

Implements an `acme-dns <https://github.com/joohoi/acme-dns>`_-compatible
protocol plus admin CRUD. External ACME clients (certbot with
``--dns-acme-dns``, lego ``ACMEDNSProvider``, acme.sh, etc.) speak
this out of the box — no custom plugins.

Two auth paths co-exist here:

* ``/register`` / ``/accounts`` — admin management. Gated by the normal
  SpatiumDDI RBAC (``acme_account`` resource type; superadmin or a
  role with ``admin`` / ``write`` on it). Uses JWT auth.
* ``/update`` — the acme-dns protocol endpoint. Auth is ``X-Api-User``
  / ``X-Api-Key`` headers verified against :class:`ACMEAccount`. No
  JWT, no session, no CSRF — it's a machine-to-machine protocol.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

import structlog
from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, select
from sqlalchemy.orm import selectinload

from app.api.deps import DB, CurrentUser
from app.core.permissions import require_permission
from app.core.request_meta import get_trusted_client_ip
from app.models.acme import ACMEAccount
from app.models.audit import AuditLog
from app.models.dns import DNSZone
from app.services import acme as acme_svc

logger = structlog.get_logger(__name__)

router = APIRouter()


# ── Schemas ─────────────────────────────────────────────────────────


class ACMERegisterRequest(BaseModel):
    """Admin-initiated account creation."""

    zone_id: uuid.UUID = Field(
        ...,
        description=(
            "DNSZone the account is bound to. Operators typically "
            "pre-create a dedicated zone (e.g. `acme.example.com.`) "
            "to hold ACME TXT records."
        ),
    )
    description: str = Field(
        "",
        max_length=1000,
        description="Human-readable label shown in the admin UI.",
    )
    allowed_source_cidrs: list[str] | None = Field(
        None,
        description=(
            "Optional allowlist of client IP CIDRs permitted to use "
            "/update with this credential. Empty / null = any source."
        ),
    )

    @field_validator("allowed_source_cidrs")
    @classmethod
    def _validate_cidrs(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        import ipaddress

        cleaned: list[str] = []
        for entry in v:
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR {entry!r}: {exc}") from exc
            cleaned.append(str(net))
        return cleaned


class ACMERegisterResponse(BaseModel):
    """acme-dns-compatible registration response.

    Field names match the acme-dns spec verbatim — clients
    deserialise by name.
    """

    username: str = Field(..., description="Used as X-Api-User on /update. Shown ONCE.")
    password: str = Field(..., description="Used as X-Api-Key on /update. Shown ONCE.")
    fulldomain: str = Field(
        ...,
        description=(
            "The FQDN clients should CNAME `_acme-challenge.<theirs>` " "to. No trailing dot."
        ),
    )
    subdomain: str = Field(
        ...,
        description=(
            "The subdomain label within the ACME zone. Goes in the " "request body on /update."
        ),
    )
    allowfrom: list[str] = Field(
        default_factory=list,
        description="Source IP allowlist, or empty array for open.",
    )


class ACMEAccountResponse(BaseModel):
    """Admin-list view. No credentials."""

    id: uuid.UUID
    subdomain: str
    username: str
    fulldomain: str
    zone_id: uuid.UUID
    description: str
    allowed_source_cidrs: list[str] | None
    last_used_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ACMEUpdateRequest(BaseModel):
    """acme-dns /update body shape. Fields named verbatim."""

    subdomain: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Must match the authenticated account's subdomain.",
    )
    txt: str = Field(
        "",
        max_length=512,
        description=(
            "Validation token from the CA. Empty string = no-op; the "
            "delete endpoint is preferred for cleanup."
        ),
    )


class ACMEUpdateResponse(BaseModel):
    txt: str = Field(..., description="Echoes the posted value on success.")


# ── Admin endpoints ─────────────────────────────────────────────────


@router.post(
    "/register",
    response_model=ACMERegisterResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("write", "acme_account"))],
)
async def register(
    body: ACMERegisterRequest,
    db: DB,
    current_user: CurrentUser,
) -> ACMERegisterResponse:
    """Create an ACME account and return the credentials (once)."""
    zone = (
        await db.execute(select(DNSZone).where(DNSZone.id == body.zone_id))
    ).scalar_one_or_none()
    if zone is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"DNS zone {body.zone_id} not found",
        )

    account, username, password = await acme_svc.register_account(
        db,
        zone=zone,
        created_by_user_id=current_user.id,
        description=body.description,
        allowed_source_cidrs=body.allowed_source_cidrs,
    )

    # Audit entry — credentials are NEVER logged; only the prefix /
    # identity metadata.
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="create",
            resource_type="acme_account",
            resource_id=str(account.id),
            resource_display=acme_svc.fulldomain_of(account, zone),
            result="success",
            new_value={
                "zone_id": str(zone.id),
                "zone_name": zone.name,
                "subdomain": account.subdomain,
                "username": account.username,
                "description": body.description,
                "allowed_source_cidrs": body.allowed_source_cidrs or [],
            },
        )
    )
    await db.commit()

    return ACMERegisterResponse(
        username=username,
        password=password,
        fulldomain=acme_svc.fulldomain_of(account, zone),
        subdomain=account.subdomain,
        allowfrom=list(account.allowed_source_cidrs or []),
    )


@router.get(
    "/accounts",
    response_model=list[ACMEAccountResponse],
    dependencies=[Depends(require_permission("read", "acme_account"))],
)
async def list_accounts(db: DB) -> list[ACMEAccountResponse]:
    """List all ACME accounts (admin / superadmin). No credentials leaked."""
    stmt = (
        select(ACMEAccount)
        .options(selectinload(ACMEAccount.zone))
        .order_by(ACMEAccount.created_at.desc())
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [
        ACMEAccountResponse(
            id=r.id,
            subdomain=r.subdomain,
            username=r.username,
            fulldomain=acme_svc.fulldomain_of(r, r.zone),
            zone_id=r.zone_id,
            description=r.description,
            allowed_source_cidrs=list(r.allowed_source_cidrs) if r.allowed_source_cidrs else None,
            last_used_at=r.last_used_at,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.delete(
    "/accounts/{account_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("delete", "acme_account"))],
)
async def revoke_account(
    account_id: uuid.UUID,
    db: DB,
    current_user: CurrentUser,
) -> None:
    """Hard-delete an account + every TXT record it owns.

    A revoked account's credentials stop working instantly on the
    next /update call (the row is gone — auth lookup returns None).
    """
    account = (
        await db.execute(
            select(ACMEAccount)
            .where(ACMEAccount.id == account_id)
            .options(selectinload(ACMEAccount.zone))
        )
    ).scalar_one_or_none()
    if account is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="ACME account not found",
        )
    # Delete any live TXT records at this subdomain before removing
    # the row (this enqueues the right DDNS removals too).
    await acme_svc.apply_txt_delete(db, account)
    fulldomain = acme_svc.fulldomain_of(account, account.zone)
    await db.execute(delete(ACMEAccount).where(ACMEAccount.id == account_id))
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="delete",
            resource_type="acme_account",
            resource_id=str(account_id),
            resource_display=fulldomain,
            result="success",
        )
    )
    await db.commit()


# ── acme-dns protocol endpoints ─────────────────────────────────────


async def _auth_acme(
    db: DB,
    request: Request,
    x_api_user: Annotated[str | None, Header(alias="X-Api-User")] = None,
    x_api_key: Annotated[str | None, Header(alias="X-Api-Key")] = None,
) -> ACMEAccount:
    """FastAPI dependency: verify acme-dns headers + source IP.

    On failure raises 401 with a generic message — don't tell the
    attacker whether username or password was wrong, or whether the
    source IP was out of the allowlist.
    """
    if not x_api_user or not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-Api-User and X-Api-Key headers required",
        )
    account = await acme_svc.authenticate(db, x_api_user, x_api_key)
    # Spoofing-resistant source IP for the account's allowlist gate (#626):
    # X-Real-IP is the nginx-set peer the client can't forge, unlike the
    # X-Forwarded-For-derived request.client.host.
    trusted_ip = get_trusted_client_ip(request)
    if account is None:
        logger.warning(
            "acme_auth_failed",
            user=x_api_user[:8] + "…",
            source_ip=trusted_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )
    client_ip = trusted_ip
    if not acme_svc.client_ip_allowed(account, client_ip):
        logger.warning(
            "acme_source_ip_denied",
            account_id=str(account.id),
            source_ip=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )
    return account


@router.post(
    "/update",
    response_model=ACMEUpdateResponse,
)
async def update_txt(
    body: ACMEUpdateRequest,
    db: DB,
    account: Annotated[ACMEAccount, Depends(_auth_acme)],
) -> ACMEUpdateResponse:
    """acme-dns /update — set a TXT record for this account's subdomain.

    Blocks until the record has been applied on the zone's primary
    DNS server, so the ACME CA's subsequent DNS poll finds the record
    live. The wait scales with the server's render time (#1184): at
    least 30 s, at most 55 s, under the 60 s at which the web frontend's
    nginx ends the request.

    Behavior:
      * If ``txt`` is empty, this is a no-op (returns 200 with the
        empty string).
      * If the posted ``txt`` matches an existing value at the
        subdomain, returns 200 immediately — idempotent retry.
      * Otherwise upserts the record, rolling the oldest value off
        if we're already at the 2-value cap.
    """
    if body.subdomain != account.subdomain:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="subdomain does not match authenticated account",
        )
    if not body.txt:
        # acme-dns returns the empty txt verbatim for consistency
        # with clients that probe with an empty POST.
        db.add(
            AuditLog(
                user_id=None,
                user_display_name=f"acme:{account.username[:8]}…",
                auth_source="acme",
                action="update",
                resource_type="acme_account",
                resource_id=str(account.id),
                resource_display=account.subdomain,
                result="success",
                new_value={"txt": "<empty>"},
            )
        )
        await db.commit()
        return ACMEUpdateResponse(txt="")

    op = await acme_svc.apply_txt_update(db, account, body.txt)
    db.add(
        AuditLog(
            user_id=None,
            user_display_name=f"acme:{account.username[:8]}…",
            auth_source="acme",
            action="update",
            resource_type="acme_account",
            resource_id=str(account.id),
            resource_display=account.subdomain,
            result="success",
            new_value={"txt_prefix": body.txt[:12]},
        )
    )
    await db.commit()

    if op is None:
        # No-op path: value already present, or zone has no primary.
        # Either way we don't block on an op we never enqueued.
        return ACMEUpdateResponse(txt=body.txt)

    timeout = await acme_svc.apply_timeout_for(
        db, [op.id], cap=acme_svc.PROVIDER_MAX_APPLY_TIMEOUT_SECONDS
    )
    try:
        state = await acme_svc.wait_for_op_applied(op.id, timeout=timeout)
    except acme_svc.ACMEApplyTimeout:
        logger.warning(
            "acme_update_apply_timeout",
            account_id=str(account.id),
            op_id=str(op.id),
            timeout_s=timeout,
        )
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=(
                "record write queued but primary DNS server did not "
                "acknowledge within the timeout; try again"
            ),
        ) from None
    if state == "failed":
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="primary DNS server rejected the record update",
        )
    return ACMEUpdateResponse(txt=body.txt)


@router.delete(
    "/update",
    status_code=status.HTTP_200_OK,
)
async def delete_txt(
    db: DB,
    account: Annotated[ACMEAccount, Depends(_auth_acme)],
    response: Response,
) -> dict[str, str]:
    """Idempotent cleanup — remove all TXT records for this subdomain.

    Called by well-behaved clients after LE validation. Not part of
    the original acme-dns protocol (which has no delete); SpatiumDDI
    offers it so stale records don't accumulate. Also exposed via
    ``POST /update`` with an empty ``txt`` body for
    protocol-compatible clients that can't issue DELETE.
    """
    ops = await acme_svc.apply_txt_delete(db, account)
    db.add(
        AuditLog(
            user_id=None,
            user_display_name=f"acme:{account.username[:8]}…",
            auth_source="acme",
            action="delete",
            resource_type="acme_account",
            resource_id=str(account.id),
            resource_display=account.subdomain,
            result="success",
            new_value={"removed": len(ops)},
        )
    )
    await db.commit()
    if ops:
        # Best-effort wait so the client can chain a "verify cleared"
        # check, but don't block as long as /update — nothing depends
        # on this returning synchronously.
        await acme_svc.wait_for_ops_applied([o.id for o in ops], timeout=10.0)
    response.headers["Content-Type"] = "application/json"
    return {"status": "cleared", "removed": str(len(ops))}
